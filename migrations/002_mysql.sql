-- ============================================================================
-- DB FIREWALL — MySQL / MariaDB Migration
-- ============================================================================
-- MySQL lacks native RLS. We use:
--   1. Session variables for tenant context
--   2. Secure views that enforce filtering
--   3. BEFORE triggers to enforce write isolation
-- ============================================================================

-- 1. Tenant mapping table
CREATE TABLE IF NOT EXISTS _firewall_tenant_map (
    db_user         VARCHAR(128) PRIMARY KEY,
    tenant_id       VARCHAR(128) NOT NULL,
    is_active       TINYINT(1) DEFAULT 1,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 1b. Bypass roles — EMPTY by default (no hardcoded root/admin bypass).
--     Opt a role in deliberately: INSERT INTO _firewall_bypass_roles VALUES ('_migrator');
CREATE TABLE IF NOT EXISTS _firewall_bypass_roles (
    role_name       VARCHAR(128) PRIMARY KEY,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Audit log
CREATE TABLE IF NOT EXISTS _firewall_audit_log (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    connection_id   BIGINT NOT NULL,
    db_user         VARCHAR(128) NOT NULL,
    client_host     VARCHAR(255),
    tenant_id       VARCHAR(128) NOT NULL,
    assigned_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    auth_method     VARCHAR(50) DEFAULT 'auto',
    INDEX idx_audit_tenant (tenant_id, assigned_at),
    INDEX idx_audit_conn (connection_id)
);

-- 3. Set/Get tenant via session variables
--    Routines below run with the default SQL SECURITY DEFINER. Unqualified
--    table names inside a stored routine resolve in the routine's OWN database
--    (not the caller's current database), so a caller cannot redirect
--    _firewall_bypass_roles / _firewall_tenant_map by switching databases
--    (unlike PostgreSQL search_path). Session TEMPORARY tables do shadow a
--    same-named base table inside routines, so do NOT grant
--    CREATE TEMPORARY TABLES to application users.
--    Inside a DEFINER routine or view CURRENT_USER() is the definer, so the
--    caller is read with USER() (the user name the client logged in with).
--    Keep no anonymous accounts: with one, USER() is whatever name was typed.
--    DROP + CREATE, not IF NOT EXISTS, so an upgrade replaces old bodies.
DELIMITER //

DROP PROCEDURE IF EXISTS _firewall_set_tenant //
CREATE PROCEDURE _firewall_set_tenant(IN p_tenant VARCHAR(128))
BEGIN
    SET @_fw_tenant_id = p_tenant;

    INSERT INTO _firewall_audit_log (connection_id, db_user, client_host, tenant_id, auth_method)
    VALUES (CONNECTION_ID(), USER(), SUBSTRING_INDEX(USER(), '@', -1), p_tenant, 'set_tenant');
END //

DROP PROCEDURE IF EXISTS _firewall_clear_tenant //
CREATE PROCEDURE _firewall_clear_tenant()
BEGIN
    SET @_fw_tenant_id = NULL;
END //

DROP FUNCTION IF EXISTS _firewall_get_tenant //
CREATE FUNCTION _firewall_get_tenant()
RETURNS VARCHAR(128) NOT DETERMINISTIC READS SQL DATA
BEGIN
    DECLARE v_tenant VARCHAR(128);

    -- Check session variable first
    SET v_tenant = @_fw_tenant_id;

    -- Auto-resolve from mapping if not set
    IF v_tenant IS NULL THEN
        SELECT tenant_id INTO v_tenant
        FROM _firewall_tenant_map
        WHERE db_user = SUBSTRING_INDEX(USER(), '@', 1)
          AND is_active = 1
        LIMIT 1;

        IF v_tenant IS NOT NULL THEN
            SET @_fw_tenant_id = v_tenant;
        END IF;
    END IF;

    RETURN v_tenant;
END //

-- A view cannot read a user variable (ERROR 1351); it calls this instead.
DROP FUNCTION IF EXISTS _firewall_is_bypass //
CREATE FUNCTION _firewall_is_bypass()
RETURNS TINYINT NOT DETERMINISTIC NO SQL
RETURN COALESCE(BINARY @_fw_tenant_id = BINARY '__BYPASS__', 0) //

-- 4. Connection init procedure — call this on every new connection
--    Connection pool libraries should call this in their on_connect hook.
--    DROP + CREATE, not IF NOT EXISTS: the body changed (the hardcoded
--    root/admin/_migrator bypass became the _firewall_bypass_roles lookup) and
--    IF NOT EXISTS would keep the old body on an upgraded database.
DROP PROCEDURE IF EXISTS _firewall_init_connection //
CREATE PROCEDURE _firewall_init_connection()
BEGIN
    DECLARE v_tenant VARCHAR(128);
    DECLARE v_user VARCHAR(128);

    SET v_user = SUBSTRING_INDEX(USER(), '@', 1);

    -- Bypass only for roles deliberately listed in _firewall_bypass_roles
    IF EXISTS (SELECT 1 FROM _firewall_bypass_roles WHERE role_name = v_user) THEN
        SET @_fw_tenant_id = '__BYPASS__';
        SIGNAL SQLSTATE '01000'
            SET MESSAGE_TEXT = 'DB Firewall: Bypassed for admin user';
    ELSE
        SELECT tenant_id INTO v_tenant
        FROM _firewall_tenant_map
        WHERE db_user = v_user AND is_active = 1
        LIMIT 1;

        IF v_tenant IS NOT NULL THEN
            CALL _firewall_set_tenant(v_tenant);
        ELSE
            SET @_fw_tenant_id = NULL;
            -- FAIL CLOSED: unmapped user will be blocked by views/triggers
        END IF;
    END IF;
END //

DELIMITER ;


-- ============================================================================
-- 5. SECURE VIEWS + WRITE TRIGGERS
-- ============================================================================
-- For each table with the tenant column (@dbfw_tenant_column, default
-- tenant_id) in the current database, _firewall_apply_all():
--   - creates the view v_<table> (filtered to the current tenant)
--   - returns, as one text row, the DDL for the BEFORE INSERT / UPDATE /
--     DELETE triggers. MySQL cannot create a trigger from a stored routine or
--     a prepared statement, so the client runs that DDL:
--
--   mysql -N -B -r db -e "SET @dbfw_tenant_column = 'tenant_id'; CALL _firewall_apply_all()" | mysql db
--
-- run_migration(conn) does both steps. Re-run after adding tables.
--
-- IMPORTANT: Your application/agents should query the VIEWS (v_orders),
-- not the base tables (orders). Revoke direct table access from agent users.
-- The tenant is a user variable: a client that can send raw SQL can set it.
-- ============================================================================

DELIMITER //

DROP PROCEDURE IF EXISTS _firewall_apply_all //
CREATE PROCEDURE _firewall_apply_all()
SQL SECURITY INVOKER
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE v_table VARCHAR(128);
    DECLARE t VARCHAR(300);
    DECLARE c VARCHAR(200);
    DECLARE s VARCHAR(300);
    DECLARE nl CHAR(1) DEFAULT CHAR(10);
    DECLARE v_ddl LONGTEXT DEFAULT CONCAT('DELIMITER $$', CHAR(10));
    DECLARE v_col VARCHAR(64) DEFAULT COALESCE(NULLIF(@dbfw_tenant_column, ''), 'tenant_id');
    DECLARE cur CURSOR FOR
        SELECT c.TABLE_NAME
        FROM INFORMATION_SCHEMA.COLUMNS c
        JOIN INFORMATION_SCHEMA.TABLES t
            ON c.TABLE_SCHEMA = t.TABLE_SCHEMA
            AND c.TABLE_NAME = t.TABLE_NAME
        WHERE c.COLUMN_NAME = v_col
            AND t.TABLE_TYPE = 'BASE TABLE'
            AND c.TABLE_SCHEMA = DATABASE()
            AND c.TABLE_NAME NOT LIKE '#_firewall#_%' ESCAPE '#'
            AND c.TABLE_NAME NOT IN (
                'schema_migrations', 'knex_migrations',
                'prisma_migrations', 'flyway_schema_history'
            );
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    SET c = CONCAT('`', REPLACE(v_col, '`', '``'), '`');
    OPEN cur;

    read_loop: LOOP
        FETCH cur INTO v_table;
        IF done THEN LEAVE read_loop; END IF;
        SET t = CONCAT('`', REPLACE(v_table, '`', '``'), '`');
        -- Name stem for v_<stem> and _fw_b?_<stem>: a name over 57 characters
        -- would push them past MySQL's 64. hooks/scan_engines.py uses the same rule.
        SET s = REPLACE(IF(CHAR_LENGTH(v_table) > 57,
                           CONCAT(LEFT(v_table, 40), '_', LEFT(SHA1(v_table), 16)), v_table), '`', '``');

        -- Filtered view (CREATE VIEW is allowed in a prepared statement)
        SET @sql = CONCAT(
            'CREATE OR REPLACE VIEW `v_', s, '` AS ',
            'SELECT * FROM ', t,
            ' WHERE BINARY ', c, ' = BINARY _firewall_get_tenant() OR _firewall_is_bypass() = 1'
        );
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;

        SET v_ddl = CONCAT(v_ddl,
            'DROP TRIGGER IF EXISTS `_fw_bi_', s, '`$$', nl,
            'CREATE TRIGGER `_fw_bi_', s, '` BEFORE INSERT ON ', t, ' FOR EACH ROW ',
            'BEGIN ',
            'IF _firewall_is_bypass() = 1 THEN SET @_fw_noop = 1; ',
            'ELSEIF _firewall_get_tenant() IS NULL THEN ',
            'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: No tenant context. INSERT denied.''; ',
            'ELSEIF NOT (BINARY NEW.', c, ' <=> BINARY _firewall_get_tenant()) THEN ',
            'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: Cross-tenant INSERT denied.''; ',
            'END IF; END$$', nl,

            'DROP TRIGGER IF EXISTS `_fw_bu_', s, '`$$', nl,
            'CREATE TRIGGER `_fw_bu_', s, '` BEFORE UPDATE ON ', t, ' FOR EACH ROW ',
            'BEGIN ',
            'IF _firewall_is_bypass() = 1 THEN SET @_fw_noop = 1; ',
            'ELSEIF _firewall_get_tenant() IS NULL THEN ',
            'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: No tenant context. UPDATE denied.''; ',
            'ELSEIF NOT (BINARY OLD.', c, ' <=> BINARY _firewall_get_tenant()) THEN ',
            'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: Cross-tenant UPDATE denied.''; ',
            'ELSEIF NOT (BINARY NEW.', c, ' <=> BINARY OLD.', c, ') THEN ',
            'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: Changing tenant_id denied.''; ',
            'END IF; END$$', nl,

            'DROP TRIGGER IF EXISTS `_fw_bd_', s, '`$$', nl,
            'CREATE TRIGGER `_fw_bd_', s, '` BEFORE DELETE ON ', t, ' FOR EACH ROW ',
            'BEGIN ',
            'IF _firewall_is_bypass() = 1 THEN SET @_fw_noop = 1; ',
            'ELSEIF _firewall_get_tenant() IS NULL THEN ',
            'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: No tenant context. DELETE denied.''; ',
            'ELSEIF NOT (BINARY OLD.', c, ' <=> BINARY _firewall_get_tenant()) THEN ',
            'SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: Cross-tenant DELETE denied.''; ',
            'END IF; END$$', nl);
    END LOOP;
    CLOSE cur;
    SELECT CONCAT(v_ddl, 'DELIMITER ;') AS trigger_ddl;
END //

DELIMITER ;
