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
DELIMITER //

CREATE PROCEDURE IF NOT EXISTS _firewall_set_tenant(IN p_tenant VARCHAR(128))
BEGIN
    SET @_fw_tenant_id = p_tenant;

    INSERT INTO _firewall_audit_log (connection_id, db_user, client_host, tenant_id, auth_method)
    VALUES (CONNECTION_ID(), CURRENT_USER(), SUBSTRING_INDEX(USER(), '@', -1), p_tenant, 'set_tenant');
END //

CREATE PROCEDURE IF NOT EXISTS _firewall_clear_tenant()
BEGIN
    SET @_fw_tenant_id = NULL;
END //

CREATE FUNCTION IF NOT EXISTS _firewall_get_tenant()
RETURNS VARCHAR(128) DETERMINISTIC READS SQL DATA
BEGIN
    DECLARE v_tenant VARCHAR(128);

    -- Check session variable first
    SET v_tenant = @_fw_tenant_id;

    -- Auto-resolve from mapping if not set
    IF v_tenant IS NULL THEN
        SELECT tenant_id INTO v_tenant
        FROM _firewall_tenant_map
        WHERE db_user = SUBSTRING_INDEX(CURRENT_USER(), '@', 1)
          AND is_active = 1
        LIMIT 1;

        IF v_tenant IS NOT NULL THEN
            SET @_fw_tenant_id = v_tenant;
        END IF;
    END IF;

    RETURN v_tenant;
END //

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

    SET v_user = SUBSTRING_INDEX(CURRENT_USER(), '@', 1);

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
-- 5. AUTO-GENERATE SECURE VIEWS + WRITE TRIGGERS
-- ============================================================================
-- Run this stored procedure after every migration to auto-protect tables.
--
-- For each table with the tenant column (@dbfw_tenant_column, default
-- tenant_id), it creates:
--   - A view: v_<table>  (filtered to current tenant)
--   - BEFORE INSERT trigger (enforces tenant_id on new rows)
--   - BEFORE UPDATE trigger (prevents cross-tenant updates)
--   - BEFORE DELETE trigger (prevents cross-tenant deletes)
--
-- IMPORTANT: Your application/agents should query the VIEWS (v_orders),
-- not the base tables (orders). Revoke direct table access from agent users.
-- ============================================================================

DELIMITER //

DROP PROCEDURE IF EXISTS _firewall_apply_all //
CREATE PROCEDURE _firewall_apply_all()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE v_table VARCHAR(128);
    DECLARE v_schema VARCHAR(128);
    -- Tenant column: SET @dbfw_tenant_column = 'org_id' before CALL (default tenant_id).
    DECLARE v_col VARCHAR(64) DEFAULT COALESCE(NULLIF(@dbfw_tenant_column, ''), 'tenant_id');
    DECLARE cur CURSOR FOR
        SELECT c.TABLE_SCHEMA, c.TABLE_NAME
        FROM INFORMATION_SCHEMA.COLUMNS c
        JOIN INFORMATION_SCHEMA.TABLES t
            ON c.TABLE_SCHEMA = t.TABLE_SCHEMA
            AND c.TABLE_NAME = t.TABLE_NAME
        WHERE c.COLUMN_NAME = v_col
            AND t.TABLE_TYPE = 'BASE TABLE'
            AND c.TABLE_SCHEMA = DATABASE()
            AND c.TABLE_NAME NOT LIKE '_firewall_%'
            AND c.TABLE_NAME NOT LIKE 'v_%'
            AND c.TABLE_NAME NOT IN (
                'schema_migrations', 'knex_migrations',
                'prisma_migrations', 'flyway_schema_history'
            );
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    OPEN cur;

    read_loop: LOOP
        FETCH cur INTO v_schema, v_table;
        IF done THEN LEAVE read_loop; END IF;

        -- Create filtered view
        SET @sql = CONCAT(
            'CREATE OR REPLACE VIEW v_', v_table, ' AS ',
            'SELECT * FROM ', v_table,
            ' WHERE `', v_col, '` = _firewall_get_tenant() ',
            'OR _firewall_get_tenant() IS NULL AND 1=0 ',
            'OR @_fw_tenant_id = ''__BYPASS__'''
        );
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;

        -- BEFORE INSERT trigger
        SET @sql = CONCAT(
            'CREATE TRIGGER IF NOT EXISTS _fw_bi_', v_table,
            ' BEFORE INSERT ON ', v_table, ' FOR EACH ROW ',
            'BEGIN ',
            '  IF @_fw_tenant_id = ''__BYPASS__'' THEN ',
            '    SET @_fw_noop = 1; ',
            '  ELSEIF _firewall_get_tenant() IS NULL THEN ',
            '    SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: No tenant context. INSERT denied.''; ',
            '  ELSEIF NEW.`', v_col, '` != _firewall_get_tenant() THEN ',
            '    SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: Cross-tenant INSERT denied.''; ',
            '  END IF; ',
            'END'
        );
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;

        -- BEFORE UPDATE trigger
        SET @sql = CONCAT(
            'CREATE TRIGGER IF NOT EXISTS _fw_bu_', v_table,
            ' BEFORE UPDATE ON ', v_table, ' FOR EACH ROW ',
            'BEGIN ',
            '  IF @_fw_tenant_id = ''__BYPASS__'' THEN ',
            '    SET @_fw_noop = 1; ',
            '  ELSEIF _firewall_get_tenant() IS NULL THEN ',
            '    SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: No tenant context. UPDATE denied.''; ',
            '  ELSEIF OLD.`', v_col, '` != _firewall_get_tenant() THEN ',
            '    SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: Cross-tenant UPDATE denied.''; ',
            '  ELSEIF NEW.`', v_col, '` != OLD.`', v_col, '` THEN ',
            '    SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: Changing tenant_id denied.''; ',
            '  END IF; ',
            'END'
        );
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;

        -- BEFORE DELETE trigger
        SET @sql = CONCAT(
            'CREATE TRIGGER IF NOT EXISTS _fw_bd_', v_table,
            ' BEFORE DELETE ON ', v_table, ' FOR EACH ROW ',
            'BEGIN ',
            '  IF @_fw_tenant_id = ''__BYPASS__'' THEN ',
            '    SET @_fw_noop = 1; ',
            '  ELSEIF _firewall_get_tenant() IS NULL THEN ',
            '    SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: No tenant context. DELETE denied.''; ',
            '  ELSEIF OLD.`', v_col, '` != _firewall_get_tenant() THEN ',
            '    SIGNAL SQLSTATE ''45000'' SET MESSAGE_TEXT = ''DB Firewall: Cross-tenant DELETE denied.''; ',
            '  END IF; ',
            'END'
        );
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;

    END LOOP;
    CLOSE cur;
END //

DELIMITER ;

-- Run it
CALL _firewall_apply_all();
