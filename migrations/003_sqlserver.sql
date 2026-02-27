-- ============================================================================
-- DB FIREWALL — SQL Server Migration (2016+)
-- ============================================================================
-- Uses native Row-Level Security with security predicates.
-- SESSION_CONTEXT() for tenant state (SQL Server 2016+).
-- ============================================================================

BEGIN TRANSACTION;

-- 1. Tenant mapping table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = '_firewall_tenant_map')
CREATE TABLE dbo._firewall_tenant_map (
    db_user         NVARCHAR(128) PRIMARY KEY,
    tenant_id       NVARCHAR(128) NOT NULL,
    is_active       BIT DEFAULT 1,
    created_at      DATETIME2 DEFAULT SYSUTCDATETIME(),
    updated_at      DATETIME2 DEFAULT SYSUTCDATETIME()
);

-- 2. Audit log
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = '_firewall_audit_log')
CREATE TABLE dbo._firewall_audit_log (
    id              BIGINT IDENTITY(1,1) PRIMARY KEY,
    session_id      INT NOT NULL DEFAULT @@SPID,
    db_user         NVARCHAR(128) NOT NULL DEFAULT SYSTEM_USER,
    client_host     NVARCHAR(255),
    tenant_id       NVARCHAR(128) NOT NULL,
    assigned_at     DATETIME2 DEFAULT SYSUTCDATETIME(),
    auth_method     NVARCHAR(50) DEFAULT 'auto'
);

CREATE NONCLUSTERED INDEX IX_firewall_audit_tenant
    ON dbo._firewall_audit_log (tenant_id, assigned_at)
    WHERE tenant_id IS NOT NULL;
GO

-- 3. Set tenant context
CREATE OR ALTER PROCEDURE dbo._firewall_set_tenant
    @tenant_id NVARCHAR(128)
AS
BEGIN
    SET NOCOUNT ON;

    IF @tenant_id IS NULL
        THROW 50001, 'DB Firewall: tenant_id cannot be NULL', 1;

    EXEC sp_set_session_context @key = N'tenant_id', @value = @tenant_id;

    INSERT INTO dbo._firewall_audit_log (client_host, tenant_id, auth_method)
    VALUES (HOST_NAME(), @tenant_id, 'set_tenant');
END;
GO

-- 4. Clear tenant context
CREATE OR ALTER PROCEDURE dbo._firewall_clear_tenant
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_set_session_context @key = N'tenant_id', @value = NULL;
END;
GO

-- 5. Auto-resolve tenant on connection
CREATE OR ALTER PROCEDURE dbo._firewall_init_connection
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @tenant NVARCHAR(128);
    DECLARE @user NVARCHAR(128) = SYSTEM_USER;

    -- Skip excluded users
    IF @user IN ('sa', 'dbo', 'admin', '_migrator')
        RETURN;

    -- Check if already set
    SET @tenant = CAST(SESSION_CONTEXT(N'tenant_id') AS NVARCHAR(128));
    IF @tenant IS NOT NULL
        RETURN;

    -- Resolve from mapping
    SELECT @tenant = tenant_id
    FROM dbo._firewall_tenant_map
    WHERE db_user = @user AND is_active = 1;

    IF @tenant IS NOT NULL
        EXEC dbo._firewall_set_tenant @tenant_id = @tenant;
    -- ELSE: fail closed — no context = predicate blocks everything
END;
GO

-- 6. Security predicate function
--    Returns 1 (allow) or 0 (deny) for each row.
CREATE OR ALTER FUNCTION dbo._firewall_tenant_predicate(
    @tenant_id NVARCHAR(128)
)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS result
WHERE
    -- Row matches current tenant
    @tenant_id = CAST(SESSION_CONTEXT(N'tenant_id') AS NVARCHAR(128))
    -- OR user is excluded (admin bypass)
    OR SYSTEM_USER IN ('sa', 'dbo', 'admin', '_migrator');
GO


-- ============================================================================
-- 7. AUTO-APPLY RLS TO ALL TABLES WITH tenant_id
-- ============================================================================

DECLARE @table NVARCHAR(128);
DECLARE @schema NVARCHAR(128);
DECLARE @policy NVARCHAR(256);
DECLARE @sql NVARCHAR(MAX);

DECLARE table_cursor CURSOR FOR
    SELECT c.TABLE_SCHEMA, c.TABLE_NAME
    FROM INFORMATION_SCHEMA.COLUMNS c
    JOIN INFORMATION_SCHEMA.TABLES t
        ON c.TABLE_SCHEMA = t.TABLE_SCHEMA
        AND c.TABLE_NAME = t.TABLE_NAME
    WHERE c.COLUMN_NAME = 'tenant_id'
        AND t.TABLE_TYPE = 'BASE TABLE'
        AND c.TABLE_NAME NOT LIKE '_firewall_%'
        AND c.TABLE_NAME NOT IN (
            'schema_migrations', '__EFMigrationsHistory',
            'flyway_schema_history', '__MigrationHistory'
        );

OPEN table_cursor;
FETCH NEXT FROM table_cursor INTO @schema, @table;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @policy = 'firewall_rls_' + @table;

    -- Drop existing policy if re-running
    IF EXISTS (SELECT * FROM sys.security_policies WHERE name = @policy)
    BEGIN
        SET @sql = 'DROP SECURITY POLICY ' + QUOTENAME(@schema) + '.' + QUOTENAME(@policy);
        EXEC sp_executesql @sql;
    END

    -- Create security policy with filter (SELECT) and block (INSERT/UPDATE/DELETE) predicates
    SET @sql = '
        CREATE SECURITY POLICY ' + QUOTENAME(@schema) + '.' + QUOTENAME(@policy) + '
        ADD FILTER PREDICATE dbo._firewall_tenant_predicate(tenant_id)
            ON ' + QUOTENAME(@schema) + '.' + QUOTENAME(@table) + ',
        ADD BLOCK PREDICATE dbo._firewall_tenant_predicate(tenant_id)
            ON ' + QUOTENAME(@schema) + '.' + QUOTENAME(@table) + ' AFTER INSERT,
        ADD BLOCK PREDICATE dbo._firewall_tenant_predicate(tenant_id)
            ON ' + QUOTENAME(@schema) + '.' + QUOTENAME(@table) + ' BEFORE UPDATE,
        ADD BLOCK PREDICATE dbo._firewall_tenant_predicate(tenant_id)
            ON ' + QUOTENAME(@schema) + '.' + QUOTENAME(@table) + ' BEFORE DELETE
        WITH (STATE = ON, SCHEMABINDING = OFF)';

    EXEC sp_executesql @sql;

    PRINT 'DB Firewall: RLS applied to ' + @schema + '.' + @table;

    FETCH NEXT FROM table_cursor INTO @schema, @table;
END

CLOSE table_cursor;
DEALLOCATE table_cursor;

COMMIT TRANSACTION;
GO

-- 8. Logon trigger (auto-assign tenant on connect)
CREATE OR ALTER TRIGGER _firewall_logon_trigger
ON ALL SERVER
FOR LOGON
AS
BEGIN
    -- Only fire for the target database
    -- Uncomment and set your database name:
    -- IF ORIGINAL_DB_NAME() = 'YourDatabase'
    -- BEGIN
    --     EXEC YourDatabase.dbo._firewall_init_connection;
    -- END
    RETURN;
END;
GO
ENABLE TRIGGER _firewall_logon_trigger ON ALL SERVER;
GO
