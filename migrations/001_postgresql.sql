-- ============================================================================
-- DB FIREWALL — PostgreSQL Migration
-- ============================================================================
-- Uses native Row-Level Security (RLS), available since PostgreSQL 9.5.
-- This is the gold standard for tenant isolation in Postgres.
-- ============================================================================

BEGIN;

-- 1. Tenant mapping table
CREATE TABLE IF NOT EXISTS _firewall_tenant_map (
    db_user         TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Audit log
CREATE TABLE IF NOT EXISTS _firewall_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    session_pid     INTEGER NOT NULL DEFAULT pg_backend_pid(),
    db_user         TEXT NOT NULL DEFAULT current_user,
    client_addr     INET,
    tenant_id       TEXT NOT NULL,
    assigned_at     TIMESTAMPTZ DEFAULT NOW(),
    auth_method     TEXT DEFAULT 'auto',
    application     TEXT DEFAULT current_setting('application_name', true)
);

CREATE INDEX IF NOT EXISTS idx_firewall_audit_tenant
    ON _firewall_audit_log (tenant_id, assigned_at);

-- 3. Session variable helper functions
CREATE OR REPLACE FUNCTION _firewall_set_tenant(p_tenant TEXT)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', p_tenant, false);
    INSERT INTO _firewall_audit_log (client_addr, tenant_id, auth_method)
    VALUES (inet_client_addr(), p_tenant, 'set_tenant');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION _firewall_get_tenant()
RETURNS TEXT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant', true), '');
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION _firewall_clear_tenant()
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', '', false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4. Auto-resolve tenant from user mapping
CREATE OR REPLACE FUNCTION _firewall_auto_resolve()
RETURNS TEXT AS $$
DECLARE
    v_tenant TEXT;
BEGIN
    -- Check if already set
    v_tenant := _firewall_get_tenant();
    IF v_tenant IS NOT NULL AND v_tenant != '' THEN
        RETURN v_tenant;
    END IF;

    -- Resolve from mapping table
    SELECT tenant_id INTO v_tenant
    FROM _firewall_tenant_map
    WHERE db_user = current_user AND is_active = TRUE;

    IF v_tenant IS NOT NULL THEN
        PERFORM _firewall_set_tenant(v_tenant);
    END IF;

    RETURN v_tenant;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 5. Universal RLS policy function
--    This is applied to every protected table.
CREATE OR REPLACE FUNCTION _firewall_tenant_check(table_name TEXT DEFAULT '')
RETURNS BOOLEAN AS $$
DECLARE
    v_tenant TEXT;
    v_user TEXT := current_user;
BEGIN
    -- Bypass for excluded users
    IF v_user IN ('postgres', 'admin', '_migrator') THEN
        RETURN TRUE;
    END IF;

    -- Auto-resolve tenant
    v_tenant := _firewall_auto_resolve();

    -- FAIL CLOSED: no tenant = deny all
    IF v_tenant IS NULL OR v_tenant = '' THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql STABLE;


-- ============================================================================
-- 6. AUTO-APPLY RLS TO ALL TABLES WITH tenant_id
-- ============================================================================
-- This DO block scans your schema and applies RLS to every table
-- that has a tenant_id column. Run after every migration.
-- ============================================================================

DO $$
DECLARE
    r RECORD;
    policy_name TEXT;
BEGIN
    FOR r IN
        SELECT c.table_schema, c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
            ON c.table_schema = t.table_schema
            AND c.table_name = t.table_name
        WHERE c.column_name = 'tenant_id'
            AND t.table_type = 'BASE TABLE'
            AND c.table_schema = 'public'
            AND c.table_name NOT LIKE '_firewall_%'
            AND c.table_name NOT IN (
                'schema_migrations', 'alembic_version',
                'knex_migrations', 'prisma_migrations',
                '__diesel_schema_migrations', 'flyway_schema_history'
            )
    LOOP
        policy_name := 'firewall_rls_' || r.table_name;

        -- Enable RLS on the table
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', r.table_schema, r.table_name);

        -- Force RLS even for table owners
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', r.table_schema, r.table_name);

        -- Drop existing policy if re-running
        BEGIN
            EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name, r.table_schema, r.table_name);
        EXCEPTION WHEN OTHERS THEN NULL;
        END;

        -- SELECT policy
        EXECUTE format(
            'CREATE POLICY %I ON %I.%I FOR SELECT USING (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR current_user IN (''postgres'', ''admin'', ''_migrator'')
            )',
            policy_name || '_sel', r.table_schema, r.table_name
        );

        -- INSERT policy (ensure new rows match current tenant)
        EXECUTE format(
            'CREATE POLICY %I ON %I.%I FOR INSERT WITH CHECK (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR current_user IN (''postgres'', ''admin'', ''_migrator'')
            )',
            policy_name || '_ins', r.table_schema, r.table_name
        );

        -- UPDATE policy
        EXECUTE format(
            'CREATE POLICY %I ON %I.%I FOR UPDATE USING (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR current_user IN (''postgres'', ''admin'', ''_migrator'')
            ) WITH CHECK (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR current_user IN (''postgres'', ''admin'', ''_migrator'')
            )',
            policy_name || '_upd', r.table_schema, r.table_name
        );

        -- DELETE policy
        EXECUTE format(
            'CREATE POLICY %I ON %I.%I FOR DELETE USING (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR current_user IN (''postgres'', ''admin'', ''_migrator'')
            )',
            policy_name || '_del', r.table_schema, r.table_name
        );

        RAISE NOTICE 'DB Firewall: RLS applied to %.%', r.table_schema, r.table_name;
    END LOOP;
END;
$$;


-- 7. Audit log auto-purge (run via pg_cron or application scheduler)
CREATE OR REPLACE FUNCTION _firewall_purge_audit(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM _firewall_audit_log
    WHERE assigned_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

COMMIT;
