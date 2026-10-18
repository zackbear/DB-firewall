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

-- 2b. Bypass roles — EMPTY by default. No role is hardcoded: on Supabase,
--     Neon, RDS etc. the app itself connects as "postgres", so a built-in
--     bypass would disable every policy. Opt a role in deliberately:
--       INSERT INTO _firewall_bypass_roles VALUES ('_migrator');
--     Superusers and BYPASSRLS roles skip RLS regardless of this table.
CREATE TABLE IF NOT EXISTS _firewall_bypass_roles (
    role_name       TEXT PRIMARY KEY,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- SECURITY DEFINER so policies can consult the table without granting
-- SELECT on it to application roles.
-- The caller passes current_user: inside SECURITY DEFINER it would resolve
-- to the function owner.
-- Every SECURITY DEFINER function below pins search_path (pg_temp LAST) and
-- schema-qualifies its tables: otherwise any caller could CREATE TEMP TABLE
-- _firewall_bypass_roles listing itself, put pg_temp first in search_path,
-- and switch every RLS policy off. It must stay executable by PUBLIC because
-- policies evaluate it as the calling role.
CREATE OR REPLACE FUNCTION _firewall_is_bypass_role(p_role TEXT)
RETURNS BOOLEAN AS $$
    SELECT EXISTS (SELECT 1 FROM public._firewall_bypass_roles WHERE role_name = p_role);
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- 3. Session variable helper functions
--    NOTE: _firewall_set_tenant is SESSION-scoped (manual/DBA use and the
--    per-DB-user auto-resolve). The Python middleware sets the GUC
--    transaction-locally instead; pool_checkin()/release() clear this one.
CREATE OR REPLACE FUNCTION _firewall_set_tenant(p_tenant TEXT)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', p_tenant, false);
    INSERT INTO public._firewall_audit_log (client_addr, tenant_id, auth_method)
    VALUES (inet_client_addr(), p_tenant, 'set_tenant');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

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
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- 4. Auto-resolve tenant from user mapping
CREATE OR REPLACE FUNCTION _firewall_auto_resolve()
RETURNS TEXT AS $$
DECLARE
    v_tenant TEXT;
BEGIN
    -- Check if already set
    v_tenant := public._firewall_get_tenant();
    IF v_tenant IS NOT NULL AND v_tenant != '' THEN
        RETURN v_tenant;
    END IF;

    -- Resolve from mapping table
    SELECT tenant_id INTO v_tenant
    FROM public._firewall_tenant_map
    WHERE db_user = current_user AND is_active = TRUE;

    IF v_tenant IS NOT NULL THEN
        PERFORM public._firewall_set_tenant(v_tenant);
    END IF;

    RETURN v_tenant;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- 5. Universal RLS policy function
--    This is applied to every protected table.
CREATE OR REPLACE FUNCTION _firewall_tenant_check(table_name TEXT DEFAULT '')
RETURNS BOOLEAN AS $$
DECLARE
    v_tenant TEXT;
    v_user TEXT := current_user;
BEGIN
    -- Bypass only for roles deliberately listed in _firewall_bypass_roles
    IF public._firewall_is_bypass_role(v_user) THEN
        RETURN TRUE;
    END IF;

    -- Auto-resolve tenant
    v_tenant := public._firewall_auto_resolve();

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

        -- Drop existing policies if re-running (idempotent)
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_sel', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_ins', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_upd', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_del', r.table_schema, r.table_name);

        -- SELECT policy
        EXECUTE format(
            'CREATE POLICY %I ON %I.%I FOR SELECT USING (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR public._firewall_is_bypass_role(current_user::text)
            )',
            policy_name || '_sel', r.table_schema, r.table_name
        );

        -- INSERT policy (ensure new rows match current tenant)
        EXECUTE format(
            'CREATE POLICY %I ON %I.%I FOR INSERT WITH CHECK (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR public._firewall_is_bypass_role(current_user::text)
            )',
            policy_name || '_ins', r.table_schema, r.table_name
        );

        -- UPDATE policy
        EXECUTE format(
            'CREATE POLICY %I ON %I.%I FOR UPDATE USING (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR public._firewall_is_bypass_role(current_user::text)
            ) WITH CHECK (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR public._firewall_is_bypass_role(current_user::text)
            )',
            policy_name || '_upd', r.table_schema, r.table_name
        );

        -- DELETE policy
        EXECUTE format(
            'CREATE POLICY %I ON %I.%I FOR DELETE USING (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR public._firewall_is_bypass_role(current_user::text)
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
    DELETE FROM public._firewall_audit_log
    WHERE assigned_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

COMMIT;
