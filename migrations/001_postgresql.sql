-- ============================================================================
-- DB FIREWALL — PostgreSQL Migration
-- ============================================================================
-- Uses native Row-Level Security (RLS). Signed tenant context (the default)
-- needs PostgreSQL 13+; dbfw.context = 'plain' works on 9.5+.
--
-- Signed context: the app sets app.current_tenant AND app.tenant_sig =
-- hex(HMAC-SHA256(key, _firewall_nonce() || ':' || tenant)). The key lives in
-- _firewall_keys, which no app role can read, and the nonce changes with every
-- transaction. So SQL the app (or an AI agent) runs cannot switch tenants:
-- it can set app.current_tenant, but it cannot sign it. The app gets the key
-- from DB_FIREWALL_TENANT_KEY (hex). Set the same variable when you run this
-- script to install your key, or leave it unset to generate one and read it
-- with: SELECT encode(key, 'hex') FROM public._firewall_keys;
--
-- Tenant column and schema (defaults: tenant_id, public). run_migration()
-- sets them from your config. With psql, set them in the same session:
--   psql -c "SET dbfw.tenant_column = 'org_id'" -c "SET dbfw.schema = 'app'" \
--        -c "SET dbfw.context = 'signed'" -c "SET dbfw.tenant_key = '<hex>'" \
--        -f migrations/001_postgresql.sql
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

-- 2c. Signing key for the tenant context. One row. No app role may read it:
--     see the REVOKE block at the end. ipad/opad are the HMAC-SHA256 inner and
--     outer key blocks, so policies need only the built-in sha256().
CREATE TABLE IF NOT EXISTS _firewall_keys (
    id              BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    key             BYTEA NOT NULL,
    ipad            BYTEA NOT NULL,
    opad            BYTEA NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Install dbfw.tenant_key (hex, 32 to 64 bytes) when given, which also
-- rotates it; otherwise keep the key, or generate one on the first run.
DO $$
DECLARE
    hex TEXT := NULLIF(current_setting('dbfw.tenant_key', true), '');
    k   BYTEA;
    ip  BYTEA := decode(repeat('36', 64), 'hex');
    op  BYTEA := decode(repeat('5c', 64), 'hex');
BEGIN
    IF hex IS NOT NULL THEN
        IF hex !~ '^([0-9a-fA-F]{2}){32,64}$' THEN
            RAISE EXCEPTION 'DB Firewall: dbfw.tenant_key must be 32 to 64 bytes, hex-encoded';
        END IF;
        k := decode(hex, 'hex');
    ELSIF EXISTS (SELECT 1 FROM public._firewall_keys) THEN
        RETURN;
    ELSE
        -- 48 bytes, 366 random bits (gen_random_uuid uses the strong RNG).
        k := decode(replace(gen_random_uuid()::text || gen_random_uuid()::text
                            || gen_random_uuid()::text, '-', ''), 'hex');
    END IF;
    FOR i IN 0 .. length(k) - 1 LOOP
        ip := set_byte(ip, i, get_byte(k, i) # 54);    -- 0x36
        op := set_byte(op, i, get_byte(k, i) # 92);    -- 0x5c
    END LOOP;
    INSERT INTO public._firewall_keys (id, key, ipad, opad) VALUES (TRUE, k, ip, op)
    ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key, ipad = EXCLUDED.ipad,
                                   opad = EXCLUDED.opad, created_at = NOW();
    -- The key must not stay readable in this session.
    PERFORM set_config('dbfw.tenant_key', '', false);
END;
$$;

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

-- 2d. Signed tenant context.
-- The nonce: this backend and this transaction's start, so a signature is
-- valid in one transaction only.
CREATE OR REPLACE FUNCTION _firewall_nonce()
RETURNS TEXT AS $$
    SELECT pg_backend_pid()::text || ':'
           || (extract(epoch FROM transaction_timestamp()) * 1000000)::bigint::text;
$$ LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp;

-- HMAC-SHA256(key, nonce || ':' || tenant), hex. No app role may execute it.
CREATE OR REPLACE FUNCTION _firewall_sign(p_tenant TEXT)
RETURNS TEXT AS $$
    SELECT encode(sha256(k.opad || sha256(k.ipad
               || convert_to(public._firewall_nonce() || ':' || p_tenant, 'UTF8'))), 'hex')
    FROM public._firewall_keys k;
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- The tenant the policies use: app.current_tenant when app.tenant_sig signs
-- it for this transaction, else NULL (no rows). Hashing both sides before the
-- comparison keeps its timing independent of the signature.
CREATE OR REPLACE FUNCTION _firewall_tenant()
RETURNS TEXT AS $$
    SELECT g.t FROM (SELECT NULLIF(current_setting('app.current_tenant', true), '') AS t,
                            current_setting('app.tenant_sig', true) AS s) g
    WHERE sha256(convert_to(g.s, 'UTF8')) = sha256(convert_to(public._firewall_sign(g.t), 'UTF8'));
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- 3. Session variable helper functions
--    NOTE: _firewall_set_tenant is SESSION-scoped (manual/DBA use and the
--    per-DB-user auto-resolve). The Python middleware sets the GUC
--    transaction-locally instead; pool_checkin()/release() clear this one.
--    It signs the tenant, so it is DBA-only: no app role may execute it
--    (REVOKE block at the end). The signature holds for this transaction.
CREATE OR REPLACE FUNCTION _firewall_set_tenant(p_tenant TEXT)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', p_tenant, false);
    PERFORM set_config('app.tenant_sig', COALESCE(public._firewall_sign(p_tenant), ''), false);
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
    PERFORM set_config('app.tenant_sig', '', false);
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
    WHERE db_user = session_user AND is_active = TRUE;   -- current_user is the owner here

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
-- 6. AUTO-APPLY RLS TO ALL TABLES WITH THE TENANT COLUMN (dbfw.tenant_column)
-- ============================================================================
-- This DO block scans your schema and applies RLS to every table
-- that has a tenant_id column. Run after every migration.
-- ============================================================================

DO $$
DECLARE
    r RECORD;
    policy_name TEXT;
    legacy_name TEXT;
    col TEXT := COALESCE(NULLIF(current_setting('dbfw.tenant_column', true), ''), 'tenant_id');
    sch TEXT := COALESCE(NULLIF(current_setting('dbfw.schema', true), ''), 'public');
    -- dbfw.policy_mode: 'permissive' (default) or 'restrictive'. Restrictive
    -- tenant policies AND with the app's own policies (Supabase, Drizzle
    -- pgPolicy), so an app policy can never widen access past the tenant.
    mode TEXT := lower(COALESCE(NULLIF(current_setting('dbfw.policy_mode', true), ''), 'permissive'));
    -- dbfw.context: 'signed' (default, see the header) or 'plain' (any SQL the
    -- app runs can set app.current_tenant and so switch tenants).
    ctx TEXT := lower(COALESCE(NULLIF(current_setting('dbfw.context', true), ''), 'signed'));
    kind TEXT;
    pred TEXT;
BEGIN
    IF mode NOT IN ('permissive', 'restrictive') THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.policy_mode must be permissive or restrictive, got %', mode;
    END IF;
    IF ctx NOT IN ('signed', 'plain') THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.context must be signed or plain, got %', ctx;
    END IF;
    kind := CASE mode WHEN 'restrictive' THEN 'AS RESTRICTIVE' ELSE 'AS PERMISSIVE' END;
    FOR r IN
        SELECT c.table_schema, c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
            ON c.table_schema = t.table_schema
            AND c.table_name = t.table_name
        WHERE c.column_name = col
            AND t.table_type = 'BASE TABLE'
            AND c.table_schema = sch
            AND c.table_name NOT LIKE '#_firewall#_%' ESCAPE '#'
            AND c.table_name NOT IN (
                'schema_migrations', 'alembic_version',
                'knex_migrations', 'prisma_migrations',
                '__diesel_schema_migrations', 'flyway_schema_history'
            )
    LOOP
        -- Policy names are capped at 63 bytes. 'firewall_rls_' || table || '_sel'
        -- overflows for table names > 46 chars and the truncated names collide
        -- (CREATE POLICY ... already exists). A hash stem is short and unique.
        policy_name := 'fw_' || left(md5(r.table_schema || '.' || r.table_name), 12);
        legacy_name := 'firewall_rls_' || r.table_name;
        -- (SELECT f()) runs once per query (an InitPlan), not once per row.
        pred := CASE ctx
            WHEN 'signed' THEN format('%I = (SELECT public._firewall_tenant())
                OR (SELECT public._firewall_is_bypass_role(current_user::text))', col)
            ELSE format('%I = NULLIF(current_setting(''app.current_tenant'', true), '''')
                OR public._firewall_is_bypass_role(current_user::text)', col) END;

        -- Enable RLS on the table
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', r.table_schema, r.table_name);

        -- Force RLS even for table owners
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', r.table_schema, r.table_name);

        -- Drop existing policies if re-running (idempotent). Permissive
        -- policies OR together, so every earlier generation must go: the
        -- legacy single policy and the legacy per-command policies hardcoded
        -- a postgres/admin/_migrator bypass that would otherwise survive an
        -- upgrade. The legacy names are passed through %I, which truncates
        -- like CREATE POLICY did, so over-long legacy names still match.
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', legacy_name, r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', legacy_name || '_sel', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', legacy_name || '_ins', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', legacy_name || '_upd', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', legacy_name || '_del', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_sel', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_ins', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_upd', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_del', r.table_schema, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', policy_name || '_base', r.table_schema, r.table_name);

        EXECUTE format('CREATE POLICY %I ON %I.%I %s FOR SELECT USING (%s)',
                       policy_name || '_sel', r.table_schema, r.table_name, kind, pred);
        -- INSERT: new rows must carry the current tenant
        EXECUTE format('CREATE POLICY %I ON %I.%I %s FOR INSERT WITH CHECK (%s)',
                       policy_name || '_ins', r.table_schema, r.table_name, kind, pred);
        EXECUTE format('CREATE POLICY %I ON %I.%I %s FOR UPDATE USING (%s) WITH CHECK (%s)',
                       policy_name || '_upd', r.table_schema, r.table_name, kind, pred, pred);
        EXECUTE format('CREATE POLICY %I ON %I.%I %s FOR DELETE USING (%s)',
                       policy_name || '_del', r.table_schema, r.table_name, kind, pred);

        -- Restrictive policies only narrow: PostgreSQL also needs a permissive
        -- policy to allow any row. A table with no permissive policy of its own
        -- gets "<stem>_base" (USING true); the tenant policies still apply. A
        -- table that has its own gets none, so those keep deciding which rows
        -- of the tenant a user sees. Re-run after adding the first one.
        IF mode = 'restrictive' AND NOT EXISTS (
            SELECT 1 FROM pg_policies p
            WHERE p.schemaname = r.table_schema AND p.tablename = r.table_name
              AND p.permissive = 'PERMISSIVE') THEN
            EXECUTE format('CREATE POLICY %I ON %I.%I AS PERMISSIVE FOR ALL USING (true) WITH CHECK (true)',
                           policy_name || '_base', r.table_schema, r.table_name);
        END IF;

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

-- 8. Only the owner may read the key, sign, or change the bypass list and the
--    tenant map. REVOKE ... FROM PUBLIC is not enough: platforms such as
--    Supabase grant new objects in public to their roles directly (default
--    privileges), so every grantee but the owner is revoked.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT 'TABLE' AS kind, c.oid::regclass::text AS obj, a.grantee
        FROM pg_class c, aclexplode(c.relacl) a
        WHERE c.oid IN ('public._firewall_keys'::regclass, 'public._firewall_bypass_roles'::regclass,
                        'public._firewall_tenant_map'::regclass)
          AND a.grantee <> c.relowner
        UNION
        SELECT 'FUNCTION', p.oid::regprocedure::text, a.grantee
        FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.oid IN ('public._firewall_sign(text)'::regprocedure, 'public._firewall_set_tenant(text)'::regprocedure)
          AND a.grantee <> p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON %s %s FROM %s', r.kind, r.obj,
                       CASE r.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(r.grantee)) END);
    END LOOP;
END;
$$;

COMMIT;
