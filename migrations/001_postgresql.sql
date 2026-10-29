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
-- with: SELECT encode(key, 'hex') FROM db_firewall._firewall_keys;
--
-- Tenant column and schema (defaults: tenant_id, public). run_migration()
-- sets them from your config. With psql, set them in the same session:
--   psql -c "SET dbfw.tenant_column = 'org_id'" -c "SET dbfw.schema = 'app'" \
--        -c "SET dbfw.context = 'signed'" -c "SET dbfw.tenant_key = '<hex>'" \
--        -c "SET dbfw.harden_signals = 'off'" -c "SET dbfw.harden = 'off'" \
--        -c "SET dbfw.app_role = 'app'" -c "SET dbfw.ddl_guard = 'on'" \
--        -f migrations/001_postgresql.sql
-- ============================================================================

BEGIN;

-- Resolve every name and operator in pg_catalog only, for this transaction. An
-- app role that can CREATE in public could otherwise plant an operator (say
-- varchar = text) that the policy predicates below would bind to.
SET LOCAL search_path = pg_catalog, pg_temp;
-- The DDL guard (section 11) must not stop this script's own changes.
SET LOCAL dbfw.ddl_guard_skip = 'on';

-- 0. Refuse objects someone else planted. A role that could create schema
--    db_firewall first, or an object in it, could read the key this script
--    then writes, or stay the owner of a firewall function through CREATE OR
--    REPLACE. Schema db_firewall and every object in it, and every
--    public._firewall_* object (an earlier version kept them there), must
--    belong to the role running this script or to a superuser. The same block runs
--    again as the last statement: a role could plant one while this script
--    waits on a lock (say, in section 6). Two DO blocks, not a pg_temp
--    function, so the script needs no TEMP privilege.
DO $$
DECLARE
    bad TEXT;
    fw OID := to_regnamespace('db_firewall');
BEGIN
    SELECT string_agg(o.name || ' (owner ' || pg_get_userbyid(o.owner) || ')', ', ') INTO bad
    FROM (SELECT 'schema db_firewall' AS name, n.nspowner AS owner FROM pg_namespace n WHERE n.oid = fw
          UNION ALL
          SELECT c.oid::regclass::text, c.relowner FROM pg_class c
          WHERE c.relnamespace = fw
             OR (c.relnamespace = 'public'::regnamespace AND c.relname LIKE '#_firewall#_%' ESCAPE '#')
          UNION ALL
          SELECT p.oid::regprocedure::text, p.proowner FROM pg_proc p
          WHERE p.pronamespace = fw
             OR (p.pronamespace = 'public'::regnamespace AND p.proname LIKE '#_firewall#_%' ESCAPE '#')
          UNION ALL
          SELECT t.oid::regtype::text, t.typowner FROM pg_type t
          WHERE (t.typnamespace = fw
                 OR (t.typnamespace = 'public'::regnamespace AND t.typname LIKE '#_firewall#_%' ESCAPE '#'))
            AND t.typrelid = 0
          UNION ALL
          SELECT o.oid::regoperator::text, o.oprowner FROM pg_operator o WHERE o.oprnamespace = fw) o
    JOIN pg_roles r ON r.oid = o.owner
    WHERE r.rolname <> current_user AND NOT r.rolsuper;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'DB Firewall: % not owned by % or a superuser. Another role may have planted them: drop them, or ALTER ... OWNER TO a trusted role, and re-run.', bad, current_user;
    END IF;
END;
$$;

-- 0b. The firewall's own schema. The policies and the firewall's functions
--     call its functions by name: a role that could add one there (an
--     overload with a default argument, say) could make every call
--     ambiguous, so only the owner creates in it. Every role uses it: the
--     policies run its functions as the role that reads the table.
DO $$
DECLARE
    r RECORD;
BEGIN
    IF current_setting('dbfw.schema', true) = 'db_firewall' THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.schema must not be db_firewall, the firewall''s own schema';
    END IF;
    CREATE SCHEMA IF NOT EXISTS db_firewall;
    FOR r IN
        SELECT a.grantee FROM pg_namespace n, aclexplode(n.nspacl) a
        WHERE n.nspname = 'db_firewall' AND a.privilege_type = 'CREATE' AND a.grantee <> n.nspowner
    LOOP
        EXECUTE format('REVOKE CREATE ON SCHEMA db_firewall FROM %s CASCADE',
                       CASE r.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(r.grantee)) END);
    END LOOP;
    GRANT USAGE ON SCHEMA db_firewall TO PUBLIC;
    -- Move what an earlier version made in public. SET SCHEMA keeps each
    -- object, so the policies, event triggers and rows that use it stay.
    FOR r IN
        SELECT c.relname::text AS name FROM pg_class c
        WHERE c.relnamespace = 'public'::regnamespace AND c.relname LIKE '#_firewall#_%' ESCAPE '#'
          AND c.relkind IN ('r', 'p', 'v')
    LOOP
        IF to_regclass(format('db_firewall.%I', r.name)) IS NOT NULL THEN
            RAISE EXCEPTION 'DB Firewall: both public.% and db_firewall.% exist: keep one (db_firewall), then re-run', r.name, r.name;
        END IF;
        EXECUTE format('ALTER TABLE public.%I SET SCHEMA db_firewall', r.name);
    END LOOP;
    FOR r IN
        SELECT p.oid::regprocedure::text AS sig, p.proname::text AS name, oidvectortypes(p.proargtypes) AS args
        FROM pg_proc p
        WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE '#_firewall#_%' ESCAPE '#'
    LOOP
        IF to_regprocedure(format('db_firewall.%I(%s)', r.name, r.args)) IS NOT NULL THEN
            RAISE EXCEPTION 'DB Firewall: both % and its copy in db_firewall exist: drop the public one, then re-run', r.sig;
        END IF;
        EXECUTE format('ALTER ROUTINE %s SET SCHEMA db_firewall', r.sig);
    END LOOP;
END;
$$;

-- 1. Tenant mapping table
CREATE TABLE IF NOT EXISTS db_firewall._firewall_tenant_map (
    db_user         TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Audit log
CREATE TABLE IF NOT EXISTS db_firewall._firewall_audit_log (
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
    ON db_firewall._firewall_audit_log (tenant_id, assigned_at);

-- 2b. Bypass roles — EMPTY by default. No role is hardcoded: on Supabase,
--     Neon, RDS etc. the app itself connects as "postgres", so a built-in
--     bypass would disable every policy. Opt a role in deliberately:
--       INSERT INTO _firewall_bypass_roles VALUES ('_migrator');
--     Superusers and BYPASSRLS roles skip RLS regardless of this table.
CREATE TABLE IF NOT EXISTS db_firewall._firewall_bypass_roles (
    role_name       TEXT PRIMARY KEY,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 2c. Signing key for the tenant context. One row. No app role may read it:
--     see the REVOKE block at the end. ipad/opad are the HMAC-SHA256 inner and
--     outer key blocks, so policies need only the built-in sha256().
CREATE TABLE IF NOT EXISTS db_firewall._firewall_keys (
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
    ELSIF EXISTS (SELECT 1 FROM db_firewall._firewall_keys) THEN
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
    INSERT INTO db_firewall._firewall_keys (id, key, ipad, opad) VALUES (TRUE, k, ip, op)
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
CREATE OR REPLACE FUNCTION db_firewall._firewall_is_bypass_role(p_role TEXT)
RETURNS BOOLEAN AS $$
    SELECT EXISTS (SELECT 1 FROM db_firewall._firewall_bypass_roles WHERE role_name = p_role);
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- 2d. Signed tenant context.
-- The nonce: this backend and this transaction's start. A signature is valid in
-- one transaction, or in several started within one query string (they share
-- the start time); the app signs in its own statement after BEGIN, so SQL it
-- runs later cannot reuse a signature in a new transaction.
CREATE OR REPLACE FUNCTION db_firewall._firewall_nonce()
RETURNS TEXT AS $$
    SELECT pg_backend_pid()::text || ':'
           || (extract(epoch FROM transaction_timestamp()) * 1000000)::bigint::text;
$$ LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp;

-- HMAC-SHA256(key, nonce || ':' || tenant), hex. No app role may execute it.
CREATE OR REPLACE FUNCTION db_firewall._firewall_sign(p_tenant TEXT)
RETURNS TEXT AS $$
    SELECT encode(sha256(k.opad || sha256(k.ipad
               || convert_to(db_firewall._firewall_nonce() || ':' || p_tenant, 'UTF8'))), 'hex')
    FROM db_firewall._firewall_keys k;
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- The tenant the policies use: app.current_tenant when app.tenant_sig signs
-- it for this transaction, else NULL (no rows). Hashing both sides before the
-- comparison keeps its timing independent of the signature.
CREATE OR REPLACE FUNCTION db_firewall._firewall_tenant()
RETURNS TEXT AS $$
    SELECT g.t FROM (SELECT NULLIF(current_setting('app.current_tenant', true), '') AS t,
                            current_setting('app.tenant_sig', true) AS s) g
    WHERE sha256(convert_to(g.s, 'UTF8')) = sha256(convert_to(db_firewall._firewall_sign(g.t), 'UTF8'));
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- 2e. Session reset: withTenant (TypeScript) runs it after each transaction,
--     pool_checkin / release() (Python) on return. SQL run in a tenant's
--     transaction can leave session state that the connection's next user
--     (another tenant) runs into: a temp view or function that shadows a
--     table, a SQL-level prepared statement under a driver's statement name,
--     a custom setting used as a drop box, a holdable cursor, a LISTEN, an
--     advisory lock (its keys can carry row data), currval/lastval. This
--     clears them all. Prepared statements the driver made (protocol level,
--     from_sql false) stay, so driver caches stay valid. RESET ALL also clears
--     custom settings, which pg_settings cannot list. p_keep is the app's own
--     session settings and role from before (_firewall_session_settings()),
--     restored afterwards. No SECURITY DEFINER and no SET clause (a SET clause
--     would put back the search_path it resets), so every name is qualified.
CREATE OR REPLACE FUNCTION db_firewall._firewall_reset_session(p_keep JSONB)
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    EXECUTE 'DISCARD TEMP';
    EXECUTE 'DISCARD SEQUENCES';     -- currval/lastval: the last tenant's ids
    EXECUTE 'CLOSE ALL';
    EXECUTE 'UNLISTEN *';
    PERFORM pg_catalog.pg_advisory_unlock_all();
    FOR r IN SELECT s.name FROM pg_catalog.pg_prepared_statements s WHERE s.from_sql LOOP
        EXECUTE pg_catalog.format('DEALLOCATE %I', r.name);
    END LOOP;
    EXECUTE 'RESET ALL';
    FOR r IN SELECT k.key, k.value FROM pg_catalog.jsonb_each_text(p_keep) k LOOP
        PERFORM pg_catalog.set_config(r.key, r.value, false);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- The settings set at session level (standard ones; pg_settings lists no
-- custom ones; not transaction_*, which only a transaction's start may set)
-- and the role: what _firewall_reset_session restores. No SET
-- clause: inside the function it would show as a session-level search_path.
CREATE OR REPLACE FUNCTION db_firewall._firewall_session_settings()
RETURNS JSONB AS $$
    SELECT COALESCE(pg_catalog.jsonb_object_agg(s.name, s.setting)
                        FILTER (WHERE s.source OPERATOR(pg_catalog.=) 'session'
                                  AND NOT pg_catalog.starts_with(s.name, 'transaction_')), '{}'::pg_catalog.jsonb)
           OPERATOR(pg_catalog.||) pg_catalog.jsonb_build_object('role', pg_catalog.current_setting('role'))
    FROM pg_catalog.pg_settings s;
$$ LANGUAGE sql STABLE;

-- 3. Session variable helper functions
--    NOTE: _firewall_set_tenant is SESSION-scoped (manual/DBA use and the
--    per-DB-user auto-resolve). The Python middleware sets the GUC
--    transaction-locally instead; pool_checkin()/release() clear this one.
--    It signs the tenant, so it is DBA-only: no app role may execute it
--    (REVOKE block at the end). The signature holds for this transaction.
CREATE OR REPLACE FUNCTION db_firewall._firewall_set_tenant(p_tenant TEXT)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', p_tenant, false);
    PERFORM set_config('app.tenant_sig', COALESCE(db_firewall._firewall_sign(p_tenant), ''), false);
    INSERT INTO db_firewall._firewall_audit_log (client_addr, tenant_id, auth_method)
    VALUES (inet_client_addr(), p_tenant, 'set_tenant');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

CREATE OR REPLACE FUNCTION db_firewall._firewall_get_tenant()
RETURNS TEXT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant', true), '');
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION db_firewall._firewall_clear_tenant()
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', '', false);
    PERFORM set_config('app.tenant_sig', '', false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- 4. Auto-resolve tenant from user mapping
CREATE OR REPLACE FUNCTION db_firewall._firewall_auto_resolve()
RETURNS TEXT AS $$
DECLARE
    v_tenant TEXT;
BEGIN
    -- Check if already set
    v_tenant := db_firewall._firewall_get_tenant();
    IF v_tenant IS NOT NULL AND v_tenant != '' THEN
        RETURN v_tenant;
    END IF;

    -- Resolve from mapping table
    SELECT tenant_id INTO v_tenant
    FROM db_firewall._firewall_tenant_map
    WHERE db_user = session_user AND is_active = TRUE;   -- current_user is the owner here

    IF v_tenant IS NOT NULL THEN
        PERFORM db_firewall._firewall_set_tenant(v_tenant);
    END IF;

    RETURN v_tenant;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- 5. Universal RLS policy function
--    This is applied to every protected table.
CREATE OR REPLACE FUNCTION db_firewall._firewall_tenant_check(table_name TEXT DEFAULT '')
RETURNS BOOLEAN AS $$
DECLARE
    v_tenant TEXT;
    v_user TEXT := current_user;
BEGIN
    -- Bypass only for roles deliberately listed in _firewall_bypass_roles
    IF db_firewall._firewall_is_bypass_role(v_user) THEN
        RETURN TRUE;
    END IF;

    -- Auto-resolve tenant
    v_tenant := db_firewall._firewall_auto_resolve();

    -- FAIL CLOSED: no tenant = deny all
    IF v_tenant IS NULL OR v_tenant = '' THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql STABLE;


-- 5b. Protecting one table, the record of what this script protects, and the
--     DDL guard (installed by section 11 when dbfw.ddl_guard = on).
--
--     _firewall_protected_schemas: the schemas this script protects, with the
--     tenant column, policy mode and context it used, so the guard protects a
--     later table the same way. Only its owner reads or writes it (section 8).
CREATE TABLE IF NOT EXISTS db_firewall._firewall_protected_schemas (
    schema_name   TEXT PRIMARY KEY,
    tenant_column TEXT NOT NULL,
    policy_mode   TEXT NOT NULL,
    context       TEXT NOT NULL,
    updated_at    TIMESTAMPTZ DEFAULT now()
);

-- _firewall_guard_calls: the guard's own calls in progress (see the guard).
-- Only its owner reads or writes it (section 8): a role that could add a row
-- could skip the guard.
CREATE TABLE IF NOT EXISTS db_firewall._firewall_guard_calls (pid INT NOT NULL, call_id TEXT NOT NULL);

-- RLS on and forced, TRIGGER and TRUNCATE revoked from all but the owner, and
-- the four firewall policies (dropped and created again). Section 6 calls it
-- for every table; the guard for a new one. The caller must own the table.
CREATE OR REPLACE FUNCTION db_firewall._firewall_protect(p_schema TEXT, p_table TEXT, p_column TEXT, p_mode TEXT, p_context TEXT)
RETURNS VOID AS $$
DECLARE
    g RECORD;
    rel REGCLASS := format('%I.%I', p_schema, p_table)::regclass;
    -- Policy names are capped at 63 bytes. 'firewall_rls_' || table || '_sel'
    -- overflows for table names > 46 chars and the truncated names collide
    -- (CREATE POLICY ... already exists). A hash stem is short and unique.
    stem TEXT := 'fw_' || left(md5(p_schema || '.' || p_table), 12);
    legacy TEXT := 'firewall_rls_' || p_table;
    legacies TEXT[] := ARRAY[]::TEXT[];
    n TEXT;
    kind TEXT := CASE p_mode WHEN 'restrictive' THEN 'AS RESTRICTIVE' ELSE 'AS PERMISSIVE' END;
    pred TEXT;
    typ OID;
    coll OID;
BEGIN
    IF p_mode NOT IN ('permissive', 'restrictive') THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.policy_mode must be permissive or restrictive, got %', p_mode;
    END IF;
    IF p_context NOT IN ('signed', 'plain') THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.context must be signed or plain, got %', p_context;
    END IF;
    -- The tenant column's type (through any domain) must belong to a
    -- superuser, and its collation must be deterministic: the policies call
    -- the type's cast and equality, and a type another role created can
    -- carry a cast of theirs (it runs in every tenant's session and can
    -- return any tenant); a collation that is not deterministic makes two
    -- tenant ids equal.
    SELECT a.atttypid, a.attcollation INTO typ, coll FROM pg_attribute a
    WHERE a.attrelid = rel AND a.attname = p_column AND a.attnum > 0 AND NOT a.attisdropped;
    WHILE (SELECT typtype FROM pg_type WHERE oid = typ) = 'd' LOOP
        typ := (SELECT typbasetype FROM pg_type WHERE oid = typ);
    END LOOP;
    IF NOT coalesce((SELECT r.rolsuper FROM pg_type y JOIN pg_roles r ON r.oid = y.typowner WHERE y.oid = typ), true)
       OR NOT coalesce((SELECT collisdeterministic FROM pg_collation WHERE oid = coll), true) THEN
        RAISE EXCEPTION 'DB Firewall: the tenant column %.%.% has the type % and the collation %: it needs a built-in or extension type and a deterministic collation',
            p_schema, p_table, p_column, typ::regtype, coalesce(coll::regcollation::text, '-')
            USING HINT = 'Use text or varchar for the tenant column.';
    END IF;

    -- (SELECT f()) runs once per query (an InitPlan), not once per row.
    pred := CASE p_context
        WHEN 'signed' THEN format('%I = (SELECT db_firewall._firewall_tenant())
            OR (SELECT db_firewall._firewall_is_bypass_role(current_user::text))', p_column)
        ELSE format('%I = NULLIF(current_setting(''app.current_tenant'', true), '''')
            OR db_firewall._firewall_is_bypass_role(current_user::text)', p_column) END;

    -- Enable RLS on the table, and force it even for table owners
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', rel);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', rel);

    -- RLS does not cover TRUNCATE (it empties every tenant's rows) or what
    -- a trigger does: with TRIGGER, a role attaches its own function (even
    -- one in pg_temp) that runs in other tenants' sessions as them. Only
    -- the owner keeps either.
    FOR g IN
        SELECT a.grantee, a.privilege_type FROM pg_class c, aclexplode(c.relacl) a
        WHERE c.oid = rel AND a.grantee <> c.relowner AND a.privilege_type IN ('TRIGGER', 'TRUNCATE')
    LOOP
        EXECUTE format('REVOKE %s ON %s FROM %s CASCADE', g.privilege_type, rel,
                       CASE g.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(g.grantee)) END);
    END LOOP;

    -- Drop existing policies if re-running (idempotent). Permissive
    -- policies OR together, so every earlier generation must go: the
    -- legacy single policy and the legacy per-command policies hardcoded
    -- a postgres/admin/_migrator bypass that would otherwise survive an
    -- upgrade, and the firewall policies of an earlier name of the table (a
    -- rename changes the stem). CREATE POLICY cut over-long legacy names to
    -- 63 bytes: compare them cut the same way.
    FOREACH n IN ARRAY ARRAY[legacy, legacy || '_sel', legacy || '_ins', legacy || '_upd', legacy || '_del'] LOOP
        WHILE octet_length(n) > 63 LOOP
            n := left(n, -1);
        END LOOP;
        legacies := legacies || n;
    END LOOP;
    FOR g IN
        SELECT polname FROM pg_policy
        WHERE polrelid = rel AND (polname = ANY (legacies) OR polname ~ '^fw_[0-9a-f]{12}_(sel|ins|upd|del|base)$')
    LOOP
        EXECUTE format('DROP POLICY %I ON %s', g.polname, rel);
    END LOOP;

    EXECUTE format('CREATE POLICY %I ON %s %s FOR SELECT USING (%s)', stem || '_sel', rel, kind, pred);
    -- INSERT: new rows must carry the current tenant
    EXECUTE format('CREATE POLICY %I ON %s %s FOR INSERT WITH CHECK (%s)', stem || '_ins', rel, kind, pred);
    EXECUTE format('CREATE POLICY %I ON %s %s FOR UPDATE USING (%s) WITH CHECK (%s)', stem || '_upd', rel, kind, pred, pred);
    EXECUTE format('CREATE POLICY %I ON %s %s FOR DELETE USING (%s)', stem || '_del', rel, kind, pred);

    -- Restrictive policies only narrow: PostgreSQL also needs a permissive
    -- policy to allow any row. A table with no permissive policy of its own
    -- gets "<stem>_base" (USING true); the tenant policies still apply. A
    -- table that has its own gets none, so those keep deciding which rows
    -- of the tenant a user sees. Re-run after adding the first one.
    IF p_mode = 'restrictive' AND NOT EXISTS (
        SELECT 1 FROM pg_policies p
        WHERE p.schemaname = p_schema AND p.tablename = p_table AND p.permissive = 'PERMISSIVE') THEN
        EXECUTE format('CREATE POLICY %I ON %s AS PERMISSIVE FOR ALL USING (true) WITH CHECK (true)',
                       stem || '_base', rel);
    END IF;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

-- The DDL guard, at the end of every DDL command (section 11). A table counts
-- as protected when it has firewall policies. After each command it checks
-- the tables the command names and their descendants (a column added to or
-- renamed on a parent changes its children too) and, after a command that
-- can change tables it does not name (ALTER TYPE ... CASCADE, CREATE SCHEMA,
-- GRANT ... ON ALL TABLES, any command not listed below), every table in
-- the schemas this script protects. A schema migrated by a version without
-- _firewall_protected_schemas is guarded once it is migrated again.
--   * A table with the tenant column and no firewall policies is protected at
--     once, the way this script would, so there is no window until the next
--     run. One with a permissive policy of its own, in permissive mode, is
--     refused instead (that policy would OR with the tenant policies).
--   * A command fails when it leaves a protected table weaker: RLS off or not
--     forced, a firewall policy missing or altered, another permissive policy
--     in permissive mode, a rule, or the table taken out of what this script
--     protects (its schema, a name it skips, its tenant column). A renamed
--     table gets the policies of its new name. TRIGGER and TRUNCATE granted
--     to another role are revoked again, as this script does.
--   * Policy names fw_<12 hex digits>_* are the firewall's: no command may
--     create one, rename a policy to one, or alter one.
--   * Inheritance and partitions: a protected table with a parent or a child
--     that is not protected fails, either way round. Reading the parent shows
--     the child's rows; a partition gets the rows written to the parent.
-- Not covered: code the table's owner attaches to it (a trigger, a CHECK
-- constraint, a default, a generated column, an index expression, a domain
-- constraint) runs on every tenant's writes, and can copy them out.
-- It binds every role but a superuser and the role that owns this script's
-- objects: only they can skip it (SET dbfw.ddl_guard_skip = 'on'), as this
-- script does for itself. SECURITY DEFINER (its owner is a superuser, who
-- installs it): it protects a table whoever created it. Every call it makes passes text arguments,
-- so a function planted with other argument types (name, say) cannot match
-- better than the firewall's own.
CREATE OR REPLACE FUNCTION db_firewall._firewall_ddl_guard()
RETURNS EVENT_TRIGGER AS $$
DECLARE
    fwpat CONSTANT TEXT := '^fw_[0-9a-f]{12}_(sel|ins|upd|del)$';
    t RECORD;
    s RECORD;
    g RECORD;
    stem TEXT;
    names TEXT[];
    eligible BOOLEAN;
    have INT;
    fw INT;
    rls BOOLEAN;
    forced BOOLEAN;
    reported OID[];
    scope OID[];
    whole BOOLEAN;
    todo BOOLEAN := false;
    mark TEXT;
    planted TEXT;
BEGIN
    IF TG_TAG = 'REVOKE'                   -- takes away only
       OR EXISTS (SELECT 1 FROM db_firewall._firewall_guard_calls gc       -- a call from inside the guard
                  WHERE gc.pid = pg_backend_pid() AND gc.call_id = current_setting('dbfw.guard_call', true)) THEN
        RETURN;
    END IF;
    IF current_setting('dbfw.ddl_guard_skip', true) = 'on'
       AND ((SELECT rolsuper FROM pg_roles WHERE rolname = session_user)
            OR pg_has_role(session_user, (SELECT proowner FROM pg_proc
                                          WHERE oid = 'db_firewall._firewall_protect(text, text, text, text, text)'::regprocedure),
                           'MEMBER')) THEN
        RETURN;
    END IF;
    -- A db_firewall._firewall_* object of another role: the firewall calls its
    -- functions by name, so an overload (one with a default argument, say)
    -- makes them ambiguous, and every read of a protected table, and every
    -- protection, fails. Section 0 refuses the same at the next migration.
    SELECT string_agg(o.name, ', ') INTO planted FROM (
        SELECT c.oid::regclass::text AS name, c.relowner AS owner FROM pg_class c
        WHERE c.relnamespace = 'db_firewall'::regnamespace
           OR (c.relnamespace = 'public'::regnamespace AND c.relname LIKE '#_firewall#_%' ESCAPE '#')
        UNION ALL
        SELECT p.oid::regprocedure::text, p.proowner FROM pg_proc p
        WHERE p.pronamespace = 'db_firewall'::regnamespace
           OR (p.pronamespace = 'public'::regnamespace AND p.proname LIKE '#_firewall#_%' ESCAPE '#')
        UNION ALL
        SELECT y.oid::regtype::text, y.typowner FROM pg_type y
        WHERE (y.typnamespace = 'db_firewall'::regnamespace
               OR (y.typnamespace = 'public'::regnamespace AND y.typname LIKE '#_firewall#_%' ESCAPE '#'))
          AND y.typrelid = 0
        UNION ALL
        SELECT x.oid::regoperator::text, x.oprowner FROM pg_operator x WHERE x.oprnamespace = 'db_firewall'::regnamespace) o
    JOIN pg_roles r ON r.oid = o.owner
    WHERE NOT r.rolsuper
      AND o.owner <> (SELECT proowner FROM pg_proc WHERE oid = 'db_firewall._firewall_protect(text, text, text, text, text)'::regprocedure);
    IF planted IS NOT NULL THEN
        RAISE EXCEPTION 'DB Firewall: % leaves %, which another role owns, where the firewall keeps its own objects', TG_TAG, planted
            USING HINT = 'Schema db_firewall, and the names public._firewall_*, belong to the migration''s role.';
    END IF;
    -- The tables the command names (the table of a policy or a rule).
    reported := ARRAY(SELECT CASE d.classid
                                  WHEN 'pg_catalog.pg_policy'::regclass THEN (SELECT polrelid FROM pg_policy WHERE oid = d.objid)
                                  WHEN 'pg_catalog.pg_rewrite'::regclass THEN (SELECT ev_class FROM pg_rewrite WHERE oid = d.objid)
                                  ELSE d.objid END
                      FROM pg_event_trigger_ddl_commands() d
                      WHERE d.classid IN ('pg_catalog.pg_class'::regclass, 'pg_catalog.pg_policy'::regclass,
                                          'pg_catalog.pg_rewrite'::regclass));
    -- What to check. These commands change only the tables they name and,
    -- through inheritance, their descendants: check those. Any other
    -- command (ALTER TYPE ... CASCADE, CREATE SCHEMA, GRANT ... ON ALL
    -- TABLES, an extension) checks every table in the protected schemas.
    whole := TG_TAG NOT IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'ALTER TABLE', 'CREATE FOREIGN TABLE',
                            'ALTER FOREIGN TABLE', 'ALTER INDEX', 'ALTER VIEW', 'ALTER MATERIALIZED VIEW',
                            'ALTER SEQUENCE', 'CREATE POLICY', 'ALTER POLICY', 'CREATE RULE', 'CREATE INDEX',
                            'REINDEX', 'CREATE VIEW', 'CREATE SEQUENCE', 'CREATE FUNCTION', 'ALTER FUNCTION',
                            'CREATE PROCEDURE', 'ALTER PROCEDURE', 'CREATE TRIGGER', 'ALTER TRIGGER', 'COMMENT')
             AND TG_TAG NOT LIKE 'DROP %';   -- a drop only takes away: the drop guard checks the policies
    scope := ARRAY(WITH RECURSIVE d(oid) AS (SELECT unnest(reported)
                                             UNION SELECT i.inhrelid FROM pg_inherits i JOIN d ON i.inhparent = d.oid)
                   SELECT oid FROM d)
          -- and every table in a protected schema with RLS off or not forced:
          -- EXPLAIN ANALYZE CREATE TABLE AS (or SELECT INTO) fires no event
          -- trigger, so the next command, whatever it is, protects it
          || ARRAY(SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   JOIN db_firewall._firewall_protected_schemas ps ON ps.schema_name = n.nspname
                   WHERE c.relkind IN ('r', 'p') AND c.relpersistence <> 't'
                     AND NOT (c.relrowsecurity AND c.relforcerowsecurity));
    -- A renamed schema takes its protected tables out of what this script protects.
    FOR t IN
        SELECT n.oid, n.nspname::text AS nspname FROM pg_event_trigger_ddl_commands() d
        JOIN pg_namespace n ON n.oid = d.objid
        WHERE d.classid = 'pg_catalog.pg_namespace'::regclass
    LOOP
        IF NOT EXISTS (SELECT 1 FROM db_firewall._firewall_protected_schemas WHERE schema_name = t.nspname)
           AND EXISTS (SELECT 1 FROM pg_class c JOIN pg_policy p ON p.polrelid = c.oid
                       WHERE c.relnamespace = t.oid AND p.polname ~ fwpat) THEN
            RAISE EXCEPTION 'DB Firewall: schema % holds protected tables and is not a schema the migration protects', t.nspname
                USING HINT = 'Rename it back, or migrate the new name first.';
        END IF;
    END LOOP;
    -- The firewall's policy names: created, renamed to, or altered.
    FOR t IN
        SELECT p.polname::text AS polname, n.nspname::text AS nspname, c.relname::text AS relname
        FROM pg_event_trigger_ddl_commands() d JOIN pg_policy p ON p.oid = d.objid
        JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE d.classid = 'pg_catalog.pg_policy'::regclass AND p.polname ~ '^fw_[0-9a-f]{12}_'
          AND TG_TAG IN ('CREATE POLICY', 'ALTER POLICY')
    LOOP
        RAISE EXCEPTION 'DB Firewall: % on the policy % of %.%: policy names fw_<hash>_* are the firewall''s', TG_TAG, t.polname, t.nspname, t.relname
            USING HINT = 'Pick another name. Re-run the migration to change the firewall policies.';
    END LOOP;
    -- One set query picks the tables that need work (normally none); the
    -- loop then acts on each, so a command costs little with many tables.
    FOR t IN
        WITH c AS (
            SELECT c.oid, n.nspname::text AS nspname, c.relname::text AS relname, c.relrowsecurity AS rls,
                   c.relforcerowsecurity AS forced, c.relacl, c.relowner, ps.policy_mode,
                   'fw_' || left(md5(n.nspname || '.' || c.relname), 12) AS st,
                   ps.schema_name IS NOT NULL
                   AND c.relname NOT LIKE '#_firewall#_%' ESCAPE '#'
                   AND c.relname NOT IN ('schema_migrations', 'alembic_version', 'knex_migrations', 'prisma_migrations',
                                         '__diesel_schema_migrations', 'flyway_schema_history')
                   AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = ps.tenant_column
                                 AND a.attnum > 0 AND NOT a.attisdropped) AS eligible
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN db_firewall._firewall_protected_schemas ps ON ps.schema_name = n.nspname
            WHERE c.relkind IN ('r', 'p') AND c.relpersistence <> 't'
              AND ((whole AND ps.schema_name IS NOT NULL) OR c.oid = ANY (scope)))
        SELECT c.oid, c.nspname, c.relname FROM c
        CROSS JOIN LATERAL (
            SELECT count(*) FILTER (WHERE polname IN (c.st || '_sel', c.st || '_ins', c.st || '_upd', c.st || '_del')) AS n_have,
                   count(*) FILTER (WHERE polname ~ fwpat) AS n_fw,
                   count(*) FILTER (WHERE polpermissive AND polname NOT IN (c.st || '_sel', c.st || '_ins',
                                                                            c.st || '_upd', c.st || '_del')) AS n_other
            FROM pg_policy WHERE polrelid = c.oid) p
        WHERE (c.eligible AND p.n_fw = 0)
           OR (p.n_fw > 0 AND (NOT c.eligible OR p.n_have < 4 OR NOT c.rls OR NOT c.forced
                               OR (c.policy_mode = 'permissive' AND p.n_other > 0)
                               OR EXISTS (SELECT 1 FROM pg_rewrite r WHERE r.ev_class = c.oid AND r.rulename <> '_RETURN')
                               OR EXISTS (SELECT 1 FROM aclexplode(c.relacl) a WHERE a.grantee <> c.relowner
                                            AND a.privilege_type IN ('TRIGGER', 'TRUNCATE'))))
        ORDER BY c.oid
    LOOP
        SELECT * INTO s FROM db_firewall._firewall_protected_schemas WHERE schema_name = t.nspname;
        eligible := s.schema_name IS NOT NULL
            AND t.relname NOT LIKE '#_firewall#_%' ESCAPE '#'
            AND t.relname NOT IN ('schema_migrations', 'alembic_version', 'knex_migrations', 'prisma_migrations',
                                  '__diesel_schema_migrations', 'flyway_schema_history')
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = t.oid AND a.attname = s.tenant_column
                          AND a.attnum > 0 AND NOT a.attisdropped);
        stem := 'fw_' || left(md5(t.nspname || '.' || t.relname), 12);
        names := ARRAY[stem || '_sel', stem || '_ins', stem || '_upd', stem || '_del'];
        SELECT relrowsecurity, relforcerowsecurity INTO rls, forced FROM pg_class WHERE oid = t.oid;
        SELECT count(*) FILTER (WHERE polname = ANY (names)), count(*) FILTER (WHERE polname ~ fwpat)
          INTO have, fw FROM pg_policy WHERE polrelid = t.oid;
        IF fw = 0 THEN
            CONTINUE WHEN NOT eligible;
            IF s.policy_mode = 'permissive' AND EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = t.oid AND polpermissive) THEN
                RAISE EXCEPTION 'DB Firewall: %.% has a permissive policy of its own, which would OR with the tenant policies', t.nspname, t.relname
                    USING HINT = 'Make it AS RESTRICTIVE, or migrate with policy_mode restrictive.';
            END IF;
            todo := true;
            RAISE NOTICE 'DB Firewall: RLS applied to %.% (DDL guard)', t.nspname, t.relname;
            -- On to the checks below: a table protected just now can bring a rule along.
        ELSIF NOT eligible THEN
            RAISE EXCEPTION 'DB Firewall: % takes the protected table %.% out of what the migration protects (its schema, a name it skips, or its tenant column changed)', TG_TAG, t.nspname, t.relname
                USING HINT = 'Undo the change, or drop the firewall policies with the migration''s role first.';
        ELSIF have = 0 AND rls AND forced THEN
            -- Renamed: the policies of the old name, still in place, give way to the new name's.
            todo := true;
        ELSIF have < 4 OR NOT rls OR NOT forced THEN
            RAISE EXCEPTION 'DB Firewall: % would leave %.% without its row-level security (RLS enabled and forced, the four firewall policies)', TG_TAG, t.nspname, t.relname
                USING HINT = 'Re-run the migration to change how tables are protected. The DDL guard checks every change: see migrations/001_postgresql.sql, section 5b.';
        END IF;
        IF todo THEN
            -- _firewall_protect runs DDL, which calls both guards again. They
            -- return at once for a call from here: a one-time value, in a
            -- table only the owner reads, marks it (no catalog write, so no
            -- lock that another session's open transaction could hold).
            mark := gen_random_uuid()::text;
            INSERT INTO db_firewall._firewall_guard_calls (pid, call_id) VALUES (pg_backend_pid(), mark);
            PERFORM set_config('dbfw.guard_call', mark, true);
            PERFORM db_firewall._firewall_protect(t.nspname::text, t.relname::text, s.tenant_column::text,
                                             s.policy_mode::text, s.context::text);
            PERFORM set_config('dbfw.guard_call', '', true);
            DELETE FROM db_firewall._firewall_guard_calls gc WHERE gc.pid = pg_backend_pid();
            todo := false;
        END IF;
        IF s.policy_mode = 'permissive' AND EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = t.oid AND polpermissive
                                                                         AND NOT polname = ANY (names)) THEN
            RAISE EXCEPTION 'DB Firewall: % leaves a permissive policy on %.% next to the tenant policies: it ORs with them and opens other tenants'' rows', TG_TAG, t.nspname, t.relname
                USING HINT = 'Make it AS RESTRICTIVE, or migrate with policy_mode restrictive.';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_rewrite WHERE ev_class = t.oid AND rulename <> '_RETURN') THEN
            RAISE EXCEPTION 'DB Firewall: % leaves a rule on %.%: a rule runs on every tenant''s rows', TG_TAG, t.nspname, t.relname
                USING HINT = 'Drop the rule. Use a view or a restrictive policy instead.';
        END IF;
        -- REVOKE only takes away: the guard returns at once for it, so this
        -- does not nest a guard per table (GRANT ... ON ALL TABLES).
        FOR g IN
            SELECT DISTINCT a.grantee, a.privilege_type FROM pg_class c, aclexplode(c.relacl) a
            WHERE c.oid = t.oid AND a.grantee <> c.relowner AND a.privilege_type IN ('TRIGGER', 'TRUNCATE')
        LOOP
            EXECUTE format('REVOKE %s ON %s FROM %s CASCADE', g.privilege_type, t.oid::regclass,
                           CASE g.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(g.grantee)) END);
            RAISE NOTICE 'DB Firewall: % on %.% revoked again: only the owner keeps it (DDL guard)', g.privilege_type, t.nspname, t.relname;
        END LOOP;
    END LOOP;
    -- A protected table and a parent or child that is not protected.
    FOR t IN
        SELECT i.inhparent::regclass::text AS parent, i.inhrelid::regclass::text AS child,
               EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = i.inhparent AND p.polname ~ fwpat) AS parent_protected
        FROM pg_inherits i JOIN pg_class ch ON ch.oid = i.inhrelid JOIN pg_class pa ON pa.oid = i.inhparent
        WHERE ch.relpersistence <> 't'
          AND (i.inhparent = ANY (scope) OR i.inhrelid = ANY (scope)
               OR (whole AND EXISTS (SELECT 1 FROM pg_namespace n JOIN db_firewall._firewall_protected_schemas ps ON ps.schema_name = n.nspname
                                     WHERE n.oid IN (ch.relnamespace, pa.relnamespace))))
          AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = i.inhparent AND p.polname ~ fwpat)
              <> EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = i.inhrelid AND p.polname ~ fwpat)
        LIMIT 1
    LOOP
        IF t.parent_protected THEN
            RAISE EXCEPTION 'DB Firewall: % puts %, which is not protected, under the protected table %: it gets the rows written to it', TG_TAG, t.child, t.parent
                USING HINT = 'Create the partition or child in a schema the migration protects, with the tenant column.';
        END IF;
        RAISE EXCEPTION 'DB Firewall: % puts the protected table % under %, which is not protected: reading it shows the protected rows', TG_TAG, t.child, t.parent
            USING HINT = 'Protect the parent first (give it the tenant column and re-run the migration).';
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- The same guard for drops: a firewall policy dropped from a table that still
-- exists (DROP POLICY, a column dropped with CASCADE, DROP OWNED). Dropping
-- the table itself is fine. The same roles can skip it.
CREATE OR REPLACE FUNCTION db_firewall._firewall_ddl_drop_guard()
RETURNS EVENT_TRIGGER AS $$
DECLARE
    o RECORD;
BEGIN
    IF EXISTS (SELECT 1 FROM db_firewall._firewall_guard_calls gc       -- a call from inside the guard
               WHERE gc.pid = pg_backend_pid() AND gc.call_id = current_setting('dbfw.guard_call', true)) THEN
        RETURN;
    END IF;
    IF current_setting('dbfw.ddl_guard_skip', true) = 'on'
       AND ((SELECT rolsuper FROM pg_roles WHERE rolname = session_user)
            OR pg_has_role(session_user, (SELECT proowner FROM pg_proc
                                          WHERE oid = 'db_firewall._firewall_protect(text, text, text, text, text)'::regprocedure),
                           'MEMBER')) THEN
        RETURN;
    END IF;
    FOR o IN
        SELECT d.address_names[1] AS sch, d.address_names[2] AS tbl, d.address_names[3] AS pol
        FROM pg_event_trigger_dropped_objects() d
        WHERE d.object_type = 'policy' AND d.address_names[3] ~ '^fw_[0-9a-f]{12}_(sel|ins|upd|del)$'
          AND to_regclass(quote_ident(d.address_names[1]) || '.' || quote_ident(d.address_names[2])) IS NOT NULL
    LOOP
        RAISE EXCEPTION 'DB Firewall: % drops the firewall policy % and would leave %.% without its row-level security', TG_TAG, o.pol, o.sch, o.tbl
            USING HINT = 'A DROP ... CASCADE of the tenant column, its type, domain or collation also drops the policies. Re-run the migration to change the firewall policies.';
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- ============================================================================
-- 6. AUTO-APPLY RLS TO ALL TABLES WITH THE TENANT COLUMN (dbfw.tenant_column)
-- ============================================================================
-- This DO block scans your schema and applies RLS to every table
-- that has a tenant_id column. Run after every migration.
-- ============================================================================

DO $$
DECLARE
    r RECORD;
    col TEXT := COALESCE(NULLIF(current_setting('dbfw.tenant_column', true), ''), 'tenant_id');
    sch TEXT := COALESCE(NULLIF(current_setting('dbfw.schema', true), ''), 'public');
    -- dbfw.policy_mode: 'permissive' (default) or 'restrictive'. Restrictive
    -- tenant policies AND with the app's own policies (Supabase, Drizzle
    -- pgPolicy), so an app policy can never widen access past the tenant.
    mode TEXT := lower(COALESCE(NULLIF(current_setting('dbfw.policy_mode', true), ''), 'permissive'));
    -- dbfw.context: 'signed' (default, see the header) or 'plain' (any SQL the
    -- app runs can set app.current_tenant and so switch tenants).
    ctx TEXT := lower(COALESCE(NULLIF(current_setting('dbfw.context', true), ''), 'signed'));
BEGIN
    IF mode NOT IN ('permissive', 'restrictive') THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.policy_mode must be permissive or restrictive, got %', mode;
    END IF;
    IF ctx NOT IN ('signed', 'plain') THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.context must be signed or plain, got %', ctx;
    END IF;
    -- What the DDL guard protects later tables with (and no schema that is gone).
    DELETE FROM db_firewall._firewall_protected_schemas p
    WHERE NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = p.schema_name);
    INSERT INTO db_firewall._firewall_protected_schemas (schema_name, tenant_column, policy_mode, context)
    VALUES (sch, col, mode, ctx)
    ON CONFLICT (schema_name) DO UPDATE SET tenant_column = EXCLUDED.tenant_column,
        policy_mode = EXCLUDED.policy_mode, context = EXCLUDED.context, updated_at = now();
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
        -- text arguments: a function planted with other types cannot match better.
        PERFORM db_firewall._firewall_protect(r.table_schema::text, r.table_name::text, col::text, mode::text, ctx::text);

        RAISE NOTICE 'DB Firewall: RLS applied to %.%', r.table_schema, r.table_name;
    END LOOP;
END;
$$;


-- 7. Audit log auto-purge (run via pg_cron or application scheduler)
CREATE OR REPLACE FUNCTION db_firewall._firewall_purge_audit(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM db_firewall._firewall_audit_log
    WHERE assigned_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

-- 8. Only the owner may read the key or sign, or read or change what the DDL
--    guard protects (_firewall_protected_schemas, _firewall_guard_calls); only the owner may change
--    the bypass list and the tenant map (reading the map stays allowed: the
--    db_user_map resolution reads it). REVOKE ... FROM PUBLIC is not enough:
--    platforms such as Supabase grant new objects in public to their roles
--    directly (default privileges), so every grantee but the owner is
--    revoked, column grants included.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT 'TABLE ' || c.oid::regclass::text AS obj, a.privilege_type AS priv, '' AS cols, a.grantee
        FROM pg_class c, aclexplode(c.relacl) a
        WHERE c.oid IN ('db_firewall._firewall_keys'::regclass, 'db_firewall._firewall_bypass_roles'::regclass,
                        'db_firewall._firewall_tenant_map'::regclass, 'db_firewall._firewall_protected_schemas'::regclass,
                        'db_firewall._firewall_guard_calls'::regclass)
          AND a.grantee <> c.relowner
          AND (c.oid IN ('db_firewall._firewall_keys'::regclass, 'db_firewall._firewall_protected_schemas'::regclass,
                         'db_firewall._firewall_guard_calls'::regclass)
               OR a.privilege_type <> 'SELECT')
        UNION
        SELECT 'TABLE ' || c.oid::regclass::text, a.privilege_type, quote_ident(att.attname), a.grantee
        FROM pg_class c JOIN pg_attribute att ON att.attrelid = c.oid, aclexplode(att.attacl) a
        WHERE c.oid IN ('db_firewall._firewall_keys'::regclass, 'db_firewall._firewall_bypass_roles'::regclass,
                        'db_firewall._firewall_tenant_map'::regclass, 'db_firewall._firewall_protected_schemas'::regclass,
                        'db_firewall._firewall_guard_calls'::regclass)
          AND a.grantee <> c.relowner
          AND (c.oid IN ('db_firewall._firewall_keys'::regclass, 'db_firewall._firewall_protected_schemas'::regclass,
                         'db_firewall._firewall_guard_calls'::regclass)
               OR a.privilege_type <> 'SELECT')
        UNION
        SELECT 'FUNCTION ' || p.oid::regprocedure::text, 'ALL', '', a.grantee
        FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.oid IN ('db_firewall._firewall_sign(text)'::regprocedure, 'db_firewall._firewall_set_tenant(text)'::regprocedure)
          AND a.grantee <> p.proowner
    LOOP
        EXECUTE format('REVOKE %s%s ON %s FROM %s', r.priv,
                       CASE WHEN r.cols <> '' THEN ' (' || r.cols || ')' ELSE '' END, r.obj,
                       CASE r.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(r.grantee)) END);
    END LOOP;
END;
$$;

-- 9. Opt-in (dbfw.harden_signals = on): all tenants share one role, and a role
--    may end or cancel its own other sessions, so SQL one tenant runs could
--    stop another tenant's requests. This revokes pg_terminate_backend and
--    pg_cancel_backend from PUBLIC in this database. That covers every app
--    and role in the database, so it is off by default; it needs a superuser.
--    Superusers keep both; grant them back to admin roles that need them.
DO $$
DECLARE
    f REGPROCEDURE;
BEGIN
    IF lower(COALESCE(NULLIF(current_setting('dbfw.harden_signals', true), ''), 'off')) NOT IN ('on', 'true', '1')
       AND lower(COALESCE(NULLIF(current_setting('dbfw.harden', true), ''), 'off')) NOT IN ('on', 'true', '1') THEN
        RETURN;
    END IF;
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.harden_signals needs a superuser (it changes pg_catalog functions)';
    END IF;
    FOR f IN SELECT p.oid FROM pg_proc p
             WHERE p.pronamespace = 'pg_catalog'::regnamespace
               AND p.proname IN ('pg_terminate_backend', 'pg_cancel_backend')
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END;
$$;

-- 10. Opt-in (dbfw.harden = on, which also does section 9): remove what
--     `db-firewall verify` fails on that this script can remove, from PUBLIC
--     and from dbfw.app_role when set, whoever granted it:
--     - CREATE on the database (new schemas, such as one named like the role,
--       come first in the default search_path) and on every schema (planted
--       objects and operators);
--     - TRIGGER and TRUNCATE on every table (a trigger function runs in other
--       tenants' sessions; TRUNCATE ignores RLS), also in default privileges,
--       so tables created later do not get them;
--     - pg_stat_activity, pg_stat_get_activity and pg_stat_get_backend_activity,
--       and pg_stat_statements when installed: one shared role sees the SQL
--       text of its other sessions, so one tenant could read the literal
--       values in another tenant's queries. Roles that only have pg_monitor
--       lose pg_stat_activity too: grant it to them again.
--     Database-wide, so off by default; needs a superuser. With dbfw.app_role
--     it refuses (and the whole script changes nothing) when that role can act
--     as the owner of the database or of any object in it (an owner can grant
--     itself everything back), or still has one of these privileges afterwards
--     through a role it is a member of. CASCADE also removes what the app role
--     passed on with a grant option.
DO $$
DECLARE
    app TEXT := NULLIF(current_setting('dbfw.app_role', true), '');
    app_oid OID;
    me TEXT := current_user;
    r RECORD;
    found TEXT;
BEGIN
    IF lower(COALESCE(NULLIF(current_setting('dbfw.harden', true), ''), 'off')) NOT IN ('on', 'true', '1') THEN
        RETURN;
    END IF;
    IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.harden needs a superuser';
    END IF;
    IF app IS NOT NULL THEN
        SELECT oid INTO app_oid FROM pg_catalog.pg_roles WHERE rolname = app;
        IF app_oid IS NULL THEN
            RAISE EXCEPTION 'DB Firewall: dbfw.app_role %: no such role (give the bare name, without quotes)', app;
        END IF;
        -- Any object (pg_shdepend), as `verify` counts them: an owner can grant
        -- itself everything back, or change what runs in other tenants'
        -- sessions (a domain constraint, a function body).
        SELECT string_agg(o, ', ') INTO found FROM (
            SELECT 'database ' || quote_ident(datname) AS o FROM pg_catalog.pg_database
            WHERE datname = current_database() AND pg_catalog.pg_has_role(app_oid, datdba, 'MEMBER')
            UNION ALL
            (SELECT o.type || ' ' || o.identity FROM pg_catalog.pg_shdepend d
             CROSS JOIN LATERAL pg_catalog.pg_identify_object(d.classid, d.objid, 0) o
             WHERE d.dbid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
               AND d.deptype = 'o'
               AND d.classid NOT IN ('pg_catalog.pg_largeobject'::pg_catalog.regclass,
                                     'pg_catalog.pg_default_acl'::pg_catalog.regclass,
                                     'pg_catalog.pg_user_mapping'::pg_catalog.regclass)
               AND pg_catalog.pg_has_role(app_oid, d.refobjid, 'MEMBER')
               AND COALESCE(o.schema, '') NOT LIKE 'pg#_temp#_%' ESCAPE '#'
               AND COALESCE(o.schema, '') NOT LIKE 'pg#_toast#_temp#_%' ESCAPE '#'
             ORDER BY 1 LIMIT 20)) s;
        IF found IS NOT NULL THEN
            RAISE EXCEPTION 'DB Firewall: dbfw.harden: % can act as the owner of %: give them to another role first (ALTER ... OWNER TO)', app, found;
        END IF;
    END IF;
    -- Every grant to PUBLIC or the app role, by any grantor: a REVOKE removes
    -- only the grants of the role that runs it (a superuser's: the owner's), so
    -- each runs as its grantor. CASCADE: also what the app role passed on with
    -- a grant option.
    FOR r IN
        WITH g AS (SELECT 0::pg_catalog.oid AS oid UNION ALL SELECT app_oid WHERE app_oid IS NOT NULL),
        acl AS (
            SELECT format('DATABASE %I', d.datname) AS obj, a.* FROM pg_catalog.pg_database d,
                   LATERAL pg_catalog.aclexplode(d.datacl) a
            WHERE d.datname = current_database() AND a.privilege_type = 'CREATE'
            UNION ALL
            SELECT format('SCHEMA %I', n.nspname), a.* FROM pg_catalog.pg_namespace n,
                   LATERAL pg_catalog.aclexplode(n.nspacl) a
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg#_%' ESCAPE '#'
              AND a.privilege_type = 'CREATE'
            UNION ALL
            SELECT format('TABLE %s', c.oid::pg_catalog.regclass), a.* FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace, LATERAL pg_catalog.aclexplode(c.relacl) a
            WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg#_%' ESCAPE '#'
              AND a.privilege_type IN ('TRIGGER', 'TRUNCATE'))
        SELECT pg_catalog.pg_get_userbyid(acl.grantor) AS grantor,
               format('REVOKE %s ON %s FROM %s CASCADE', acl.privilege_type, acl.obj,
                      CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(acl.grantee)) END) AS cmd
        FROM acl WHERE acl.grantee IN (SELECT oid FROM g)
        UNION ALL
        -- Default privileges: tables (and schemas) created later.
        SELECT me, format('ALTER DEFAULT PRIVILEGES FOR ROLE %I%s REVOKE %s ON %s FROM %s',
                      pg_catalog.pg_get_userbyid(da.defaclrole),
                      CASE WHEN da.defaclnamespace <> 0 THEN format(' IN SCHEMA %I', n.nspname) ELSE '' END,
                      a.privilege_type, CASE da.defaclobjtype WHEN 'r' THEN 'TABLES' ELSE 'SCHEMAS' END,
                      CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(a.grantee)) END)
        FROM pg_catalog.pg_default_acl da LEFT JOIN pg_catalog.pg_namespace n ON n.oid = da.defaclnamespace,
             LATERAL pg_catalog.aclexplode(da.defaclacl) a
        WHERE a.grantee IN (SELECT oid FROM g)
          AND ((da.defaclobjtype = 'r' AND a.privilege_type IN ('TRIGGER', 'TRUNCATE'))
               OR (da.defaclobjtype = 'n' AND a.privilege_type = 'CREATE'))
    LOOP
        BEGIN
            EXECUTE format('SET LOCAL ROLE %I', r.grantor);
            EXECUTE r.cmd;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE EXCEPTION 'DB Firewall: dbfw.harden: % as its grantor % failed: % (grant % USAGE on that schema, or revoke it by hand)',
                r.cmd, r.grantor, SQLERRM, r.grantor;
        END;
        EXECUTE format('SET LOCAL ROLE %I', me);
    END LOOP;
    REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC;
    REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer),
                               pg_catalog.pg_stat_get_backend_activity(integer) FROM PUBLIC;
    -- pg_stat_statements, when installed: its text keeps some literal values.
    FOR r IN SELECT format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', p.oid::pg_catalog.regprocedure) AS cmd
             FROM pg_catalog.pg_proc p WHERE p.proname = 'pg_stat_statements'
             UNION ALL
             SELECT format('REVOKE SELECT ON %s FROM PUBLIC', c.oid::pg_catalog.regclass)
             FROM pg_catalog.pg_class c WHERE c.relname IN ('pg_stat_statements', 'pg_stat_statements_info')
               AND c.relkind = 'v'
    LOOP
        EXECUTE r.cmd;
    END LOOP;
    IF app_oid IS NOT NULL THEN
        -- What is left comes through roles the app role is a member of.
        SELECT string_agg(o, ', ') INTO found FROM (
            SELECT 'CREATE on database ' || quote_ident(current_database()) AS o
            WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_roles m WHERE pg_catalog.pg_has_role(app_oid, m.oid, 'MEMBER')
                            AND pg_catalog.has_database_privilege(m.oid, current_database(), 'CREATE'))
            UNION ALL
            SELECT 'CREATE on schema ' || quote_ident(n.nspname) FROM pg_catalog.pg_namespace n
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg#_%' ESCAPE '#'
              AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles m WHERE pg_catalog.pg_has_role(app_oid, m.oid, 'MEMBER')
                            AND pg_catalog.has_schema_privilege(m.oid, n.oid, 'CREATE'))
            UNION ALL
            SELECT 'TRIGGER or TRUNCATE on ' || c.oid::pg_catalog.regclass::text FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg#_%' ESCAPE '#'
              AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles m WHERE pg_catalog.pg_has_role(app_oid, m.oid, 'MEMBER')
                            AND pg_catalog.has_table_privilege(m.oid, c.oid, 'TRIGGER, TRUNCATE'))
            UNION ALL
            SELECT 'pg_stat_activity or pg_stat_statements'
            WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_roles m WHERE pg_catalog.pg_has_role(app_oid, m.oid, 'MEMBER')
                            AND (pg_catalog.has_table_privilege(m.oid, 'pg_catalog.pg_stat_activity', 'SELECT')
                                 OR pg_catalog.has_function_privilege(m.oid, 'pg_catalog.pg_stat_get_activity(integer)', 'EXECUTE')
                                 OR pg_catalog.has_function_privilege(m.oid, 'pg_catalog.pg_stat_get_backend_activity(integer)', 'EXECUTE')
                                 OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc f WHERE f.proname = 'pg_stat_statements'
                                              AND pg_catalog.has_function_privilege(m.oid, f.oid, 'EXECUTE'))
                                 OR EXISTS (SELECT 1 FROM pg_catalog.pg_class v WHERE v.relname = 'pg_stat_statements'
                                              AND v.relkind = 'v' AND pg_catalog.has_table_privilege(m.oid, v.oid, 'SELECT'))))
            LIMIT 20) s;
        IF found IS NOT NULL THEN
            RAISE EXCEPTION 'DB Firewall: dbfw.harden: % still has %, through a role it is a member of: revoke it there, or end that membership', app, found;
        END IF;
    END IF;
END;
$$;

-- 11. Opt-in (dbfw.ddl_guard = on): install the DDL guard (section 5b) as two
--     event triggers in this database. Event triggers need a superuser. A
--     later run without dbfw.ddl_guard leaves them as they are; remove them
--     with DROP EVENT TRIGGER _firewall_ddl_guard, _firewall_ddl_drop_guard.
DO $$
BEGIN
    IF lower(COALESCE(NULLIF(current_setting('dbfw.ddl_guard', true), ''), 'off')) NOT IN ('on', 'true', '1') THEN
        RETURN;
    END IF;
    IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'DB Firewall: dbfw.ddl_guard needs a superuser (event triggers)';
    END IF;
    DROP EVENT TRIGGER IF EXISTS _firewall_ddl_guard;       -- created again: its tags may have changed
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger WHERE evtname = '_firewall_ddl_guard') THEN
        -- Every command, no tag list: ALTER INDEX and ALTER VIEW also rename
        -- a table or its columns, and a list would miss the next such path.
        CREATE EVENT TRIGGER _firewall_ddl_guard ON ddl_command_end
            EXECUTE FUNCTION db_firewall._firewall_ddl_guard();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger WHERE evtname = '_firewall_ddl_drop_guard') THEN
        CREATE EVENT TRIGGER _firewall_ddl_drop_guard ON sql_drop EXECUTE FUNCTION db_firewall._firewall_ddl_drop_guard();
    END IF;
    -- The guard must fire for every session, also one with
    -- session_replication_role = replica.
    ALTER EVENT TRIGGER _firewall_ddl_guard ENABLE ALWAYS;
    ALTER EVENT TRIGGER _firewall_ddl_drop_guard ENABLE ALWAYS;
END;
$$;

-- The same check as section 0, again (see there). Kept identical to it.
DO $$
DECLARE
    bad TEXT;
    fw OID := to_regnamespace('db_firewall');
BEGIN
    SELECT string_agg(o.name || ' (owner ' || pg_get_userbyid(o.owner) || ')', ', ') INTO bad
    FROM (SELECT 'schema db_firewall' AS name, n.nspowner AS owner FROM pg_namespace n WHERE n.oid = fw
          UNION ALL
          SELECT c.oid::regclass::text, c.relowner FROM pg_class c
          WHERE c.relnamespace = fw
             OR (c.relnamespace = 'public'::regnamespace AND c.relname LIKE '#_firewall#_%' ESCAPE '#')
          UNION ALL
          SELECT p.oid::regprocedure::text, p.proowner FROM pg_proc p
          WHERE p.pronamespace = fw
             OR (p.pronamespace = 'public'::regnamespace AND p.proname LIKE '#_firewall#_%' ESCAPE '#')
          UNION ALL
          SELECT t.oid::regtype::text, t.typowner FROM pg_type t
          WHERE (t.typnamespace = fw
                 OR (t.typnamespace = 'public'::regnamespace AND t.typname LIKE '#_firewall#_%' ESCAPE '#'))
            AND t.typrelid = 0
          UNION ALL
          SELECT o.oid::regoperator::text, o.oprowner FROM pg_operator o WHERE o.oprnamespace = fw) o
    JOIN pg_roles r ON r.oid = o.owner
    WHERE r.rolname <> current_user AND NOT r.rolsuper;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'DB Firewall: % not owned by % or a superuser. Another role may have planted them: drop them, or ALTER ... OWNER TO a trusted role, and re-run.', bad, current_user;
    END IF;
END;
$$;

COMMIT;
