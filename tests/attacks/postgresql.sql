-- Attacks on PostgreSQL tenant isolation, collected from the PR 13 to 15
-- reviews. `db-firewall verify` must fail each one with the named check.
-- Add every new bypass here before fixing it, and raise the count pinned in
-- packages/cli/test/attacks.test.mjs. Not covered yet (they need C code to
-- set up): SECURITY DEFINER type I/O functions and selectivity estimators.
--
-- The fixture (packages/cli/test/attacks.test.mjs builds it): schema {S} with
-- {S}.docs (id serial, tenant_id text, body text) and the rows
-- ('A', 'a-secret') and ('B', 'b-secret'), protected by the migration; the
-- app role {ROLE} has SELECT, INSERT, UPDATE and DELETE on it. {DB} is the
-- database. Setup and undo run as an admin (a superuser in CI).
--
-- A case:
--   -- @attack <what it does>
--   -- @check <table>: <check name>       (verify must fail it; "-" is a global check)
--   -- @mode strict                       (optional: verify --strict; default plain)
--   -- @args <more verify arguments>      (optional)
--   -- @min <major version>               (optional: skip on older servers)
--   -- @leak <SQL>                        (optional: the app runs it as tenant A, signed,
--                                          in a transaction rolled back; its rows or
--                                          notices must show "b-secret": the attack is real)
--   -- @setup
--   <SQL>
--   -- @undo
--   <SQL>
-- A "-- @pass <what>" case instead must pass verify: a safe pattern that must
-- not fail (a false fail makes the tool useless).

-- ---------------------------------------------------------------- roles
-- @attack a role it can SET ROLE to has BYPASSRLS
-- @check -: role
-- @setup
CREATE ROLE {ROLE}_bypass NOLOGIN BYPASSRLS; GRANT {ROLE}_bypass TO {ROLE};
-- @undo
REVOKE {ROLE}_bypass FROM {ROLE}; DROP ROLE {ROLE}_bypass;

-- @attack it can run programs as the server
-- @check -: role
-- @setup
GRANT pg_execute_server_program TO {ROLE};
-- @undo
REVOKE pg_execute_server_program FROM {ROLE};

-- @attack it can read server files
-- @check -: role
-- @setup
GRANT pg_read_server_files TO {ROLE};
-- @undo
REVOKE pg_read_server_files FROM {ROLE};

-- @attack it can SET ROLE to a superuser without BYPASSRLS
-- @check -: role
-- @leak SET LOCAL ROLE {ROLE}_su; SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
CREATE ROLE {ROLE}_su NOLOGIN SUPERUSER NOBYPASSRLS; GRANT {ROLE}_su TO {ROLE};
-- @undo
REVOKE {ROLE}_su FROM {ROLE}; DROP ROLE {ROLE}_su;

-- @attack the app role is in the bypass list
-- @check -: role
-- @leak SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
INSERT INTO public._firewall_bypass_roles (role_name) VALUES ('{ROLE}');
-- @undo
DELETE FROM public._firewall_bypass_roles WHERE role_name = '{ROLE}';

-- @attack it can write server files
-- @check -: role
-- @setup
GRANT pg_write_server_files TO {ROLE};
-- @undo
REVOKE pg_write_server_files FROM {ROLE};

-- @attack it is in pg_write_all_data
-- @check -: role
-- @setup
GRANT pg_write_all_data TO {ROLE};
-- @undo
REVOKE pg_write_all_data FROM {ROLE};

-- @attack a role it can SET ROLE to but does not inherit can write the bypass list (NOINHERIT)
-- @check -: cannot write firewall tables
-- @leak SET LOCAL ROLE {ROLE}_w2; INSERT INTO public._firewall_bypass_roles (role_name) VALUES ('{ROLE}'); RESET ROLE; SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
CREATE ROLE {ROLE}_w2 NOLOGIN; GRANT INSERT ON public._firewall_bypass_roles TO {ROLE}_w2;
ALTER ROLE {ROLE} NOINHERIT; GRANT {ROLE}_w2 TO {ROLE};
-- @undo
ALTER ROLE {ROLE} INHERIT; REVOKE {ROLE}_w2 FROM {ROLE};
REVOKE ALL ON public._firewall_bypass_roles FROM {ROLE}_w2; DROP ROLE {ROLE}_w2;

-- ---------------------------------------------------------------- ownership
-- @attack it owns the table (an owner can turn RLS off)
-- @check {S}.docs: role does not own the table
-- @leak ALTER TABLE {S}.docs DISABLE ROW LEVEL SECURITY; SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
ALTER TABLE {S}.docs OWNER TO {ROLE};
-- @undo
-- An owner change merges the role's own grant into the owner entry: grant it back.
ALTER TABLE {S}.docs OWNER TO CURRENT_USER; GRANT SELECT, INSERT, UPDATE, DELETE ON {S}.docs TO {ROLE};
GRANT USAGE ON SEQUENCE {S}.docs_id_seq TO {ROLE};

-- @attack it owns the database
-- @check -: owns no database objects
-- @setup
ALTER DATABASE {DB} OWNER TO {ROLE};
-- @undo
ALTER DATABASE {DB} OWNER TO CURRENT_USER;

-- @attack it owns the database, so schema public (PostgreSQL 15+: pg_database_owner)
-- @check -: does not own firewall objects
-- @min 15
-- @setup
ALTER DATABASE {DB} OWNER TO {ROLE};
-- @undo
ALTER DATABASE {DB} OWNER TO CURRENT_USER;

-- @attack it owns a firewall function (and replaces it)
-- @check -: does not own firewall objects
-- @setup
ALTER FUNCTION public._firewall_is_bypass_role(text) OWNER TO {ROLE};
-- @undo
ALTER FUNCTION public._firewall_is_bypass_role(text) OWNER TO CURRENT_USER;

-- @attack it owns a schema (an owner can grant itself CREATE back)
-- @check -: cannot create in any schema
-- @setup
CREATE SCHEMA {S}_own AUTHORIZATION {ROLE};
-- @undo
DROP SCHEMA {S}_own;

-- @attack it owns a domain a constraint of which runs in other tenants' sessions
-- @check -: owns no database objects
-- @setup
CREATE DOMAIN {S}.sec AS text; ALTER DOMAIN {S}.sec OWNER TO {ROLE};
-- @undo
DROP DOMAIN {S}.sec;

-- ---------------------------------------------------------------- firewall tables and functions
-- @attack it can write the bypass list
-- @check -: cannot write firewall tables
-- @leak INSERT INTO public._firewall_bypass_roles (role_name) VALUES (current_user); SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
GRANT INSERT ON public._firewall_bypass_roles TO {ROLE};
-- @undo
REVOKE INSERT ON public._firewall_bypass_roles FROM {ROLE};

-- @attack it has a column grant on the bypass list
-- @check -: cannot write firewall tables
-- @leak INSERT INTO public._firewall_bypass_roles (role_name) VALUES (current_user); SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
GRANT INSERT (role_name) ON public._firewall_bypass_roles TO {ROLE};
-- @undo
REVOKE INSERT (role_name) ON public._firewall_bypass_roles FROM {ROLE};

-- @attack a SET-only role can write the bypass list
-- @check -: cannot write firewall tables
-- @min 16
-- @leak SET LOCAL ROLE {ROLE}_w; INSERT INTO public._firewall_bypass_roles (role_name) VALUES ('{ROLE}'); RESET ROLE; SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
CREATE ROLE {ROLE}_w NOLOGIN; GRANT INSERT ON public._firewall_bypass_roles TO {ROLE}_w;
GRANT {ROLE}_w TO {ROLE} WITH INHERIT FALSE;
-- @undo
REVOKE {ROLE}_w FROM {ROLE}; REVOKE ALL ON public._firewall_bypass_roles FROM {ROLE}_w; DROP ROLE {ROLE}_w;

-- @attack it can UPDATE a row of the bypass list
-- @check -: cannot write firewall tables
-- @leak UPDATE public._firewall_bypass_roles SET role_name = current_user; SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
INSERT INTO public._firewall_bypass_roles (role_name) VALUES ('{ROLE}_mig'); GRANT UPDATE ON public._firewall_bypass_roles TO {ROLE};
-- @undo
REVOKE UPDATE ON public._firewall_bypass_roles FROM {ROLE}; DELETE FROM public._firewall_bypass_roles WHERE role_name IN ('{ROLE}_mig', '{ROLE}');

-- @attack it can execute _firewall_set_tenant
-- @check -: cannot read the key or sign
-- @leak SELECT public._firewall_set_tenant('B'); SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
GRANT EXECUTE ON FUNCTION public._firewall_set_tenant(text) TO {ROLE};
-- @undo
REVOKE EXECUTE ON FUNCTION public._firewall_set_tenant(text) FROM {ROLE};

-- @attack it can write the tenant map
-- @check -: cannot write firewall tables
-- @leak INSERT INTO public._firewall_tenant_map (db_user, tenant_id) VALUES (session_user, 'B'); SELECT set_config('app.current_tenant', '', true); SELECT public._firewall_auto_resolve(); SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
GRANT INSERT ON public._firewall_tenant_map TO {ROLE};
-- @undo
REVOKE INSERT ON public._firewall_tenant_map FROM {ROLE}; DELETE FROM public._firewall_tenant_map;

-- @attack it can read the signing key
-- @check -: cannot read the key or sign
-- @setup
GRANT SELECT ON public._firewall_keys TO {ROLE};
-- @undo
REVOKE SELECT ON public._firewall_keys FROM {ROLE};

-- @attack it can sign
-- @check -: cannot read the key or sign
-- @leak SELECT set_config('app.current_tenant', 'B', true), set_config('app.tenant_sig', public._firewall_sign('B'), true); SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
GRANT EXECUTE ON FUNCTION public._firewall_sign(text) TO {ROLE};
-- @undo
REVOKE EXECUTE ON FUNCTION public._firewall_sign(text) FROM {ROLE};

-- @attack the bypass function was changed
-- @check -: firewall functions unchanged
-- @leak SET LOCAL dbfw.maintenance = 'on'; SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
-- CREATE OR REPLACE keeps the function the policies call; the undo puts the saved one back.
CREATE TABLE public.{S}_saved AS SELECT pg_get_functiondef('public._firewall_is_bypass_role(text)'::regprocedure) AS def;
CREATE OR REPLACE FUNCTION public._firewall_is_bypass_role(p_role TEXT) RETURNS BOOLEAN AS $f$
    SELECT EXISTS (SELECT 1 FROM public._firewall_bypass_roles WHERE role_name = p_role)
        OR current_setting('dbfw.maintenance', true) = 'on';
$f$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp;
-- @undo
DO $u$ BEGIN EXECUTE (SELECT def FROM public.{S}_saved); END $u$; DROP TABLE public.{S}_saved;

-- @attack _firewall_tenant was changed to trust an unsigned tenant
-- @check -: firewall functions unchanged
-- @leak SELECT set_config('app.current_tenant', 'B', true); SELECT string_agg(body, ',') FROM {S}.docs
-- @setup
CREATE TABLE public.{S}_saved AS SELECT pg_get_functiondef('public._firewall_tenant()'::regprocedure) AS def;
CREATE OR REPLACE FUNCTION public._firewall_tenant() RETURNS TEXT AS $f$
    SELECT NULLIF(current_setting('app.current_tenant', true), '');
$f$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp;
-- @undo
DO $u$ BEGIN EXECUTE (SELECT def FROM public.{S}_saved); END $u$; DROP TABLE public.{S}_saved;

-- @attack _firewall_auto_resolve was changed
-- @check -: firewall functions unchanged
-- @setup
ALTER FUNCTION public._firewall_auto_resolve() RENAME TO _firewall_auto_resolve_saved;
CREATE FUNCTION public._firewall_auto_resolve() RETURNS TEXT AS $f$ SELECT 'x'::text $f$ LANGUAGE sql;
-- @undo
DROP FUNCTION public._firewall_auto_resolve();
ALTER FUNCTION public._firewall_auto_resolve_saved() RENAME TO _firewall_auto_resolve;

-- @attack an extra _firewall_ function
-- @check -: firewall functions unchanged
-- @setup
CREATE FUNCTION public._firewall_extra() RETURNS int LANGUAGE sql AS 'SELECT 1';
-- @undo
DROP FUNCTION public._firewall_extra();

-- ---------------------------------------------------------------- privileges RLS does not cover
-- @attack it has TRUNCATE (RLS does not apply to it)
-- @check {S}.docs: no TRUNCATE
-- @setup
GRANT TRUNCATE ON {S}.docs TO {ROLE};
-- @undo
REVOKE TRUNCATE ON {S}.docs FROM {ROLE};

-- @attack it has TRUNCATE through a role it can SET ROLE to (NOINHERIT)
-- @check {S}.docs: no TRUNCATE
-- @setup
CREATE ROLE {ROLE}_trunc NOLOGIN; GRANT TRUNCATE ON {S}.docs TO {ROLE}_trunc;
ALTER ROLE {ROLE} NOINHERIT; GRANT {ROLE}_trunc TO {ROLE};
-- @undo
ALTER ROLE {ROLE} INHERIT; REVOKE {ROLE}_trunc FROM {ROLE}; REVOKE ALL ON {S}.docs FROM {ROLE}_trunc; DROP ROLE {ROLE}_trunc;

-- @attack it owns a table (an owner can create triggers on it)
-- @check -: cannot create triggers
-- @setup
CREATE TABLE {S}.mine (x int); ALTER TABLE {S}.mine OWNER TO {ROLE};
-- @undo
DROP TABLE {S}.mine;

-- @attack a planted function shadows a catalog function through the role's search_path
-- @check {S}.docs: no TRUNCATE
-- @setup
CREATE FUNCTION {S}.has_table_privilege(oid, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false';
GRANT TRUNCATE ON {S}.docs TO {ROLE}; ALTER ROLE {ROLE} SET search_path = {S}, pg_catalog;
-- @undo
ALTER ROLE {ROLE} RESET search_path; REVOKE TRUNCATE ON {S}.docs FROM {ROLE};
DROP FUNCTION {S}.has_table_privilege(oid, oid, text);

-- @attack it has TRIGGER on a table
-- @check -: cannot create triggers
-- @setup
GRANT TRIGGER ON {S}.docs TO {ROLE};
-- @undo
REVOKE TRIGGER ON {S}.docs FROM {ROLE};

-- @attack it can CREATE schemas in the database
-- @check -: cannot create in any schema
-- @setup
GRANT CREATE ON DATABASE {DB} TO {ROLE};
-- @undo
REVOKE CREATE ON DATABASE {DB} FROM {ROLE};

-- @attack it can CREATE in public
-- @check -: cannot create in any schema
-- @setup
GRANT CREATE ON SCHEMA public TO {ROLE};
-- @undo
REVOKE CREATE ON SCHEMA public FROM {ROLE};

-- @attack it can CREATE in the app's schema
-- @check -: cannot create in any schema
-- @setup
GRANT CREATE ON SCHEMA {S} TO {ROLE};
-- @undo
REVOKE CREATE ON SCHEMA {S} FROM {ROLE};

-- @attack an unprotected tenant table (no grant yet)
-- @check {S}.ledger: policies
-- @setup
CREATE TABLE {S}.ledger (id int, tenant_id text);
-- @undo
DROP TABLE {S}.ledger;

-- @attack a readable tenant table in another schema
-- @check -: no tenant tables in other schemas
-- @leak SELECT string_agg(body, ',') FROM {S}_other.docs
-- @setup
CREATE SCHEMA {S}_other; CREATE TABLE {S}_other.docs (id int, tenant_id text, body text);
INSERT INTO {S}_other.docs VALUES (2, 'B', 'b-secret');
GRANT USAGE ON SCHEMA {S}_other TO {ROLE}; GRANT SELECT ON {S}_other.docs TO {ROLE};
-- @undo
DROP SCHEMA {S}_other CASCADE;

-- @attack a column grant on a tenant table in another schema
-- @check -: no tenant tables in other schemas
-- @leak SELECT string_agg(body, ',') FROM {S}_other.copy
-- @setup
CREATE SCHEMA {S}_other; CREATE TABLE {S}_other.copy (id int, tenant_id text, body text);
INSERT INTO {S}_other.copy VALUES (2, 'B', 'b-secret');
GRANT USAGE ON SCHEMA {S}_other TO {ROLE}; GRANT SELECT (body) ON {S}_other.copy TO {ROLE};
-- @undo
DROP SCHEMA {S}_other CASCADE;

-- ---------------------------------------------------------------- views
-- @attack a view runs as a superuser
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.v_docs
-- @setup
CREATE VIEW {S}.v_docs AS SELECT * FROM {S}.docs; GRANT SELECT ON {S}.v_docs TO {ROLE};
-- @undo
DROP VIEW {S}.v_docs;

-- @attack a definer view readable through a column grant
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.col_v
-- @setup
CREATE VIEW {S}.col_v AS SELECT * FROM {S}.docs; GRANT SELECT (body) ON {S}.col_v TO {ROLE};
-- @undo
DROP VIEW {S}.col_v;

-- @attack a view on a definer view
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.outer_v
-- @setup
CREATE VIEW {S}.inner_v AS SELECT * FROM {S}.docs; CREATE VIEW {S}.outer_v AS SELECT * FROM {S}.inner_v;
GRANT SELECT ON {S}.outer_v TO {ROLE};
-- @undo
DROP VIEW {S}.outer_v; DROP VIEW {S}.inner_v;

-- @attack a definer view in another schema
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}_other.all_docs
-- @setup
CREATE SCHEMA {S}_other; CREATE VIEW {S}_other.all_docs AS SELECT * FROM {S}.docs;
GRANT USAGE ON SCHEMA {S}_other TO {ROLE}; GRANT SELECT ON {S}_other.all_docs TO {ROLE};
-- @undo
DROP SCHEMA {S}_other CASCADE;

-- @attack a definer view owned by a non-bypassing role over a superuser's definer view the app cannot read
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.outer_x
-- @setup
CREATE ROLE {ROLE}_x NOLOGIN;
CREATE VIEW {S}.inner_d AS SELECT * FROM {S}.docs; GRANT SELECT ON {S}.inner_d TO {ROLE}_x;
CREATE VIEW {S}.outer_x AS SELECT * FROM {S}.inner_d; ALTER VIEW {S}.outer_x OWNER TO {ROLE}_x;
GRANT SELECT ON {S}.outer_x TO {ROLE};
-- @undo
DROP VIEW {S}.outer_x; DROP VIEW {S}.inner_d; DROP ROLE {ROLE}_x;

-- @attack a view owned by a superuser without BYPASSRLS
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.su_v
-- @setup
CREATE ROLE {ROLE}_su2 NOLOGIN SUPERUSER NOBYPASSRLS;
CREATE VIEW {S}.su_v AS SELECT * FROM {S}.docs; ALTER VIEW {S}.su_v OWNER TO {ROLE}_su2; GRANT SELECT ON {S}.su_v TO {ROLE};
-- @undo
DROP VIEW {S}.su_v; DROP ROLE {ROLE}_su2;

-- @attack a materialized view
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.m_docs
-- @setup
CREATE MATERIALIZED VIEW {S}.m_docs AS SELECT * FROM {S}.docs; GRANT SELECT ON {S}.m_docs TO {ROLE};
-- @undo
DROP MATERIALIZED VIEW {S}.m_docs;

-- @attack a materialized view over an invoker view
-- @check -: no RLS-bypassing views or functions
-- @min 15
-- @leak SELECT string_agg(body, ',') FROM {S}.mv
-- @setup
CREATE VIEW {S}.base_v WITH (security_invoker = true) AS SELECT * FROM {S}.docs;
CREATE MATERIALIZED VIEW {S}.mv AS SELECT * FROM {S}.base_v; GRANT SELECT ON {S}.mv TO {ROLE};
-- @undo
DROP MATERIALIZED VIEW {S}.mv; DROP VIEW {S}.base_v;

-- @attack a materialized view over a function
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.bodies_mv
-- @setup
CREATE FUNCTION {S}.all_bodies() RETURNS TABLE (body text) LANGUAGE sql STABLE AS 'SELECT body FROM {S}.docs';
CREATE MATERIALIZED VIEW {S}.bodies_mv AS SELECT * FROM {S}.all_bodies(); GRANT SELECT ON {S}.bodies_mv TO {ROLE};
-- @undo
DROP MATERIALIZED VIEW {S}.bodies_mv; DROP FUNCTION {S}.all_bodies();

-- @attack --allow-global cannot clear a definer view over a tenant table
-- @check -: no RLS-bypassing views or functions
-- @mode strict
-- @args --allow-global {S}.ref_*
-- @leak SELECT string_agg(body, ',') FROM {S}.ref_docs
-- @setup
CREATE VIEW {S}.ref_docs AS SELECT * FROM {S}.docs; GRANT SELECT ON {S}.ref_docs TO {ROLE};
-- @undo
DROP VIEW {S}.ref_docs;

-- @attack a definer view owned by a non-bypassing role over a materialized view of a tenant table
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.over_mv
-- @setup
CREATE ROLE {ROLE}_mvo NOLOGIN;
-- Filled as the superuser (every tenant's rows), then owned by a role that does not skip RLS:
-- only "a materialized view has no RLS" flags it.
CREATE MATERIALIZED VIEW {S}.hidden_mv AS SELECT * FROM {S}.docs; ALTER MATERIALIZED VIEW {S}.hidden_mv OWNER TO {ROLE}_mvo;
CREATE VIEW {S}.over_mv AS SELECT * FROM {S}.hidden_mv; ALTER VIEW {S}.over_mv OWNER TO {ROLE}_mvo;
GRANT SELECT ON {S}.over_mv TO {ROLE};
-- @undo
DROP VIEW {S}.over_mv; DROP MATERIALIZED VIEW {S}.hidden_mv; DROP ROLE {ROLE}_mvo;

-- @attack an invoker view over a table the app cannot read
-- @check -: strict: only tenant data readable
-- @mode strict
-- @min 15
-- @setup
CREATE TABLE {S}.plain_t (note text);
CREATE VIEW {S}.iv WITH (security_invoker = true) AS SELECT * FROM {S}.plain_t; GRANT SELECT ON {S}.iv TO {ROLE};
-- @undo
DROP VIEW {S}.iv; DROP TABLE {S}.plain_t;

-- @attack an invoker view over an invoker view over a table that is not tenant data
-- @check -: strict: only tenant data readable
-- @mode strict
-- @min 15
-- @setup
CREATE TABLE {S}.plain_t (note text);
CREATE VIEW {S}.iv_low WITH (security_invoker = true) AS SELECT * FROM {S}.plain_t;
CREATE VIEW {S}.iv_top WITH (security_invoker = true) AS SELECT * FROM {S}.iv_low;
GRANT SELECT ON {S}.iv_top TO {ROLE};
-- @undo
DROP VIEW {S}.iv_top; DROP VIEW {S}.iv_low; DROP TABLE {S}.plain_t;

-- @attack an invoker view over a definer view of a table that is not tenant data
-- @check -: strict: only tenant data readable
-- @mode strict
-- @min 15
-- @leak SELECT string_agg(note, ',') FROM {S}.iv_def
-- @setup
CREATE TABLE {S}.plain_t (note text); INSERT INTO {S}.plain_t VALUES ('b-secret');
CREATE VIEW {S}.def_v AS SELECT * FROM {S}.plain_t; GRANT SELECT ON {S}.def_v TO {ROLE};
CREATE VIEW {S}.iv_def WITH (security_invoker = true) AS SELECT * FROM {S}.def_v;
GRANT SELECT ON {S}.iv_def TO {ROLE};
-- @undo
DROP VIEW {S}.iv_def; DROP VIEW {S}.def_v; DROP TABLE {S}.plain_t;

-- @attack an invoker view over a system catalog
-- @check -: strict: only tenant data readable
-- @mode strict
-- @min 15
-- @setup
CREATE VIEW {S}.cat_v WITH (security_invoker = true) AS SELECT relname FROM pg_catalog.pg_class;
GRANT SELECT ON {S}.cat_v TO {ROLE};
-- @undo
DROP VIEW {S}.cat_v;

-- @attack an invoker view over an information_schema view (a system relation with a recorded dependency)
-- @check -: strict: only tenant data readable
-- @mode strict
-- @min 15
-- @setup
CREATE VIEW {S}.is_v WITH (security_invoker = true) AS SELECT table_name FROM information_schema.tables;
GRANT SELECT ON {S}.is_v TO {ROLE};
-- @undo
DROP VIEW {S}.is_v;

-- @attack a readable standalone sequence
-- @check -: strict: only tenant data readable
-- @mode strict
-- @setup
CREATE SEQUENCE {S}.counter; GRANT USAGE ON SEQUENCE {S}.counter TO {ROLE};
-- @undo
DROP SEQUENCE {S}.counter;

-- @attack a readable sequence owned by a table that is not tenant data
-- @check -: strict: only tenant data readable
-- @mode strict
-- @setup
CREATE TABLE {S}.log_t (id serial, note text); GRANT USAGE ON SEQUENCE {S}.log_t_id_seq TO {ROLE};
-- @undo
DROP TABLE {S}.log_t;

-- @attack an invoker view of constants
-- @check -: strict: only tenant data readable
-- @mode strict
-- @min 15
-- @leak SELECT string_agg(column2, ',') FROM {S}.consts
-- @setup
CREATE VIEW {S}.consts WITH (security_invoker = true) AS VALUES ('B', 'b-secret');
GRANT SELECT ON {S}.consts TO {ROLE};
-- @undo
DROP VIEW {S}.consts;

-- @attack an invoker view that calls a function
-- @check -: strict: only tenant data readable
-- @mode strict
-- @min 15
-- @leak SELECT k FROM {S}.fv LIMIT 1
-- @setup
CREATE FUNCTION {S}.k() RETURNS text LANGUAGE sql AS $f$ SELECT 'b-secret'::text $f$;
CREATE VIEW {S}.fv WITH (security_invoker = true) AS SELECT {S}.k() AS k, d.* FROM {S}.docs d;
GRANT SELECT ON {S}.fv TO {ROLE};
-- @undo
DROP VIEW {S}.fv; DROP FUNCTION {S}.k();

-- @attack a readable table without the tenant column
-- @check -: strict: only tenant data readable
-- @mode strict
-- @leak SELECT string_agg(note, ',') FROM {S}.history
-- @setup
CREATE TABLE {S}.history (note text); INSERT INTO {S}.history VALUES ('b-secret');
GRANT SELECT ON {S}.history TO {ROLE};
-- @undo
DROP TABLE {S}.history;

-- ---------------------------------------------------------------- rules
-- @attack a rule on a protected table reads a table the app cannot
-- @check -: no RLS-bypassing views or functions
-- @leak INSERT INTO {S}.docs (tenant_id, body) VALUES ('A', 'x')
-- @setup
CREATE TABLE {S}.audit (who text); INSERT INTO {S}.audit VALUES ('b-secret');
CREATE RULE leak AS ON INSERT TO {S}.docs DO ALSO SELECT who FROM {S}.audit;
-- @undo
DROP RULE leak ON {S}.docs; DROP TABLE {S}.audit;

-- @attack a rule on a table the app writes through a column grant
-- @check -: no RLS-bypassing views or functions
-- @leak INSERT INTO {S}.notes (body) VALUES ('x')
-- @setup
CREATE TABLE {S}.audit (who text); INSERT INTO {S}.audit VALUES ('b-secret');
CREATE TABLE {S}.notes (body text); GRANT INSERT (body) ON {S}.notes TO {ROLE};
CREATE RULE leak AS ON INSERT TO {S}.notes DO ALSO SELECT who FROM {S}.audit;
-- @undo
DROP TABLE {S}.notes, {S}.audit;

-- @attack a rule on a table reached through an INSERT-only view
-- @check -: no RLS-bypassing views or functions
-- @leak INSERT INTO {S}.notes_w VALUES ('x')
-- @setup
CREATE TABLE {S}.audit (who text); INSERT INTO {S}.audit VALUES ('b-secret');
CREATE TABLE {S}.notes (body text); CREATE VIEW {S}.notes_w AS SELECT body FROM {S}.notes;
GRANT INSERT ON {S}.notes_w TO {ROLE};
CREATE RULE leak AS ON INSERT TO {S}.notes DO ALSO SELECT who FROM {S}.audit;
-- @undo
DROP VIEW {S}.notes_w; DROP TABLE {S}.notes, {S}.audit;

-- @attack --allow-global cannot clear a rule
-- @check -: no RLS-bypassing views or functions
-- @mode strict
-- @args --allow-global {S}.*
-- @leak INSERT INTO {S}.docs (tenant_id, body) VALUES ('A', 'x')
-- @setup
CREATE TABLE {S}.audit (who text); INSERT INTO {S}.audit VALUES ('b-secret');
CREATE RULE leak AS ON INSERT TO {S}.docs DO ALSO SELECT who FROM {S}.audit;
-- @undo
DROP RULE leak ON {S}.docs; DROP TABLE {S}.audit;

-- ---------------------------------------------------------------- functions that run as their owner
-- @attack a SECURITY DEFINER function
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.all_docs()
-- @setup
CREATE FUNCTION {S}.all_docs() RETURNS SETOF {S}.docs LANGUAGE sql SECURITY DEFINER AS 'SELECT * FROM {S}.docs';
GRANT EXECUTE ON FUNCTION {S}.all_docs() TO {ROLE};
-- @undo
DROP FUNCTION {S}.all_docs();

-- @attack a SECURITY DEFINER function in another schema
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}_other.dump()
-- @setup
CREATE SCHEMA {S}_other; GRANT USAGE ON SCHEMA {S}_other TO {ROLE};
CREATE FUNCTION {S}_other.dump() RETURNS SETOF {S}.docs LANGUAGE sql SECURITY DEFINER AS 'SELECT * FROM {S}.docs';
-- @undo
DROP SCHEMA {S}_other CASCADE;

-- @attack a SECURITY DEFINER function attached to an extension
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT string_agg(body, ',') FROM {S}.export_docs()
-- @setup
CREATE FUNCTION {S}.export_docs() RETURNS SETOF {S}.docs LANGUAGE sql SECURITY DEFINER AS 'SELECT * FROM {S}.docs';
ALTER EXTENSION plpgsql ADD FUNCTION {S}.export_docs();
-- @undo
ALTER EXTENSION plpgsql DROP FUNCTION {S}.export_docs(); DROP FUNCTION {S}.export_docs();

-- @attack a SECURITY DEFINER function with the name of an allowlisted table
-- @check -: no RLS-bypassing views or functions
-- @mode strict
-- @args --allow-global {S}.countries
-- @leak SELECT {S}.countries('B')
-- @setup
CREATE TABLE {S}.countries (c text); GRANT SELECT ON {S}.countries TO {ROLE};
CREATE FUNCTION {S}.countries(t text) RETURNS text LANGUAGE sql SECURITY DEFINER
    AS 'SELECT string_agg(body, '','') FROM {S}.docs WHERE tenant_id = t';
-- @undo
DROP FUNCTION {S}.countries(text); DROP TABLE {S}.countries;

-- @attack a SECURITY DEFINER trigger function with EXECUTE revoked
-- @check -: no RLS-bypassing views or functions
-- @leak INSERT INTO {S}.docs (tenant_id, body) VALUES ('A', 'x')
-- @setup
CREATE FUNCTION {S}.tg() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $f$
BEGIN RAISE NOTICE '%', (SELECT string_agg(body, ',') FROM {S}.docs); RETURN NEW; END $f$;
REVOKE EXECUTE ON FUNCTION {S}.tg() FROM PUBLIC;
CREATE TRIGGER tg AFTER INSERT ON {S}.docs FOR EACH ROW EXECUTE FUNCTION {S}.tg();
-- @undo
DROP TRIGGER tg ON {S}.docs; DROP FUNCTION {S}.tg();

-- @attack a SECURITY DEFINER trigger function with EXECUTE revoked, in strict mode
-- @check -: strict: no SECURITY DEFINER functions
-- @mode strict
-- @setup
CREATE FUNCTION {S}.tg() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $f$ BEGIN RETURN NEW; END $f$;
REVOKE EXECUTE ON FUNCTION {S}.tg() FROM PUBLIC;
CREATE TRIGGER tg AFTER INSERT ON {S}.docs FOR EACH ROW EXECUTE FUNCTION {S}.tg();
-- @undo
DROP TRIGGER tg ON {S}.docs; DROP FUNCTION {S}.tg();

-- @attack a SECURITY DEFINER event trigger function fires on the app's temp-table DDL
-- @check -: no RLS-bypassing views or functions
-- @leak CREATE TEMP TABLE t_evt (x int)
-- @setup
CREATE FUNCTION {S}.evt() RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER AS $f$
BEGIN RAISE NOTICE '%', (SELECT string_agg(body, ',') FROM {S}.docs); END $f$;
REVOKE EXECUTE ON FUNCTION {S}.evt() FROM PUBLIC;
CREATE EVENT TRIGGER {ROLE}_evt ON ddl_command_end EXECUTE FUNCTION {S}.evt();
-- @undo
DROP EVENT TRIGGER {ROLE}_evt; DROP FUNCTION {S}.evt();

-- @attack an aggregate over a SECURITY DEFINER function with EXECUTE revoked
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT {S}.agg('q')
-- @setup
CREATE FUNCTION {S}.sfunc(text, text) RETURNS text LANGUAGE sql SECURITY DEFINER
    AS 'SELECT string_agg(body, '','') FROM {S}.docs';
REVOKE EXECUTE ON FUNCTION {S}.sfunc(text, text) FROM PUBLIC;
CREATE AGGREGATE {S}.agg(text) (SFUNC = {S}.sfunc, STYPE = text);
-- @undo
DROP AGGREGATE {S}.agg(text); DROP FUNCTION {S}.sfunc(text, text);

-- @attack a range type's subtype_diff is a SECURITY DEFINER function with EXECUTE revoked
-- @check -: no RLS-bypassing views or functions
-- @leak INSERT INTO {S}.spans VALUES ('[1500,1502)')
-- @setup
CREATE FUNCTION {S}.diff(float8, float8) RETURNS float8 LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER AS $f$
BEGIN RAISE NOTICE '%', (SELECT string_agg(body, ',') FROM {S}.docs); RETURN $1 - $2; END $f$;
REVOKE EXECUTE ON FUNCTION {S}.diff(float8, float8) FROM PUBLIC;
CREATE TYPE {S}.fr AS RANGE (subtype = float8, subtype_diff = {S}.diff);
CREATE TABLE {S}.spans (r {S}.fr); CREATE INDEX ON {S}.spans USING gist (r);
SET client_min_messages = warning;
INSERT INTO {S}.spans SELECT {S}.fr(g, g + 1) FROM generate_series(1, 2000) g;
GRANT INSERT ON {S}.spans TO {ROLE};
-- @undo
DROP TABLE {S}.spans; DROP TYPE {S}.fr; DROP FUNCTION {S}.diff(float8, float8);

-- @attack an operator class "=" that is a SECURITY DEFINER function, reached through array equality
-- @check -: no RLS-bypassing views or functions
-- @leak SELECT ARRAY['1'::{S}.myint] = ARRAY['1'::{S}.myint]
-- @setup
CREATE TYPE {S}.myint;
CREATE FUNCTION {S}.myin(cstring) RETURNS {S}.myint LANGUAGE internal IMMUTABLE STRICT AS 'int4in';
CREATE FUNCTION {S}.myout({S}.myint) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT AS 'int4out';
CREATE TYPE {S}.myint (INPUT = {S}.myin, OUTPUT = {S}.myout, LIKE = int4);
CREATE FUNCTION {S}.mylt({S}.myint, {S}.myint) RETURNS bool LANGUAGE internal IMMUTABLE STRICT AS 'int4lt';
CREATE FUNCTION {S}.mycmp({S}.myint, {S}.myint) RETURNS int LANGUAGE internal IMMUTABLE STRICT AS 'btint4cmp';
CREATE FUNCTION {S}.myeq({S}.myint, {S}.myint) RETURNS bool LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER AS $f$
BEGIN RAISE NOTICE '%', (SELECT string_agg(body, ',') FROM {S}.docs); RETURN $1::text = $2::text; END $f$;
REVOKE EXECUTE ON FUNCTION {S}.myeq({S}.myint, {S}.myint) FROM PUBLIC;
CREATE OPERATOR {S}.< (LEFTARG = {S}.myint, RIGHTARG = {S}.myint, FUNCTION = {S}.mylt);
CREATE OPERATOR {S}.= (LEFTARG = {S}.myint, RIGHTARG = {S}.myint, FUNCTION = {S}.myeq, MERGES);
CREATE OPERATOR CLASS {S}.myint_ops DEFAULT FOR TYPE {S}.myint USING btree AS
    OPERATOR 1 {S}.<, OPERATOR 3 {S}.=, FUNCTION 1 {S}.mycmp({S}.myint, {S}.myint);
-- @undo
DROP OPERATOR FAMILY {S}.myint_ops USING btree CASCADE; DROP TYPE {S}.myint CASCADE;

-- @attack a SECURITY DEFINER btree comparison function with EXECUTE revoked (index support)
-- @check -: no RLS-bypassing views or functions
-- @setup
CREATE TYPE {S}.myint2;
CREATE FUNCTION {S}.myin2(cstring) RETURNS {S}.myint2 LANGUAGE internal IMMUTABLE STRICT AS 'int4in';
CREATE FUNCTION {S}.myout2({S}.myint2) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT AS 'int4out';
CREATE TYPE {S}.myint2 (INPUT = {S}.myin2, OUTPUT = {S}.myout2, LIKE = int4);
CREATE FUNCTION {S}.mylt2({S}.myint2, {S}.myint2) RETURNS bool LANGUAGE internal IMMUTABLE STRICT AS 'int4lt';
CREATE FUNCTION {S}.myeq2({S}.myint2, {S}.myint2) RETURNS bool LANGUAGE internal IMMUTABLE STRICT AS 'int4eq';
CREATE FUNCTION {S}.mycmp2({S}.myint2, {S}.myint2) RETURNS int LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER AS $f$
BEGIN RETURN btint4cmp($1::text::int, $2::text::int); END $f$;
REVOKE EXECUTE ON FUNCTION {S}.mycmp2({S}.myint2, {S}.myint2) FROM PUBLIC;
CREATE OPERATOR {S}.< (LEFTARG = {S}.myint2, RIGHTARG = {S}.myint2, FUNCTION = {S}.mylt2);
CREATE OPERATOR {S}.= (LEFTARG = {S}.myint2, RIGHTARG = {S}.myint2, FUNCTION = {S}.myeq2);
CREATE OPERATOR CLASS {S}.myint2_ops DEFAULT FOR TYPE {S}.myint2 USING btree AS
    OPERATOR 1 {S}.<, OPERATOR 3 {S}.=, FUNCTION 1 {S}.mycmp2({S}.myint2, {S}.myint2);
-- @undo
DROP OPERATOR FAMILY {S}.myint2_ops USING btree CASCADE; DROP TYPE {S}.myint2 CASCADE;

-- @attack a type whose input function is SECURITY DEFINER with EXECUTE revoked (type I/O)
-- @check -: no RLS-bypassing views or functions
-- @setup
CREATE TYPE {S}.myint3;
CREATE FUNCTION {S}.myin3(cstring) RETURNS {S}.myint3 LANGUAGE internal IMMUTABLE STRICT SECURITY DEFINER AS 'int4in';
CREATE FUNCTION {S}.myout3({S}.myint3) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT AS 'int4out';
CREATE TYPE {S}.myint3 (INPUT = {S}.myin3, OUTPUT = {S}.myout3, LIKE = int4);
REVOKE EXECUTE ON FUNCTION {S}.myin3(cstring) FROM PUBLIC;
-- @undo
DROP TYPE {S}.myint3 CASCADE;

-- @attack an operator whose selectivity estimator is SECURITY DEFINER with EXECUTE revoked
-- @check -: no RLS-bypassing views or functions
-- @setup
CREATE FUNCTION {S}.sel(internal, oid, internal, integer) RETURNS float8 LANGUAGE internal STABLE STRICT SECURITY DEFINER AS 'eqsel';
REVOKE EXECUTE ON FUNCTION {S}.sel(internal, oid, internal, integer) FROM PUBLIC;
CREATE FUNCTION {S}.same(text, text) RETURNS bool LANGUAGE sql IMMUTABLE AS 'SELECT $1 = $2';
CREATE OPERATOR {S}.=== (LEFTARG = text, RIGHTARG = text, FUNCTION = {S}.same, RESTRICT = {S}.sel);
-- @undo
DROP OPERATOR {S}.=== (text, text); DROP FUNCTION {S}.same(text, text); DROP FUNCTION {S}.sel(internal, oid, internal, integer);

-- @attack a planner support function that is SECURITY DEFINER with EXECUTE revoked
-- @check -: no RLS-bypassing views or functions
-- @setup
CREATE FUNCTION {S}.supp(internal) RETURNS internal LANGUAGE internal STABLE STRICT SECURITY DEFINER AS 'textlike_support';
REVOKE EXECUTE ON FUNCTION {S}.supp(internal) FROM PUBLIC;
CREATE FUNCTION {S}.likeish(text, text) RETURNS bool LANGUAGE internal IMMUTABLE STRICT SUPPORT {S}.supp AS 'textlike';
-- @undo
DROP FUNCTION {S}.likeish(text, text); DROP FUNCTION {S}.supp(internal);

-- @attack a text search parser function that is SECURITY DEFINER with EXECUTE revoked
-- @check -: no RLS-bypassing views or functions
-- @setup
CREATE FUNCTION {S}.prs_start(internal, integer) RETURNS internal LANGUAGE internal STRICT SECURITY DEFINER AS 'prsd_start';
REVOKE EXECUTE ON FUNCTION {S}.prs_start(internal, integer) FROM PUBLIC;
CREATE TEXT SEARCH PARSER {S}.prs (START = {S}.prs_start, GETTOKEN = prsd_nexttoken, END = prsd_end,
                                   LEXTYPES = prsd_lextype, HEADLINE = prsd_headline);
-- @undo
DROP TEXT SEARCH PARSER {S}.prs; DROP FUNCTION {S}.prs_start(internal, integer);

-- @attack a foreign-data wrapper validator that is a SECURITY DEFINER function
-- @check -: no RLS-bypassing views or functions
-- @leak CREATE USER MAPPING FOR CURRENT_USER SERVER {ROLE}_ws OPTIONS (a 'b')
-- @setup
CREATE FUNCTION {S}.val(text[], oid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $f$
BEGIN RAISE NOTICE '%', (SELECT string_agg(body, ',') FROM {S}.docs); END $f$;
REVOKE EXECUTE ON FUNCTION {S}.val(text[], oid) FROM PUBLIC;
CREATE FOREIGN DATA WRAPPER {ROLE}_w VALIDATOR {S}.val;
CREATE SERVER {ROLE}_ws FOREIGN DATA WRAPPER {ROLE}_w; GRANT USAGE ON FOREIGN SERVER {ROLE}_ws TO {ROLE};
-- @undo
DROP SERVER {ROLE}_ws CASCADE; DROP FOREIGN DATA WRAPPER {ROLE}_w; DROP FUNCTION {S}.val(text[], oid);

-- @attack a language validator that is a SECURITY DEFINER function
-- @check -: no RLS-bypassing views or functions
-- @leak CREATE FUNCTION pg_temp.t() RETURNS int LANGUAGE {ROLE}_lang AS 'BEGIN RETURN 1; END'
-- @setup
CREATE FUNCTION {S}.lval(oid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $f$
BEGIN RAISE NOTICE '%', (SELECT string_agg(body, ',') FROM {S}.docs); END $f$;
REVOKE EXECUTE ON FUNCTION {S}.lval(oid) FROM PUBLIC;
CREATE TRUSTED LANGUAGE {ROLE}_lang HANDLER plpgsql_call_handler VALIDATOR {S}.lval;
-- @undo
DROP LANGUAGE {ROLE}_lang; DROP FUNCTION {S}.lval(oid);

-- @attack a LEAKPROOF function outside pg_catalog
-- @check -: no RLS-bypassing views or functions
-- @setup
CREATE FUNCTION {S}.peek(text) RETURNS boolean LANGUAGE sql LEAKPROOF AS 'SELECT true';
-- @undo
DROP FUNCTION {S}.peek(text);

-- @attack a SECURITY DEFINER function the app cannot execute (strict counts every one)
-- @check -: strict: no SECURITY DEFINER functions
-- @mode strict
-- @setup
CREATE FUNCTION {S}.admin_only() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';
REVOKE EXECUTE ON FUNCTION {S}.admin_only() FROM PUBLIC;
-- @undo
DROP FUNCTION {S}.admin_only();

-- ---------------------------------------------------------------- stores shared by all tenants
-- @attack a foreign table
-- @check -: no RLS-bypassing views or functions
-- @setup
CREATE FOREIGN DATA WRAPPER {ROLE}_fdw; CREATE SERVER {ROLE}_srv FOREIGN DATA WRAPPER {ROLE}_fdw;
CREATE FOREIGN TABLE {S}.docs_remote (id int, tenant_id text) SERVER {ROLE}_srv;
GRANT SELECT ON {S}.docs_remote TO {ROLE};
-- @undo
DROP FOREIGN TABLE {S}.docs_remote; DROP SERVER {ROLE}_srv; DROP FOREIGN DATA WRAPPER {ROLE}_fdw;

-- @attack a readable large object
-- @check -: strict: no readable large objects
-- @mode strict
-- @leak SELECT convert_from(lo_get(424242), 'UTF8')
-- @setup
SELECT lo_from_bytea(424242, convert_to('b-secret', 'UTF8')); ALTER LARGE OBJECT 424242 OWNER TO {ROLE};
-- @undo
SELECT lo_unlink(424242);

-- @attack --allow-global cannot clear a foreign table with the tenant column
-- @check -: no RLS-bypassing views or functions
-- @mode strict
-- @args --allow-global {S}.docs_remote
-- @setup
CREATE FOREIGN DATA WRAPPER {ROLE}_fdw; CREATE SERVER {ROLE}_srv FOREIGN DATA WRAPPER {ROLE}_fdw;
CREATE FOREIGN TABLE {S}.docs_remote (id int, tenant_id text) SERVER {ROLE}_srv;
GRANT SELECT ON {S}.docs_remote TO {ROLE};
-- @undo
DROP FOREIGN TABLE {S}.docs_remote; DROP SERVER {ROLE}_srv; DROP FOREIGN DATA WRAPPER {ROLE}_fdw;

-- @attack a large object granted to the app (not owned)
-- @check -: strict: no readable large objects
-- @mode strict
-- @leak SELECT convert_from(lo_get(424243), 'UTF8')
-- @setup
SELECT lo_from_bytea(424243, convert_to('b-secret', 'UTF8')); GRANT SELECT ON LARGE OBJECT 424243 TO {ROLE};
-- @undo
SELECT lo_unlink(424243);

-- @attack lo_compat_privileges makes every large object readable
-- @check -: strict: no readable large objects
-- @mode strict
-- @leak SELECT convert_from(lo_get(424244), 'UTF8')
-- @setup
SELECT lo_from_bytea(424244, convert_to('b-secret', 'UTF8')); ALTER DATABASE {DB} SET lo_compat_privileges = on;
-- @undo
ALTER DATABASE {DB} RESET lo_compat_privileges; SELECT lo_unlink(424244);

-- @attack other sessions' SQL in pg_stat_activity
-- @check -: strict: cannot read other sessions' SQL
-- @mode strict
-- @setup
GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC;
-- @undo
REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC;

-- @attack other sessions' SQL through pg_stat_get_activity
-- @check -: strict: cannot read other sessions' SQL
-- @mode strict
-- @setup
GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) TO PUBLIC;
-- @undo
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) FROM PUBLIC;

-- @attack other sessions' SQL in pg_stat_statements
-- @check -: strict: cannot read other sessions' SQL
-- @mode strict
-- @setup
CREATE EXTENSION pg_stat_statements SCHEMA public;
-- @undo
DROP EXTENSION pg_stat_statements;

-- @attack other sessions' SQL through the pg_stat_statements function (its views revoked)
-- @check -: strict: cannot read other sessions' SQL
-- @mode strict
-- @setup
CREATE EXTENSION pg_stat_statements SCHEMA public;
REVOKE SELECT ON public.pg_stat_statements, public.pg_stat_statements_info FROM PUBLIC;
-- @undo
DROP EXTENSION pg_stat_statements;

-- @attack --allow-query-text does not clear a table named like pg_stat_statements
-- @check -: strict: only tenant data readable
-- @mode strict
-- @args --allow-query-text
-- @setup
CREATE TABLE {S}."x.pg_stat_statements" (note text); GRANT SELECT ON {S}."x.pg_stat_statements" TO {ROLE};
-- @undo
DROP TABLE {S}."x.pg_stat_statements";

-- ---------------------------------------------------------------- safe patterns
-- @pass a security_invoker view over a protected table
-- @min 15
-- @setup
CREATE VIEW {S}.vi_docs WITH (security_invoker = true) AS SELECT * FROM {S}.docs;
GRANT SELECT ON {S}.vi_docs TO {ROLE};
-- @undo
DROP VIEW {S}.vi_docs;

-- @pass security_invoker spelled 1
-- @min 15
-- @setup
CREATE VIEW {S}.vi1 WITH (security_invoker = 1) AS SELECT * FROM {S}.docs; GRANT SELECT ON {S}.vi1 TO {ROLE};
-- @undo
DROP VIEW {S}.vi1;

-- @pass a security_invoker view over a protected table, in strict mode
-- @mode strict
-- @min 15
-- @setup
CREATE VIEW {S}.my_docs WITH (security_invoker = true) AS SELECT * FROM {S}.docs;
GRANT SELECT ON {S}.my_docs TO {ROLE};
-- @undo
DROP VIEW {S}.my_docs;

-- @pass an invoker trigger function
-- @setup
CREATE FUNCTION {S}.stamp() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$;
CREATE TRIGGER stamp BEFORE INSERT ON {S}.docs FOR EACH ROW EXECUTE FUNCTION {S}.stamp();
-- @undo
DROP TRIGGER stamp ON {S}.docs; DROP FUNCTION {S}.stamp();

-- @pass common extensions, in strict mode
-- @mode strict
-- @setup
CREATE EXTENSION IF NOT EXISTS pgcrypto; CREATE EXTENSION IF NOT EXISTS citext; CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- @undo
DROP EXTENSION pgcrypto; DROP EXTENSION citext; DROP EXTENSION pg_trgm;

-- @pass --allow-query-text with pg_stat_statements installed
-- @mode strict
-- @args --allow-query-text
-- @setup
CREATE EXTENSION pg_stat_statements SCHEMA public;
-- @undo
DROP EXTENSION pg_stat_statements;
