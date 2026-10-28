-- Attacks on PostgreSQL tenant isolation, collected from the PR 13 to 15
-- reviews. `db-firewall verify` must fail each one with the named check.
-- Add every new bypass here before fixing it.
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
DROP TYPE {S}.myint CASCADE;

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

-- @attack other sessions' SQL in pg_stat_activity
-- @check -: strict: cannot read other sessions' SQL
-- @mode strict
-- @setup
GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC;
-- @undo
REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC;

-- @attack other sessions' SQL in pg_stat_statements
-- @check -: strict: cannot read other sessions' SQL
-- @mode strict
-- @setup
CREATE EXTENSION pg_stat_statements SCHEMA public;
-- @undo
DROP EXTENSION pg_stat_statements;

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
