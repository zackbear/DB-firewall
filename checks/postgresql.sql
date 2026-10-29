-- The PostgreSQL checks of `db-firewall scan` and `db-firewall verify`, in
-- one place: packages/cli (TypeScript) and hooks/ (Python) both run these
-- queries, so the two tools find the same things. Change a check here, not in
-- either tool.
--
-- Format, read by both tools:
--   -- @excluded <glob> ...   the tables the migration skips (and so the scan)
--   -- @check <name>         a global verify check: one row (ok boolean, detail
--                            text). A query error fails it.
--   -- @info <name>          the same, but never fails: an information line
--   -- @query <name>         a query a tool runs itself, with its own logic
-- Each block runs to the next "-- @" line. Parameters are $1, $2, ... in the
-- order given. The tools run everything with search_path = pg_catalog,
-- pg_temp, so a planted operator in another schema cannot change a result.
--
-- "A role the app can use": the role itself, a role it inherits, or one it can
-- SET ROLE to (pg_has_role ... 'MEMBER'). The verify checks run as the app role.

-- @excluded _firewall_* schema_migrations alembic_version knex_migrations prisma_migrations __diesel_schema_migrations flyway_schema_history

-- ============================================================== scan
-- @query scan_tables
-- Every table in schema $1 with the tenant column $2, and its firewall
-- policies. Protected = RLS enabled AND forced AND all four firewall policies
-- AND their exact shape AND, when they are permissive, no other permissive
-- policy (PostgreSQL ORs permissive policies). ref_rel: the relation the
-- reference predicate is built on (a partition's root).
WITH t AS (
  SELECT c.oid, n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity,
         'fw_' || left(md5(n.nspname || '.' || c.relname), 12) AS stem,
         'firewall_rls_' || c.relname AS legacy
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p') AND n.nspname = $1
    AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = $2
                  AND a.attnum > 0 AND NOT a.attisdropped))
SELECT t.relname AS table, t.relrowsecurity AS enabled, t.relforcerowsecurity AS forced,
  pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid = t.oid)) AS owner,
  (CASE WHEN (SELECT relispartition FROM pg_class WHERE oid = t.oid) THEN pg_partition_root(t.oid)
        ELSE t.oid END)::regclass::text AS ref_rel,
  ARRAY(SELECT op FROM unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op
        WHERE NOT EXISTS (SELECT 1 FROM pg_policies p
                          WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                            AND p.policyname IN (t.stem || '_' || op, t.legacy || '_' || op))) AS missing,
  ARRAY(SELECT p.policyname::text FROM pg_policies p
        WHERE p.schemaname = t.nspname AND p.tablename = t.relname AND p.permissive = 'PERMISSIVE'
          AND p.policyname NOT IN (SELECT pre || '_' || op FROM unnest(ARRAY[t.stem, t.legacy]) AS pre,
                                   unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op)) AS extra,
  COALESCE((SELECT count(*) = 4 AND bool_and(p.permissive = 'RESTRICTIVE') FROM pg_policies p
            WHERE p.schemaname = t.nspname AND p.tablename = t.relname
              AND p.policyname IN (t.stem || '_sel', t.stem || '_ins',
                                   t.stem || '_upd', t.stem || '_del')), false) AS restrictive,
  COALESCE((SELECT json_agg(json_build_array(p.policyname, p.cmd, p.roles, p.qual, p.with_check))
            FROM pg_policies p
            WHERE p.schemaname = t.nspname AND p.tablename = t.relname
              AND p.policyname IN (SELECT pre || '_' || op FROM unnest(ARRAY[t.stem, t.legacy]) AS pre,
                                   unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op)), '[]') AS policies,
  EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = t.nspname AND p.tablename = t.relname
            AND p.policyname = t.stem || '_base') AS base
FROM t ORDER BY t.relname

-- @query reference_qual
-- The deparsed predicate of the policy on the temporary reference table.
SELECT qual FROM pg_policies WHERE tablename = '_fw_ref' AND policyname = '_fw_ref_p'
  AND schemaname = pg_my_temp_schema()::regnamespace::text

-- @query fw_function
-- One function the migration creates ($1: its regprocedure text), as it is now.
SELECT prosrc, prosecdef, proconfig, provolatile, l.lanname, format_type(prorettype, NULL) AS ret
FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE p.oid = to_regprocedure($1)

-- @query fw_extra
-- public._firewall_* functions the migration does not create ($1: its signatures).
SELECT p.oid::regprocedure::text AS fn FROM pg_proc p
WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE '#_firewall#_%' ESCAPE '#'
  AND NOT (p.proname || '(' || oidvectortypes(p.proargtypes) || ')') = ANY($1)
ORDER BY 1

-- @query fw_owners
-- The owners of the public._firewall_* objects: one, or only superusers.
SELECT pg_get_userbyid(o.owner) AS owner, r.rolsuper AS super, string_agg(o.name, ', ' ORDER BY o.name) AS objects
FROM (SELECT relname::text AS name, relowner AS owner FROM pg_class
      WHERE relnamespace = 'public'::regnamespace AND relname LIKE '#_firewall#_%' ESCAPE '#'
      UNION ALL SELECT proname::text, proowner FROM pg_proc
      WHERE pronamespace = 'public'::regnamespace AND proname LIKE '#_firewall#_%' ESCAPE '#') o
JOIN pg_roles r ON r.oid = o.owner
GROUP BY o.owner, r.rolsuper ORDER BY count(*) DESC

-- ============================================================== verify: the role
-- @check role
-- RLS must apply to every role the app can use: none is a superuser, has
-- BYPASSRLS or is in _firewall_bypass_roles, or is a member of a predefined
-- role that reads every row (pg_read_all_data, pg_write_all_data) or runs
-- programs or reads and writes files as the server.
WITH bad AS (
  SELECT CASE WHEN r.rolname = current_user THEN 'role ' || r.rolname ELSE 'is a member of ' || r.rolname || ', which' END
         || CASE WHEN r.rolsuper THEN ' is a superuser' WHEN r.rolbypassrls THEN ' has BYPASSRLS'
                 ELSE ' is in _firewall_bypass_roles' END AS item, 0 AS o, r.rolname
  FROM pg_roles r WHERE pg_has_role(current_user, r.oid, 'MEMBER')
    AND (r.rolsuper OR r.rolbypassrls OR public._firewall_is_bypass_role(r.rolname::text))
  UNION ALL
  SELECT 'is a member of ' || rolname || ', which reads or runs things as the server', 1, rolname FROM pg_roles
  WHERE rolname IN ('pg_read_all_data', 'pg_write_all_data', 'pg_execute_server_program',
                    'pg_read_server_files', 'pg_write_server_files')
    AND pg_has_role(current_user, oid, 'MEMBER'))
SELECT count(*) = 0 AS ok,
       COALESCE(string_agg(item, '; ' ORDER BY o, rolname) || ': RLS does not apply', 'no role it can use skips RLS') AS detail
FROM bad

-- @check cannot write firewall tables
-- The app could add itself as a bypass role, map itself to a tenant, or take
-- a schema out of the DDL guard.
WITH bad AS (
  SELECT t AS name FROM unnest(ARRAY['public._firewall_bypass_roles', 'public._firewall_tenant_map',
                                     'public._firewall_protected_schemas']) t
  WHERE to_regclass(t) IS NOT NULL
    AND EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                  AND (has_any_column_privilege(m.oid, t, 'INSERT') OR has_any_column_privilege(m.oid, t, 'UPDATE')
                       OR has_table_privilege(m.oid, t, 'DELETE, TRUNCATE'))))
SELECT count(*) = 0 AS ok,
       COALESCE('can write ' || string_agg(name, ', ' ORDER BY name) || ' (could add itself as a bypass role)',
                'no write access') AS detail
FROM bad

-- @check cannot read the key or sign
-- With the key, or a way to sign, the app could sign any tenant.
WITH bad AS (
  SELECT 'table _firewall_keys' AS name WHERE to_regclass('public._firewall_keys') IS NOT NULL
    AND EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                  AND has_any_column_privilege(m.oid, 'public._firewall_keys'::regclass, 'SELECT'))
  UNION ALL SELECT 'function ' || p.proname FROM pg_proc p
  WHERE p.pronamespace = 'public'::regnamespace AND p.proname IN ('_firewall_sign', '_firewall_set_tenant')
    AND EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                  AND has_function_privilege(m.oid, p.oid, 'EXECUTE')))
SELECT count(*) = 0 AS ok,
       COALESCE('can use ' || string_agg(name, ', ' ORDER BY name) || ' (could sign another tenant): re-run migrate',
                'neither') AS detail
FROM bad

-- @check does not own firewall objects
-- The owner of schema public (on PostgreSQL 15 and later the database owner,
-- through pg_database_owner) can drop the bypass list and create its own; an
-- owner of a firewall object can replace it.
WITH bad AS (
  SELECT 'schema public' AS name FROM pg_namespace WHERE nspname = 'public' AND pg_has_role(current_user, nspowner, 'MEMBER')
  UNION ALL SELECT 'table ' || relname FROM pg_class WHERE relnamespace = 'public'::regnamespace
    AND relname LIKE '#_firewall#_%' ESCAPE '#' AND pg_has_role(current_user, relowner, 'MEMBER')
  UNION ALL SELECT 'function ' || proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace
    AND proname LIKE '#_firewall#_%' ESCAPE '#' AND pg_has_role(current_user, proowner, 'MEMBER'))
SELECT count(*) = 0 AS ok,
       COALESCE('can act as the owner of ' || string_agg(name, ', ' ORDER BY name)
                || ' (could drop or replace the bypass list)', 'owns none') AS detail
FROM bad

-- @check owns no database objects
-- An owner can change what runs in other tenants' sessions: a domain
-- constraint or a function body that sends values out (pg_notify), a table's
-- RLS, its own grants back. Any object in the database counts (pg_shdepend),
-- except temporary ones, large objects, default ACLs and user mappings (the
-- mapped role counts as their owner).
WITH bad AS (
  SELECT 'database ' || datname AS name FROM pg_database
  WHERE datname = current_database() AND pg_has_role(current_user, datdba, 'MEMBER')
  UNION ALL (SELECT o.type || ' ' || o.identity FROM pg_shdepend s
    CROSS JOIN LATERAL pg_identify_object(s.classid, s.objid, 0) o
    WHERE s.dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) AND s.deptype = 'o'
      AND s.classid NOT IN ('pg_largeobject'::regclass, 'pg_default_acl'::regclass, 'pg_user_mapping'::regclass)
      AND pg_has_role(current_user, s.refobjid, 'MEMBER')
      AND COALESCE(o.schema, '') NOT LIKE 'pg#_temp#_%' ESCAPE '#'
      AND COALESCE(o.schema, '') NOT LIKE 'pg#_toast#_temp#_%' ESCAPE '#'
    ORDER BY 1 LIMIT 20))
SELECT count(*) = 0 AS ok,
       COALESCE('a role it can use owns ' || string_agg(name, ', ' ORDER BY name)
                || ': give them to another role (run migrations as it)', 'owns none') AS detail
FROM bad

-- @info signals other sessions (info)
-- What one shared role allows that no tenant check can see.
SELECT true AS ok,
       CASE WHEN EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                           AND EXISTS (SELECT 1 FROM pg_proc p WHERE p.pronamespace = 'pg_catalog'::regnamespace
                                         AND p.proname IN ('pg_terminate_backend', 'pg_cancel_backend')
                                         AND has_function_privilege(m.oid, p.oid, 'EXECUTE')))
            THEN 'yes: SQL one tenant runs can end or cancel another tenant''s requests (availability only); '
                 || 'migrate --harden-signals revokes it'
            ELSE 'no (pg_terminate_backend / pg_cancel_backend revoked)' END AS detail

-- @info role defaults (info)
SELECT true AS ok,
       COALESCE('set: ' || string_agg(ro.rolname || COALESCE(' in ' || d.datname, '') || ': '
                                      || array_to_string(s.setconfig, ', '), '; ' ORDER BY ro.rolname), 'none')
       || ' (the role can change its own with ALTER ROLE CURRENT_USER SET; no grant prevents it, '
       || 'and a bad value can break its later connections)' AS detail
FROM pg_db_role_setting s JOIN pg_roles ro ON ro.oid = s.setrole
LEFT JOIN pg_database d ON d.oid = s.setdatabase
WHERE pg_has_role(current_user, s.setrole, 'MEMBER') AND (s.setdatabase = 0 OR d.datname = current_database())

-- @info DDL guard (info)
-- migrate --ddl-guard: two event triggers protect a new table at once and
-- refuse a change that weakens a protected one.
SELECT true AS ok,
       CASE WHEN (SELECT count(*) FROM pg_event_trigger
                  WHERE evtname IN ('_firewall_ddl_guard', '_firewall_ddl_drop_guard') AND evtenabled <> 'D') = 2
            THEN 'on: a new table with the tenant column is protected at once, and a change that weakens a '
                 || 'protected table fails, for every role but a superuser and the migration''s'
            ELSE 'off (migrate --ddl-guard installs it: a new table is then protected at once, not at the next '
                 || 'migration run)' END AS detail

-- @check cannot create triggers
-- TRIGGER on a table lets the app attach a deferred trigger: it fires at
-- COMMIT and can leave state for the connection's next user.
WITH bad AS (
  SELECT c.oid::regclass::text AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND n.nspname NOT LIKE 'pg#_toast%' ESCAPE '#' AND n.nspname NOT LIKE 'pg#_temp#_%' ESCAPE '#'
    AND (EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                   AND has_table_privilege(m.oid, c.oid, 'TRIGGER'))
         OR pg_has_role(current_user, c.relowner, 'MEMBER'))
  ORDER BY 1 LIMIT 20)
SELECT count(*) = 0 AS ok,
       COALESCE('TRIGGER is granted on, or a role it can use owns, ' || string_agg(name, ', ' ORDER BY name)
                || ': REVOKE TRIGGER ... FROM the app role, and give owned tables to another role',
                'no TRIGGER on any table') AS detail
FROM bad

-- @check cannot create in any schema
-- CREATE in a schema lets the app plant objects or operators that a later
-- query binds to, reached through a search_path it sets for itself (ALTER
-- ROLE ... SET persists, and no reset can undo it). CREATE on the database
-- makes new schemas, such as one named like the role: the default search_path
-- ("$user", public) looks there first. An owner can grant itself CREATE.
WITH db AS (
  SELECT EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                   AND has_database_privilege(m.oid, current_database(), 'CREATE')) AS create_db,
         pg_has_role(current_user, datdba, 'MEMBER') AS owns
  FROM pg_database WHERE datname = current_database()),
ns AS (
  SELECT n.nspname FROM pg_namespace n
  WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg#_toast%' ESCAPE '#'
    AND n.nspname NOT LIKE 'pg#_temp#_%' ESCAPE '#'
    AND (EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                   AND has_schema_privilege(m.oid, n.oid, 'CREATE'))
         OR pg_has_role(current_user, n.nspowner, 'MEMBER')))
SELECT NOT db.create_db AND NOT db.owns AND NOT EXISTS (SELECT 1 FROM ns) AS ok,
  CASE WHEN db.owns THEN 'a role it can use owns this database (an owner can grant itself CREATE)'
       WHEN db.create_db THEN 'a role it can use can CREATE schemas in this database '
                              || '(REVOKE CREATE ON DATABASE ... FROM PUBLIC and the app role)'
       WHEN EXISTS (SELECT 1 FROM ns) THEN 'a role it can use can CREATE in, or owns, '
            || (SELECT string_agg(nspname, ', ' ORDER BY nspname) FROM ns)
            || ': REVOKE CREATE ON SCHEMA ... FROM PUBLIC and the app role, and give owned schemas to another role '
            || '(run migrations as another role)'
       ELSE 'no CREATE in any schema' END AS detail
FROM db

-- ============================================================== verify: per table
-- @query table_privileges
-- For table $1 (regclass text) and the tenant column $2: privileges RLS does
-- not cover (the owner can turn RLS off; TRUNCATE ignores it), and who can
-- read the tenant column.
SELECT pg_has_role(current_user, c.relowner, 'MEMBER') AS owns,
       EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                 AND has_table_privilege(m.oid, c.oid, 'TRUNCATE')) AS truncate,
       has_column_privilege(current_user, c.oid, $2, 'SELECT') AS can_select,
       EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                 AND has_column_privilege(m.oid, c.oid, $2, 'SELECT')) AS some_role_selects
FROM pg_class c WHERE c.oid = $1::regclass

-- @query nonce
SELECT public._firewall_nonce() AS n

-- ============================================================== verify: read paths RLS does not guard
-- @query bypass_views
-- A view or materialized view the app can read whose chain down to a table
-- with the tenant column ($1) holds a materialized view (no RLS at all) or a
-- view that runs as an owner who skips RLS (not security_invoker); and a
-- materialized view with the tenant column or built over a function.
-- ponytail: any such view in the chain counts, even one shadowed by a lower
-- definer view of a non-bypassing owner (a false fail, never a false pass).
WITH RECURSIVE rel AS (
  SELECT v.oid, v.relkind = 'm' OR (NOT COALESCE((SELECT option_value::boolean FROM pg_options_to_table(v.reloptions)
                                                 WHERE option_name = 'security_invoker'), false)
                                    AND (r.rolsuper OR r.rolbypassrls OR public._firewall_is_bypass_role(r.rolname::text))) AS bad
  FROM pg_class v JOIN pg_roles r ON r.oid = v.relowner WHERE v.relkind IN ('v', 'm')),
dep AS (
  SELECT DISTINCT rw.ev_class AS v, d.refobjid AS t FROM pg_rewrite rw
  JOIN pg_depend d ON d.objid = rw.oid AND d.classid = 'pg_rewrite'::regclass
                  AND d.refclassid = 'pg_class'::regclass AND d.refobjid <> rw.ev_class),
chain(top, cur, bad) AS (
  SELECT d.v, d.t, rel.bad FROM dep d JOIN rel ON rel.oid = d.v
  UNION
  SELECT c.top, d.t, c.bad OR rel.bad FROM chain c JOIN dep d ON d.v = c.cur JOIN rel ON rel.oid = d.v)
SELECT DISTINCT n.nspname || '.' || v.relname AS name, v.relkind = 'm' AS matview,
       pg_get_userbyid(v.relowner) AS owner
FROM chain c JOIN pg_class v ON v.oid = c.top JOIN pg_namespace n ON n.oid = v.relnamespace
JOIN pg_class t ON t.oid = c.cur AND t.relkind IN ('r', 'p')
WHERE c.bad AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                AND has_any_column_privilege(m.oid, v.oid, 'SELECT'))
  AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = t.oid AND a.attname = $1
                AND a.attnum > 0 AND NOT a.attisdropped)
UNION
SELECT n.nspname || '.' || v.relname, true, pg_get_userbyid(v.relowner)
FROM pg_class v JOIN pg_namespace n ON n.oid = v.relnamespace
WHERE v.relkind = 'm' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                AND has_any_column_privilege(m.oid, v.oid, 'SELECT'))
  AND (EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = v.oid AND a.attname = $1
                 AND a.attnum > 0 AND NOT a.attisdropped)
       OR EXISTS (SELECT 1 FROM pg_rewrite rw JOIN pg_depend d ON d.objid = rw.oid
                    AND d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_proc'::regclass
                  JOIN pg_proc f ON f.oid = d.refobjid AND f.pronamespace <> 'pg_catalog'::regnamespace
                  WHERE rw.ev_class = v.oid))
ORDER BY 1

-- @query bypass_foreign
-- Foreign tables the app can read: RLS does not reach the remote data. tenant:
-- it has the tenant column ($1), so no allowlist entry clears it.
SELECT n.nspname || '.' || c.relname AS name,
       EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = $1
                 AND a.attnum > 0 AND NOT a.attisdropped) AS tenant
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'f' AND EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                                    AND has_any_column_privilege(m.oid, c.oid, 'SELECT'))
ORDER BY 1

-- @query bypass_rules
-- A rule's actions run with the table owner's privileges and can read (or
-- copy) what the app cannot. Any rule counts: a write reaches a table through
-- a view, a column grant or a cascade. Use a trigger instead.
SELECT rw.rulename || ' on ' || c.oid::regclass::text AS name FROM pg_rewrite rw JOIN pg_class c ON c.oid = rw.ev_class
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE rw.rulename <> '_RETURN' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY 1

-- @query bypass_functions
-- A SECURITY DEFINER function owned by a role that skips RLS, which the app
-- can execute or which PostgreSQL runs without checking EXECUTE: trigger and
-- event trigger functions, aggregate and range support, index support (amproc,
-- and the operators of operator families), selectivity estimators, planner
-- support, type I/O, encoding conversions, transforms, text search parsers and
-- templates, and FDW and language handlers and validators. And a LEAKPROOF
-- function outside pg_catalog: it runs before the RLS filter and can leak the
-- rows it sees. ponytail: a function body is opaque (plpgsql records no
-- dependencies), so every such function counts, the firewall's own aside.
WITH implicit AS (
  SELECT tgfoid AS f FROM pg_trigger UNION SELECT evtfoid FROM pg_event_trigger
  UNION SELECT unnest(ARRAY[aggtransfn, aggfinalfn, aggcombinefn, aggserialfn, aggdeserialfn,
                            aggmtransfn, aggminvtransfn, aggmfinalfn])::oid FROM pg_aggregate
  UNION SELECT unnest(ARRAY[rngcanonical, rngsubdiff])::oid FROM pg_range
  UNION SELECT amproc FROM pg_amproc
  UNION SELECT unnest(ARRAY[oprrest, oprjoin])::oid FROM pg_operator
  UNION SELECT unnest(ARRAY[typinput, typoutput, typreceive, typsend, typmodin, typmodout,
                            typanalyze, typsubscript])::oid FROM pg_type
  UNION SELECT conproc FROM pg_conversion
  UNION SELECT o.oprcode::oid FROM pg_amop a JOIN pg_operator o ON o.oid = a.amopopr
  UNION SELECT prosupport::oid FROM pg_proc WHERE prosupport <> 0
  UNION SELECT unnest(ARRAY[trffromsql, trftosql])::oid FROM pg_transform
  UNION SELECT unnest(ARRAY[prsstart, prstoken, prsend, prsheadline, prslextype])::oid FROM pg_ts_parser
  UNION SELECT unnest(ARRAY[tmplinit, tmpllexize])::oid FROM pg_ts_template
  UNION SELECT unnest(ARRAY[fdwhandler, fdwvalidator]) FROM pg_foreign_data_wrapper
  UNION SELECT unnest(ARRAY[lanplcallfoid, laninline, lanvalidator]) FROM pg_language)
SELECT p.oid::regprocedure::text AS name, pg_get_userbyid(p.proowner) AS owner, p.proleakproof AS leakproof
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND NOT (n.nspname = 'public' AND p.proname LIKE '#_firewall#_%' ESCAPE '#')
  AND (EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                 AND has_function_privilege(m.oid, p.oid, 'EXECUTE'))
       OR p.oid IN (SELECT f FROM implicit))
  AND (p.proleakproof OR (p.prosecdef AND (r.rolsuper OR r.rolbypassrls OR public._firewall_is_bypass_role(r.rolname::text))))
ORDER BY 1

-- @query other_schemas
-- Tables with the tenant column ($2) outside the scanned schemas ($1) that a
-- role the app can use can read (a column grant is enough).
SELECT n.nspname || '.' || c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND NOT (n.nspname = ANY($1))
  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
  AND EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                AND has_any_column_privilege(m.oid, c.oid, 'SELECT'))
  AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = $2
                AND a.attnum > 0 AND NOT a.attisdropped)
ORDER BY 1

-- @query keys_without_tenant
-- Keys that are not scoped to the tenant: RLS hides other tenants' rows, but
-- a unique key or an exclusion constraint still refuses a duplicate of their
-- value, and a foreign key still finds (or misses) their parent row, so the
-- error tells the app that another tenant has the value. $1: the protected
-- tables, as jsonb [[schema, table], ...]; $2: the tenant column.
-- * A unique index (primary keys included) or exclusion constraint on the
--   table whose key columns leave out the tenant column (a tenant column only
--   in INCLUDE, or in an exclusion constraint with an operator other than =,
--   does not count). A single-column key on a generated value (an
--   identity column, or a default from a sequence or a uuid function) is not
--   counted: a duplicate then shows only that an id is taken (an app that
--   sends its own ids can still learn which ids exist).
-- * A foreign key to a protected table, unless the referencing table is
--   protected too and its tenant column fills the referenced one (else the
--   app can probe another tenant's rows with that tenant's value there).
WITH prot AS (
  SELECT c.oid, n.nspname || '.' || c.relname AS name, a.attnum AS att
  FROM jsonb_array_elements($1::jsonb) e
  JOIN pg_namespace n ON n.nspname = e->>0 JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = e->>1
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = $2 AND a.attnum > 0 AND NOT a.attisdropped)
SELECT CASE WHEN x.indisexclusion THEN 'exclusion constraint ' ELSE 'unique key ' END
       || i.relname || ' on ' || p.name AS item
FROM prot p JOIN pg_index x ON x.indrelid = p.oid AND (x.indisunique OR x.indisexclusion)
JOIN pg_class i ON i.oid = x.indexrelid
WHERE NOT EXISTS (SELECT 1 FROM generate_series(0, x.indnkeyatts - 1) k WHERE x.indkey[k] = p.att
                    AND (NOT x.indisexclusion   -- an exclusion constraint counts it only with =
                         OR EXISTS (SELECT 1 FROM pg_constraint xc JOIN pg_operator o ON o.oid = xc.conexclop[k + 1]
                                    WHERE xc.conindid = x.indexrelid AND o.oprname = '=')))
  AND NOT (x.indnkeyatts = 1 AND x.indkey[0] <> 0 AND NOT x.indisexclusion
           AND EXISTS (SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                       WHERE a.attrelid = p.oid AND a.attnum = x.indkey[0]
                         AND (a.attidentity <> ''
                              OR pg_get_expr(d.adbin, d.adrelid) ~ '^((public|extensions)\.)?(nextval|gen_random_uuid|uuid_generate_v[14])\(')))
UNION ALL
SELECT 'foreign key ' || con.conname || ' on ' || con.conrelid::regclass::text || ' to ' || p.name
FROM prot p JOIN pg_constraint con ON con.confrelid = p.oid AND con.contype = 'f'
WHERE con.conrelid NOT IN (SELECT oid FROM prot)    -- else its policies do not pin that column
   OR NOT EXISTS (SELECT 1 FROM generate_subscripts(con.confkey, 1) k
                  JOIN pg_attribute ca ON ca.attrelid = con.conrelid AND ca.attnum = con.conkey[k]
                  WHERE con.confkey[k] = p.att AND ca.attname = $2)
ORDER BY 1

-- @query query_text
-- All tenants share one role, so its sessions see each other's SQL text in
-- pg_stat_activity and pg_stat_statements, literal values included.
SELECT EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
  AND (has_table_privilege(m.oid, 'pg_catalog.pg_stat_activity', 'SELECT')
       OR has_function_privilege(m.oid, 'pg_catalog.pg_stat_get_activity(integer)', 'EXECUTE')
       OR has_function_privilege(m.oid, 'pg_catalog.pg_stat_get_backend_activity(integer)', 'EXECUTE')
       OR EXISTS (SELECT 1 FROM pg_proc f WHERE f.proname = 'pg_stat_statements'
                    AND has_function_privilege(m.oid, f.oid, 'EXECUTE'))
       OR EXISTS (SELECT 1 FROM pg_class v WHERE v.relname = 'pg_stat_statements' AND v.relkind = 'v'
                    AND has_table_privilege(m.oid, v.oid, 'SELECT')))) AS can

-- ============================================================== verify --strict
-- @query strict_readable
-- Every relation a role the app can use can read, outside the system schemas,
-- with what decides whether it is tenant data. $1: the protected tables, as
-- jsonb [[schema, table], ...]. safe: a protected table, or a sequence one owns.
-- extension: the extension the relation belongs to, if any.
-- For a security_invoker view, the walk down its chain through invoker views:
-- broken when a view on it reads no relation, calls a function outside
-- pg_catalog, or it reaches a system relation; blockers: the relations it
-- reaches that are neither invoker views nor protected (each must be
-- allowlisted). ponytail: constants in a view body (VALUES, literals in a
-- UNION) cannot be seen.
WITH RECURSIVE prot AS (
  SELECT c.oid FROM jsonb_array_elements($1::jsonb) e
  JOIN pg_namespace n ON n.nspname = e->>0 JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = e->>1),
rel AS (
  SELECT c.oid, n.nspname || '.' || c.relname AS name, c.relkind AS kind,
         c.relkind = 'v' AND COALESCE((SELECT option_value::boolean FROM pg_options_to_table(c.reloptions)
                                       WHERE option_name = 'security_invoker'), false) AS invoker,
         EXISTS (SELECT 1 FROM pg_rewrite rw JOIN pg_depend d ON d.objid = rw.oid
                   AND d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_proc'::regclass
                 JOIN pg_proc f ON f.oid = d.refobjid AND f.pronamespace <> 'pg_catalog'::regnamespace
                 WHERE rw.ev_class = c.oid) AS calls_fn,
         c.oid IN (SELECT oid FROM prot) AS prot,
         (SELECT e.extname FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
          WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.refclassid = 'pg_extension'::regclass
            AND d.deptype = 'e' LIMIT 1) AS extension,
         c.relkind = 'S' AND EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass
                                       AND d.objid = c.oid AND d.refclassid = 'pg_class'::regclass
                                       AND d.deptype IN ('a', 'i') AND d.refobjid IN (SELECT oid FROM prot)) AS prot_seq,
         EXISTS (SELECT 1 FROM pg_roles m WHERE pg_has_role(current_user, m.oid, 'MEMBER')
                   AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(m.oid, c.oid, 'SELECT, USAGE')
                            ELSE has_any_column_privilege(m.oid, c.oid, 'SELECT') END) AS readable
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg#_%' ESCAPE '#'),
edge AS (
  SELECT DISTINCT rw.ev_class AS v, d.refobjid AS t FROM pg_rewrite rw
  JOIN pg_depend d ON d.objid = rw.oid AND d.classid = 'pg_rewrite'::regclass
                  AND d.refclassid = 'pg_class'::regclass AND d.refobjid <> rw.ev_class),
walk(top, cur) AS (
  SELECT r.oid, r.oid FROM rel r WHERE r.readable AND r.invoker
  UNION
  SELECT w.top, e.t FROM walk w JOIN rel x ON x.oid = w.cur AND x.invoker JOIN edge e ON e.v = w.cur)
SELECT r.name, r.kind, r.invoker, r.extension, r.prot OR r.prot_seq AS safe,
       r.invoker AND EXISTS (SELECT 1 FROM walk w LEFT JOIN rel x ON x.oid = w.cur WHERE w.top = r.oid
                               AND (x.oid IS NULL
                                    OR (x.invoker AND (x.calls_fn OR NOT EXISTS (SELECT 1 FROM edge e WHERE e.v = x.oid)))))
         AS broken,
       ARRAY(SELECT DISTINCT x.name FROM walk w JOIN rel x ON x.oid = w.cur
             WHERE w.top = r.oid AND NOT x.invoker AND NOT x.prot ORDER BY 1) AS blockers
FROM rel r WHERE r.readable ORDER BY r.name

-- @check strict: no readable large objects
-- Large objects are one store for the whole database: no RLS, no tenant.
SELECT count(*) = 0 AS ok,
       CASE WHEN count(*) = 0 THEN 'none'
            ELSE count(*) || ' large object(s) readable'
                 || CASE WHEN current_setting('lo_compat_privileges')::boolean THEN ' (lo_compat_privileges is on)' ELSE '' END
                 || ': shared by all tenants (lo_unlink them, or revoke)' END AS detail
FROM pg_largeobject_metadata l
WHERE current_setting('lo_compat_privileges')::boolean OR pg_has_role(current_user, l.lomowner, 'MEMBER')
   OR EXISTS (SELECT 1 FROM aclexplode(l.lomacl) a WHERE a.privilege_type = 'SELECT'
                AND (a.grantee = 0 OR pg_has_role(current_user, a.grantee, 'MEMBER')))

-- @query strict_definer
-- Every SECURITY DEFINER function outside the firewall's own, executable or
-- not: PostgreSQL runs some (triggers, aggregate, range and index support,
-- type I/O) without checking EXECUTE.
SELECT p.oid::regprocedure::text AS sig
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND NOT (n.nspname = 'public' AND p.proname LIKE '#_firewall#_%' ESCAPE '#')
ORDER BY 1
