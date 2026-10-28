"""
DB Firewall scanner: per-engine checks. Each returns {table: {..., "protected": bool}}
for every non-excluded table that has the tenant column.
"""

import hashlib
import json
import os
import re
import sys
from typing import Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from middleware.db_firewall import DBEngine, _is_excluded_table, engine_options, placeholder  # noqa: E402

# Exact schema.table match (pg_class + pg_namespace), so a same-named table
# elsewhere cannot vouch for this one. Protected = RLS enabled AND forced
# (owners bypass unforced RLS) AND all four firewall policies AND, for
# permissive firewall policies, no other PERMISSIVE policy: PostgreSQL ORs
# permissive policies, so one extra "USING (true)" opens every row. When all
# four firewall policies are RESTRICTIVE (policy_mode: restrictive) they AND
# with every other policy, so the app's permissive policies cannot widen past
# the tenant and are allowed. Params: (schema, tenant column).
_PG_SQL = """
            WITH t AS (
                SELECT c.oid, n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity,
                       'fw_' || left(md5(n.nspname || '.' || c.relname), 12) AS stem,
                       'firewall_rls_' || c.relname AS legacy
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind IN ('r', 'p') AND n.nspname = %s
                  AND EXISTS (SELECT 1 FROM pg_attribute a
                              WHERE a.attrelid = c.oid AND a.attname = %s
                                AND a.attnum > 0 AND NOT a.attisdropped)
            )
            SELECT t.relname, t.relrowsecurity, t.relforcerowsecurity,
                   ARRAY(SELECT op FROM unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op
                         WHERE NOT EXISTS (
                             SELECT 1 FROM pg_policies p
                             WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                               AND p.policyname IN (t.stem || '_' || op, t.legacy || '_' || op))),
                   ARRAY(SELECT p.policyname FROM pg_policies p
                         WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                           AND p.permissive = 'PERMISSIVE'
                           AND p.policyname NOT IN (
                               SELECT pre || '_' || op
                               FROM unnest(ARRAY[t.stem, t.legacy]) AS pre,
                                    unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op)),
                   COALESCE((SELECT count(*) = 4 AND bool_and(p.permissive = 'RESTRICTIVE')
                             FROM pg_policies p
                             WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                               AND p.policyname IN (t.stem || '_sel', t.stem || '_ins',
                                                    t.stem || '_upd', t.stem || '_del')), false),
                   -- The firewall policies as they are now, for the shape check below.
                   COALESCE((SELECT json_agg(json_build_array(p.policyname, p.cmd, p.roles,
                                                              p.qual, p.with_check))
                             FROM pg_policies p
                             WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                               AND p.policyname IN (
                                   SELECT pre || '_' || op
                                   FROM unnest(ARRAY[t.stem, t.legacy]) AS pre,
                                        unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op)), '[]'),
                   EXISTS (SELECT 1 FROM pg_policies p
                           WHERE p.schemaname = t.nspname AND p.tablename = t.relname
                             AND p.policyname = t.stem || '_base')
            FROM t
            ORDER BY t.relname
"""

_MYSQL_TABLES = """
    SELECT c.TABLE_SCHEMA, c.TABLE_NAME
    FROM INFORMATION_SCHEMA.COLUMNS c
    JOIN INFORMATION_SCHEMA.TABLES t
        ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
    WHERE c.COLUMN_NAME = %s
        AND t.TABLE_TYPE = 'BASE TABLE'
        AND c.TABLE_SCHEMA = COALESCE(%s, DATABASE())
    ORDER BY c.TABLE_NAME
"""

_SQLSERVER_TABLES = """
    SELECT c.TABLE_NAME
    FROM INFORMATION_SCHEMA.COLUMNS c
    JOIN INFORMATION_SCHEMA.TABLES t
        ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
    WHERE c.COLUMN_NAME = {ph}
        AND t.TABLE_TYPE = 'BASE TABLE'
    ORDER BY c.TABLE_NAME
"""

# VPD predicates AND together, so extra policies only narrow. Protected = an
# enabled policy using FN_TENANT_ISOLATION that covers all four statement
# types with update_check on. Params: (owner, owner, tenant column).
_ORACLE_SQL = """
    SELECT c.table_name,
           (SELECT COUNT(*) FROM all_policies p
             WHERE p.object_owner = c.owner AND p.object_name = c.table_name
               AND p.function = 'FN_TENANT_ISOLATION' AND p.enable = 'YES'
               AND p.sel = 'YES' AND p.ins = 'YES' AND p.upd = 'YES' AND p.del = 'YES'
               AND p.chk_option = 'YES') AS full_policies,
           (SELECT COUNT(*) FROM all_policies p
             WHERE p.object_owner = c.owner AND p.object_name = c.table_name) AS any_policies
    FROM all_tab_columns c
    JOIN all_tables tb ON tb.owner = c.owner AND tb.table_name = c.table_name
    WHERE c.owner = COALESCE(:1, USER) AND c.column_name = UPPER(:2)
      AND c.table_name NOT IN ('VPD_AUDIT_LOG', 'TENANT_USER_MAP')
    ORDER BY c.table_name
"""


_PG_CMD = {"sel": "SELECT", "ins": "INSERT", "upd": "UPDATE", "del": "DELETE"}


def _pg_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _pg_predicate(tenant_col: str, context: str) -> str:
    """The migration's predicate for dbfw.context signed (default) or plain."""
    col = _pg_ident(tenant_col)
    if context == "plain":
        return (f"{col} = NULLIF(current_setting('app.current_tenant', true), '') "
                "OR public._firewall_is_bypass_role(current_user::text)")
    return (f"{col} = (SELECT public._firewall_tenant()) "
            "OR (SELECT public._firewall_is_bypass_role(current_user::text))")


def _pg_reference(cursor, schema: str, table: str, tenant_col: str, context: str = "signed"):
    """The firewall predicate exactly as PostgreSQL deparses it for this table:
    a policy with the migration's predicate on a temporary copy of the table's
    columns, read back from pg_policies, then rolled back. Comparing deparsed
    text exactly catches a changed cast, an overloaded function or a changed
    constant that a normalised comparison would miss. Returns (text, None),
    or (None, reason) when it cannot be built."""
    pred = _pg_predicate(tenant_col, context)
    autocommit = bool(getattr(getattr(cursor, "connection", None), "autocommit", False))
    cursor.execute("BEGIN" if autocommit else "SAVEPOINT _fw_ref")
    try:
        cursor.execute(f"CREATE TEMP TABLE _fw_ref (LIKE {_pg_ident(schema)}.{_pg_ident(table)})")
        cursor.execute(f"CREATE POLICY _fw_ref_p ON pg_temp._fw_ref USING ({pred}) WITH CHECK ({pred})")
        cursor.execute("SELECT qual FROM pg_policies WHERE tablename = '_fw_ref' "
                       "AND policyname = '_fw_ref_p' AND schemaname = pg_my_temp_schema()::regnamespace::text")
        row = cursor.fetchone()
        return (row[0], None) if row else (None, "no result")
    except Exception as e:          # read-only transaction, no TEMP privilege, no SELECT ...
        return None, str(e).strip().splitlines()[0]
    finally:
        cursor.execute("ROLLBACK" if autocommit else "ROLLBACK TO SAVEPOINT _fw_ref")


def _pg_altered(policies, reference) -> list:
    """Firewall policies whose shape differs from what the migration creates:
    another role than PUBLIC, another command, or a predicate whose deparsed
    text is not exactly the reference."""
    altered = []
    for name, cmd, roles, qual, check in policies:
        op = name.rsplit("_", 1)[-1]
        want_qual = reference if op in ("sel", "upd", "del") else None
        want_check = reference if op in ("ins", "upd") else None
        if reference is None or roles != ["public"] or cmd != _PG_CMD[op] \
                or qual != want_qual or check != want_check:
            altered.append(name)
    return sorted(altered)


_PG_FUNCTION_RE = re.compile(r"CREATE OR REPLACE FUNCTION public\.(_firewall_\w+)\(([^)]*)\)\s*RETURNS (\w+) "
                             r"AS \$\$(.*?)\$\$ LANGUAGE (\w+)([^;]*);", re.S)


def _pg_firewall_objects(cursor):
    """None when every function the migration creates matches it (body,
    SECURITY DEFINER, settings, volatility, language, return type), no extra
    public._firewall_* function exists, and the public._firewall_* objects have
    one owner (or only superusers); else the reason. The policies call some of
    these functions and others sign, so a changed body opens every table while
    the policies still look exact. Same rules as packages/cli/src/scan.ts."""
    from middleware.db_firewall.migrate import MIGRATIONS_DIR
    sql = (MIGRATIONS_DIR / "001_postgresql.sql").read_text()
    norm = lambda x: " ".join(x.split())   # noqa: E731
    diff, sigs = [], []
    for name, args, ret, body, lang, tail in _PG_FUNCTION_RE.findall(sql):
        sig = ", ".join(a.split()[1].lower() for a in args.split(",") if len(a.split()) > 1)
        sigs.append(f"{name}({sig})")
        cursor.execute("SELECT prosrc, prosecdef, proconfig, provolatile, l.lanname, "
                       "format_type(prorettype, NULL) FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang "
                       "WHERE p.oid = to_regprocedure(%s)", (f"public.{name}({sig})",))
        row = cursor.fetchone()
        if not row:
            diff.append(f"{name} (missing)")
            continue
        src, secdef, config, volatile, lanname, rettype = row
        path = re.search(r"SET search_path = ([^\n;]+?)\s*$", tail, re.M)
        what = [w for w, bad in (
            ("body", norm(src) != norm(body)),
            ("SECURITY DEFINER", bool(secdef) != ("SECURITY DEFINER" in tail)),
            ("settings", (config or None) != ([f"search_path={path.group(1)}"] if path else None)),
            ("volatility", volatile != ("s" if "STABLE" in tail else "i" if "IMMUTABLE" in tail else "v")),
            ("language or return type", lanname != lang.lower() or rettype != ret.lower())) if bad]
        if what:
            diff.append(f"{name} ({', '.join(what)})")
    cursor.execute("SELECT p.oid::regprocedure::text FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace "
                   "AND p.proname LIKE '#_firewall#_%%' ESCAPE '#' "
                   "AND NOT (p.proname || '(' || oidvectortypes(p.proargtypes) || ')') = ANY(%s) ORDER BY 1",
                   (sigs,))
    extra = [r[0] for r in cursor.fetchall()]
    if extra:
        diff.append("extra " + ", ".join(extra))
    cursor.execute("SELECT pg_get_userbyid(o.owner), r.rolsuper, string_agg(o.name, ', ' ORDER BY o.name) FROM ("
                   "SELECT relname::text AS name, relowner AS owner FROM pg_class "
                   "WHERE relnamespace = 'public'::regnamespace AND relname LIKE '#_firewall#_%%' ESCAPE '#' "
                   "UNION ALL SELECT proname::text, proowner FROM pg_proc "
                   "WHERE pronamespace = 'public'::regnamespace AND proname LIKE '#_firewall#_%%' ESCAPE '#') o "
                   "JOIN pg_roles r ON r.oid = o.owner GROUP BY o.owner, r.rolsuper ORDER BY count(*) DESC")
    owners = cursor.fetchall()
    if len(owners) > 1 and not all(sup for _, sup, _ in owners):
        diff.append("more than one owner (" + "; ".join(f"{o}: {objs}" for o, _, objs in owners)
                    + "): objects another role planted? drop those and re-run the migration")
    return ("differ from the migration: " + "; ".join(diff)) if diff else None


def _scan_postgres(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    # Read the policies with search_path = pg_catalog, pg_temp: under the
    # default path a planted operator (say public.= for varchar, text) deparses
    # as a plain "=" and the policy would look exact.
    cursor.execute("SELECT current_setting('search_path'), "
                   "set_config('search_path', 'pg_catalog, pg_temp', false)")
    old_path = cursor.fetchone()[0]
    try:
        return _scan_postgres_tables(cursor, tenant_col, excluded, opts)
    finally:
        cursor.execute("SELECT set_config('search_path', %s, false)", (old_path,))


def _scan_postgres_tables(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    results = {}
    try:
        objects = _pg_firewall_objects(cursor)
    except Exception as e:          # no migration yet, an aborted transaction ...
        objects = "could not be checked: " + str(e).strip().splitlines()[0]
    cursor.execute(_PG_SQL, (opts.get("schema") or "public", tenant_col))
    schema = opts.get("schema") or "public"
    for table, enabled, forced, missing, extra, restrictive, policies, base in cursor.fetchall():
        if _is_excluded_table(table, excluded):
            continue
        if isinstance(policies, str):
            policies = json.loads(policies)
        # The expected context (engines.postgresql.tenant_context, default
        # signed). Policies in the other context count as altered, but the
        # report names the context they use.
        context = (opts.get("tenant_context") or "signed").lower()
        reference, why = _pg_reference(cursor, schema, table, tenant_col, context) if policies else (None, None)
        unverified = bool(policies) and reference is None
        # Without a reference the predicates cannot be checked: report that,
        # and fail closed, instead of calling every policy altered.
        altered = _pg_altered(policies, reference) if reference is not None else []
        found = context if policies and not altered and not unverified else None
        if policies and altered and not unverified:
            other = "plain" if context == "signed" else "signed"
            ref2, _ = _pg_reference(cursor, schema, table, tenant_col, other)
            found = other if ref2 is not None and not _pg_altered(policies, ref2) else "altered"
        missing, extra = sorted(missing), sorted(extra)
        results[table] = {
            "has_tenant_col": True, "has_rls_policy": not missing,
            "missing_policies": missing, "extra_permissive_policies": extra,
            "rls_enabled": bool(enabled), "rls_forced": bool(forced),
            "policy_mode": "restrictive" if restrictive else "permissive",
            "tenant_context": found,
            "altered_policies": altered,
            "predicate_check": ("unavailable: " + str(why)
                                + " (run the scanner outside a read-only transaction, with the "
                                  "TEMP privilege and SELECT on the table)") if unverified
                               else f"firewall functions {objects}" if objects else "ok",
            # restrictive mode: "<stem>_base" (USING true) next to the app's own
            # permissive policies ORs with them inside the tenant: re-run the migration.
            "stale_base_policy": bool(base) and any(not e.endswith("_base") for e in extra),
            "protected": bool(enabled) and bool(forced) and not missing and not altered
                         and not unverified and not objects and (bool(restrictive) or not extra),
        }
    return results


def _mysql_stem(table: str) -> str:
    """Name stem for v_<stem> and _fw_b?_<stem>, as 002_mysql.sql builds it:
    over 57 characters, the first 40 plus "_" plus 16 hex digits of SHA1."""
    if len(table) <= 57:
        return table
    return f"{table[:40]}_{hashlib.sha1(table.encode('utf-8')).hexdigest()[:16]}"


def _scan_mysql(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    """Protected = the v_<table> view and all three _fw_b{i,u,d}_<table> triggers."""
    results = {}
    cursor.execute(_MYSQL_TABLES, (tenant_col, opts.get("schema")))
    for schema, table in cursor.fetchall():
        if _is_excluded_table(table, excluded):
            continue
        stem = _mysql_stem(table)
        cursor.execute("SELECT 1 FROM INFORMATION_SCHEMA.VIEWS "
                       "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s", (schema, f"v_{stem}"))
        has_view = cursor.fetchone() is not None
        cursor.execute("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TRIGGERS "
                       "WHERE TRIGGER_SCHEMA = %s AND TRIGGER_NAME IN (%s, %s, %s) "
                       "AND EVENT_OBJECT_TABLE = %s",
                       (schema, f"_fw_bi_{stem}", f"_fw_bu_{stem}", f"_fw_bd_{stem}", table))
        has_triggers = cursor.fetchone()[0] == 3
        results[table] = {"has_tenant_col": True, "has_secure_view": has_view,
                          "has_triggers": has_triggers, "protected": has_view and has_triggers}
    return results


def _scan_sqlserver(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    """Protected = a security policy named firewall_rls_<table> exists."""
    results = {}
    ph = placeholder(cursor)                # pyodbc "?", pymssql "%s"
    cursor.execute(_SQLSERVER_TABLES.format(ph=ph), (tenant_col,))
    for (table,) in cursor.fetchall():
        if _is_excluded_table(table, excluded):
            continue
        cursor.execute(f"SELECT 1 FROM sys.security_policies WHERE name = {ph}",
                       (f"firewall_rls_{table}",))
        has_policy = cursor.fetchone() is not None
        results[table] = {"has_tenant_col": True, "has_rls_policy": has_policy,
                          "protected": has_policy}
    return results


def _scan_oracle(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    results = {}
    schema = opts.get("schema")
    cursor.execute(_ORACLE_SQL, (schema.upper() if schema else None, tenant_col))
    for table, full, anyp in cursor.fetchall():
        if _is_excluded_table(table, excluded) or _is_excluded_table(table.lower(), excluded):
            continue
        results[table] = {"has_tenant_col": True, "has_vpd_policy": anyp > 0,
                          "full_vpd_policy": full > 0, "protected": full > 0}
    return results


def _scan_sqlite(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    results = {}
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    for (table,) in cursor.fetchall():
        if _is_excluded_table(table, excluded):
            continue
        cursor.execute("SELECT name FROM pragma_table_info(?)", (table,))
        if tenant_col in [r[0] for r in cursor.fetchall()]:
            results[table] = {"has_tenant_col": True, "protected": False,
                              "note": "Requires middleware-only enforcement"}
    return results


_SCANNERS = {DBEngine.POSTGRESQL: _scan_postgres, DBEngine.MYSQL: _scan_mysql,
             DBEngine.SQLSERVER: _scan_sqlserver, DBEngine.ORACLE: _scan_oracle,
             DBEngine.SQLITE: _scan_sqlite}


def scan_tables(connection, engine: str, config: dict) -> Dict[str, dict]:
    """Status of every non-excluded table with the tenant column.
    An engine the scanner does not know raises instead of passing the gate."""
    scanner = _SCANNERS.get(engine)
    if scanner is None:
        raise ValueError(f"DB Firewall scanner: unsupported engine {engine!r}")
    cursor = connection.cursor()
    try:
        return scanner(cursor, config.get("tenant_column", "tenant_id"),
                       config.get("excluded_tables", []), engine_options(config, engine))
    finally:
        cursor.close()
