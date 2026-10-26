"""
DB Firewall scanner: per-engine checks. Each returns {table: {..., "protected": bool}}
for every non-excluded table that has the tenant column.
"""

import os
import sys
from typing import Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from middleware.db_firewall import DBEngine, _is_excluded_table, engine_options  # noqa: E402

# Exact schema.table match (pg_class + pg_namespace), so a same-named table
# elsewhere cannot vouch for this one. Protected = RLS enabled AND forced
# (owners bypass unforced RLS) AND all four firewall policies AND no other
# PERMISSIVE policy: PostgreSQL ORs permissive policies, so one extra
# "USING (true)" opens every row. Params: (schema, tenant column).
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
                                    unnest(ARRAY['sel', 'ins', 'upd', 'del']) AS op))
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
    WHERE c.COLUMN_NAME = ?
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


def _scan_postgres(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    results = {}
    cursor.execute(_PG_SQL, (opts.get("schema") or "public", tenant_col))
    for table, enabled, forced, missing, extra in cursor.fetchall():
        if _is_excluded_table(table, excluded):
            continue
        missing, extra = sorted(missing), sorted(extra)
        results[table] = {
            "has_tenant_col": True, "has_rls_policy": not missing,
            "missing_policies": missing, "extra_permissive_policies": extra,
            "rls_enabled": bool(enabled), "rls_forced": bool(forced),
            "protected": bool(enabled) and bool(forced) and not missing and not extra,
        }
    return results


def _scan_mysql(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    """Protected = the v_<table> view and all three _fw_b{i,u,d}_<table> triggers."""
    results = {}
    cursor.execute(_MYSQL_TABLES, (tenant_col, opts.get("schema")))
    for schema, table in cursor.fetchall():
        if _is_excluded_table(table, excluded):
            continue
        cursor.execute("SELECT 1 FROM INFORMATION_SCHEMA.VIEWS "
                       "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s", (schema, f"v_{table}"))
        has_view = cursor.fetchone() is not None
        cursor.execute("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TRIGGERS "
                       "WHERE TRIGGER_SCHEMA = %s AND TRIGGER_NAME IN (%s, %s, %s)",
                       (schema, f"_fw_bi_{table}", f"_fw_bu_{table}", f"_fw_bd_{table}"))
        has_triggers = cursor.fetchone()[0] == 3
        results[table] = {"has_tenant_col": True, "has_secure_view": has_view,
                          "has_triggers": has_triggers, "protected": has_view and has_triggers}
    return results


def _scan_sqlserver(cursor, tenant_col, excluded, opts) -> Dict[str, dict]:
    """Protected = a security policy named firewall_rls_<table> exists."""
    results = {}
    cursor.execute(_SQLSERVER_TABLES, (tenant_col,))
    for (table,) in cursor.fetchall():
        if _is_excluded_table(table, excluded):
            continue
        cursor.execute("SELECT 1 FROM sys.security_policies WHERE name = ?",
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
