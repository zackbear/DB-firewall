"""
sqlglot AST rewriter tests (no database needed).

Every positive test parses the rewriter's OUTPUT with sqlglot and checks
structurally that each protected table reference has
``<qualifier>.tenant_id = '<tenant>'`` in scope (WHERE of its query, or the
ON clause of the join it sits on). INSERT targets must carry the tenant
column + literal. Negative tests assert PermissionError.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
sqlglot = pytest.importorskip("sqlglot")
from sqlglot import exp  # noqa: E402

from sql_rewriter import rewrite, DIALECTS, _mask_placeholders  # noqa: E402

TENANT = "TENANT_A"
COL = "tenant_id"
PROTECTED = {"orders", "items", "customers"}
EXCLUDED = {"schema_migrations", "_firewall_audit_log"}


def is_protected(name, quoted=False):
    return name in PROTECTED


def rw(sql, dialect="postgresql", tenant=TENANT, prot=is_protected):
    return rewrite(sql, tenant, COL, prot, dialect)


# ---------------------------------------------------------------- checker ---

def _conjuncts(node):
    if node is None:
        return []
    if isinstance(node, exp.Where):
        node = node.this
    if isinstance(node, exp.Paren):
        return _conjuncts(node.this)
    if isinstance(node, exp.And):
        return _conjuncts(node.this) + _conjuncts(node.expression)
    return [node]


def _has_pred(conds, qualifier, tenant):
    return any(isinstance(c, exp.EQ) and isinstance(c.this, exp.Column)
               and c.this.name == COL and c.this.table == qualifier
               and isinstance(c.expression, exp.Literal) and c.expression.this == tenant
               for c in conds)


def _owner(node):
    p = node.parent
    while p is not None and not isinstance(p, (exp.Select, exp.Update, exp.Delete)):
        p = p.parent
    return p


def parse(out, dialect):
    read = DIALECTS.get(dialect)
    return sqlglot.parse_one(_mask_placeholders(out, read)[0], read=read)


def assert_scoped(out, dialect="postgresql", tenant=TENANT, prot=is_protected):
    """Structural proof: every protected table reference in ``out`` is scoped."""
    tree = parse(out, dialect)
    cte_names = {c.alias for c in tree.find_all(exp.CTE)}
    checked = 0
    for t in tree.find_all(exp.Table):
        if not prot(t.name) or t.name in cte_names and not isinstance(t.parent, exp.CTE):
            continue
        if isinstance(t.parent, (exp.Insert, exp.Schema)):
            continue                            # INSERT targets: see assert_stamped
        owner = _owner(t)
        assert owner is not None, f"{t.sql()} has no enclosing query"
        conds = _conjuncts(owner.args.get("where"))
        for j in owner.find_all(exp.Join):
            if _owner(j) is owner:
                conds += _conjuncts(j.args.get("on"))
        qual = t.alias or t.name
        assert _has_pred(conds, qual, tenant), \
            f"{qual} not scoped in: {owner.sql()}"
        checked += 1
    return checked


def assert_stamped(out, dialect="postgresql", tenant=TENANT, with_placeholder=False):
    ins = parse(out, dialect)
    assert isinstance(ins, exp.Insert)
    cols = [c.name for c in ins.this.expressions]
    assert cols.count(COL) == 1
    idx = cols.index(COL)
    src = ins.expression
    rows = ([t.expressions for t in src.expressions] if isinstance(src, exp.Values)
            else [s.expressions for s in src.find_all(exp.Select)])
    for row in rows:
        v = row[idx]
        if with_placeholder and isinstance(v, exp.Column):
            continue
        assert isinstance(v, exp.Literal) and v.this == tenant, out
    return ins


# ---------------------------------------------------------------- scoping ---

class TestScopes:

    def test_simple_select_and_existing_where_keeps_or_grouped(self):
        out = rw("SELECT * FROM orders WHERE a = 1 OR b = 2")
        assert assert_scoped(out) == 1
        assert "(a = 1 OR b = 2)" in out          # precedence preserved

    def test_union_both_branches(self):
        out = rw("SELECT id FROM orders UNION SELECT id FROM orders WHERE tenant_id = 'TENANT_B'")
        assert assert_scoped(out) == 2
        for sel in sqlglot.parse_one(out).find_all(exp.Select):
            assert _has_pred(_conjuncts(sel.args["where"]), "orders", TENANT)

    @pytest.mark.parametrize("op", ["INTERSECT", "EXCEPT", "UNION ALL"])
    def test_other_set_ops(self, op):
        assert assert_scoped(rw(f"SELECT a FROM orders {op} SELECT a FROM items")) == 2

    def test_cte_body_and_outer(self):
        out = rw("WITH o AS (SELECT * FROM orders) SELECT o.id FROM o JOIN items i ON i.oid = o.id")
        assert assert_scoped(out) == 2             # orders (in CTE) + items (outer)
        assert "o.tenant_id" not in out            # the CTE name is not a table

    def test_cte_shadowing_real_table_scopes_body(self):
        out = rw("WITH orders AS (SELECT * FROM orders WHERE x = 1) SELECT * FROM orders")
        tree = sqlglot.parse_one(out)
        body = tree.find(exp.CTE).this
        assert _has_pred(_conjuncts(body.args["where"]), "orders", TENANT)
        assert tree.args.get("where") is None       # outer ref is the CTE

    def test_recursive_cte_self_reference_not_scoped(self):
        out = rw("WITH RECURSIVE t AS (SELECT * FROM orders WHERE pid IS NULL "
                 "UNION ALL SELECT o.* FROM orders o JOIN t ON o.pid = t.id) SELECT * FROM t")
        assert assert_scoped(out) == 2
        assert "t.tenant_id" not in out

    def test_subquery_in_where(self):
        out = rw("SELECT * FROM customers c WHERE c.id IN (SELECT cid FROM orders)")
        assert assert_scoped(out) == 2

    def test_scalar_subquery_in_select_list(self):
        out = rw("SELECT (SELECT count(*) FROM items WHERE qty > 1) FROM orders")
        assert assert_scoped(out) == 2

    def test_derived_table(self):
        out = rw("SELECT d.n FROM (SELECT count(*) n FROM orders GROUP BY cid) d")
        assert assert_scoped(out) == 1

    def test_self_join_with_aliases(self):
        out = rw("SELECT a.id FROM orders a JOIN orders b ON a.pid = b.id")
        assert assert_scoped(out) == 2
        conds = _conjuncts(sqlglot.parse_one(out).args["where"])
        assert _has_pred(conds, "a", TENANT) and _has_pred(conds, "b", TENANT)

    def test_inner_join_goes_to_where(self):
        out = rw("SELECT * FROM orders o JOIN items i ON i.oid = o.id")
        j = sqlglot.parse_one(out).args["joins"][0]
        assert COL not in j.args["on"].sql()
        assert assert_scoped(out) == 2

    def test_left_join_protected_right_side_gets_on_predicate(self):
        out = rw("SELECT * FROM customers c LEFT JOIN orders o ON o.cid = c.id")
        tree = sqlglot.parse_one(out)
        assert _has_pred(_conjuncts(tree.args["joins"][0].args["on"]), "o", TENANT)
        assert _has_pred(_conjuncts(tree.args["where"]), "c", TENANT)
        assert not _has_pred(_conjuncts(tree.args["where"]), "o", TENANT)

    def test_right_join_left_side_gets_on_right_side_where(self):
        out = rw("SELECT * FROM orders o RIGHT JOIN customers c ON o.cid = c.id")
        tree = sqlglot.parse_one(out)
        assert _has_pred(_conjuncts(tree.args["joins"][0].args["on"]), "o", TENANT)
        assert _has_pred(_conjuncts(tree.args["where"]), "c", TENANT)

    def test_full_join_falls_back_to_where(self):
        out = rw("SELECT * FROM orders o FULL OUTER JOIN items i ON i.oid = o.id")
        tree = sqlglot.parse_one(out)
        w = _conjuncts(tree.args["where"])
        assert _has_pred(w, "o", TENANT) and _has_pred(w, "i", TENANT)

    def test_left_join_using_falls_back_to_where(self):
        out = rw("SELECT * FROM customers c LEFT JOIN orders o USING (cid)")
        assert assert_scoped(out) == 2

    def test_comma_join(self):
        assert assert_scoped(rw("SELECT * FROM orders o, items i WHERE i.oid = o.id")) == 2

    def test_schema_qualified_and_quoted(self):
        out = rw('SELECT * FROM public."orders"')
        assert assert_scoped(out) == 1
        assert '"orders".tenant_id' in out

    def test_exists_correlated(self):
        out = rw("SELECT * FROM orders o WHERE EXISTS (SELECT 1 FROM items i WHERE i.oid = o.id)")
        assert assert_scoped(out) == 2

    def test_leading_paren_select(self):
        out = rw("(SELECT * FROM orders ORDER BY id LIMIT 1)")
        assert assert_scoped(out) == 1
        assert out.startswith("(")

    def test_order_limit_offset_preserved(self):
        out = rw("SELECT * FROM orders ORDER BY created_at DESC LIMIT 5 OFFSET 2")
        assert assert_scoped(out) == 1
        assert out.upper().endswith("ORDER BY created_at DESC LIMIT 5 OFFSET 2".upper())

    def test_lateral_subquery(self):
        out = rw("SELECT * FROM orders o, LATERAL (SELECT * FROM items i WHERE i.oid = o.id) x")
        assert assert_scoped(out) == 2

    def test_delete_with_subquery(self):
        out = rw("DELETE FROM orders WHERE id IN (SELECT oid FROM items)")
        assert assert_scoped(out) == 2


class TestWriteStatements:

    def test_update_from(self):
        out = rw("UPDATE orders SET status = 'x' FROM customers WHERE orders.cid = customers.id")
        assert assert_scoped(out) == 2
        w = _conjuncts(sqlglot.parse_one(out).args["where"])
        assert _has_pred(w, "orders", TENANT) and _has_pred(w, "customers", TENANT)

    def test_update_from_left_join(self):
        out = rw("UPDATE orders o SET s = 1 FROM customers c LEFT JOIN items i ON i.cid = c.id "
                 "WHERE o.cid = c.id")
        assert assert_scoped(out) == 3

    def test_delete_using(self):
        out = rw("DELETE FROM orders USING customers WHERE orders.cid = customers.id")
        assert assert_scoped(out) == 2

    def test_update_set_tenant_column_rejected(self):
        with pytest.raises(PermissionError, match="tenant column"):
            rw("UPDATE orders SET tenant_id = 'TENANT_B' WHERE id = 1")
        with pytest.raises(PermissionError, match="tenant column"):
            rw("UPDATE orders SET tenant_id = %s WHERE id = 1")
        assert_scoped(rw("UPDATE orders SET tenant_id = 'TENANT_A', x = 1"))

    def test_insert_select_stamps_and_scopes(self):
        out = rw("INSERT INTO orders (cid, total) SELECT id, 0 FROM customers")
        assert_stamped(out)
        assert assert_scoped(out) == 1             # customers in the SELECT

    def test_insert_select_union_stamps_both_branches(self):
        out = rw("INSERT INTO orders (cid) SELECT id FROM customers UNION ALL SELECT oid FROM items")
        assert_stamped(out)
        assert assert_scoped(out) == 2

    def test_insert_values_stamps_every_row(self):
        out = rw("INSERT INTO orders (cid, total) VALUES (1, 2), (3, 4) RETURNING id")
        ins = assert_stamped(out)
        assert len(ins.expression.expressions) == 2
        assert "RETURNING id" in out

    def test_insert_with_matching_tenant_literal_untouched(self):
        out = rw("INSERT INTO orders (cid, tenant_id) VALUES (1, 'TENANT_A')")
        assert_stamped(out)

    def test_insert_with_conflicting_tenant_literal_rejected(self):
        with pytest.raises(PermissionError, match="different tenant"):
            rw("INSERT INTO orders (cid, tenant_id) VALUES (1, 'TENANT_B')")
        with pytest.raises(PermissionError, match="different tenant"):
            rw("INSERT INTO orders (cid, tenant_id) VALUES (1, 'TENANT_A'), (2, 'TENANT_B')")
        with pytest.raises(PermissionError, match="different tenant"):
            rw("INSERT INTO orders (cid, tenant_id) SELECT id, 'TENANT_B' FROM customers")

    def test_insert_with_tenant_placeholder_rejected_unless_allowed(self):
        # M2: a bound tenant value is the caller's choice, not the firewall's
        sql = "INSERT INTO orders (cid, tenant_id) VALUES (%s, %s)"
        with pytest.raises(PermissionError, match="allow_tenant_placeholder"):
            rw(sql)
        assert rewrite(sql, TENANT, COL, is_protected, "postgresql",
                       allow_tenant_placeholder=True) == sql

    def test_insert_select_star_with_tenant_column_rejected(self):
        with pytest.raises(PermissionError, match="SELECT \\*"):
            rw("INSERT INTO orders (cid, tenant_id) SELECT * FROM items")

    @pytest.mark.parametrize("sql", [
        "INSERT INTO orders VALUES (1, 2)",
        "INSERT INTO orders DEFAULT VALUES",
        "INSERT INTO orders SELECT * FROM items",
    ])
    def test_insert_without_column_list_rejected(self, sql):
        with pytest.raises(PermissionError, match="column list"):
            rw(sql)

    def test_insert_on_conflict_switching_tenant_rejected(self):
        with pytest.raises(PermissionError, match="tenant column"):
            rw("INSERT INTO orders (id, cid) VALUES (1, 2) "
               "ON CONFLICT (id) DO UPDATE SET tenant_id = 'TENANT_B'")
        assert_stamped(rw("INSERT INTO orders (id, cid) VALUES (1, 2) "
                          "ON CONFLICT (id) DO UPDATE SET cid = 3"))

    def test_insert_into_unprotected_from_protected_only_scopes(self):
        out = rw("INSERT INTO schema_migrations (v) SELECT id FROM orders")
        assert assert_scoped(out) == 1
        assert "schema_migrations (v)" in out       # target untouched

    def test_data_modifying_cte(self):
        out = rw("WITH x AS (DELETE FROM orders WHERE done RETURNING *) "
                 "INSERT INTO items (oid) SELECT id FROM x")
        assert assert_scoped(out) == 1
        assert_stamped(out)


# ---------------------------------------------------------- pass-through ---

class TestUntouched:

    def test_excluded_table_untouched(self):
        sql = "SELECT * FROM schema_migrations UNION SELECT * FROM _firewall_audit_log"
        assert rw(sql) == sql

    def test_non_tenant_table_untouched(self):
        sql = "SELECT * FROM pg_catalog.pg_type WHERE oid = 1"
        assert rw(sql, prot=lambda n, q=False: False) == sql

    def test_mixed_scopes_only_protected(self):
        out = rw("SELECT * FROM orders o JOIN schema_migrations m ON m.v = o.v")
        assert assert_scoped(out) == 1
        assert "m.tenant_id" not in out

    @pytest.mark.parametrize("dialect,sql", [
        ("postgresql", "SELECT * FROM orders WHERE id = %s AND name = %(name)s AND n = $1 LIMIT %s"),
        ("postgresql", "SELECT * FROM orders WHERE id = ANY(%s) AND d > now() - %s::interval"),
        ("mysql", "SELECT * FROM orders WHERE id = %s AND x IN (%s, %s)"),
        ("sqlite", "SELECT * FROM orders WHERE id = ? AND y = :name AND z = ?2"),
        ("sqlserver", "SELECT TOP 5 * FROM orders WHERE id = ?"),
        ("oracle", "SELECT * FROM orders WHERE id = :1 AND n = :nm"),
        (None, "SELECT * FROM orders WHERE id = ?"),
    ])
    def test_placeholders_survive(self, dialect, sql):
        out = rw(sql, dialect=dialect)
        for tok in ("%s", "%(name)s", "$1", "?", ":name", "?2", ":1", ":nm"):
            assert out.count(tok) == sql.count(tok), (tok, out)
        assert "__dbfw_ph_" not in out
        assert assert_scoped(out, dialect=dialect) == 1

    def test_placeholders_in_insert_values(self):
        out = rw("INSERT INTO orders (cid, total) VALUES (%s, %s)")
        assert out == "INSERT INTO orders (cid, total, tenant_id) VALUES (%s, %s, 'TENANT_A')"

    def test_cast_and_slice_colons_are_not_placeholders(self):
        out = rw("SELECT a::text, arr[1:2] FROM orders WHERE b::int = 1")
        assert assert_scoped(out) == 1
        assert "arr[1:2]" in out

    def test_postgres_jsonb_question_operator_kept(self):
        out = rw("SELECT * FROM orders WHERE data ? 'k'")
        assert "data ? 'k'" in out and assert_scoped(out) == 1

    @pytest.mark.parametrize("sql", [
        "SELECT * FROM orders WHERE note = 'a UNION b' ORDER BY id",
        "SELECT * FROM orders WHERE note = 'x WHERE y' AND status = 'a'",
        "SELECT * FROM orders WHERE note = 'it''s; DROP TABLE x'",
    ])
    def test_keywords_inside_string_literals_untouched(self, sql):
        out = rw(sql)
        assert assert_scoped(out) == 1
        lit = sql[sql.index("'"):sql.index("'", sql.index("'") + 1) + 1]
        assert lit in out or lit.replace("''", "'") in out

    @pytest.mark.parametrize("sql", [
        "SELECT * FROM orders -- WHERE tenant_id = 'TENANT_B'",
        "SELECT * FROM orders /* UNION SELECT * FROM orders */",
        "/* hint */ SELECT * FROM orders",
        "SELECT * FROM orders -- comment */ OR 1=1",
    ])
    def test_comments_stripped_harmlessly(self, sql):
        out = rw(sql)
        assert "--" not in out and "/*" not in out
        assert assert_scoped(out) == 1
        assert "TENANT_B" not in out and "1=1" not in out

    def test_tenant_id_with_quote_escaped(self):
        out = rw("SELECT * FROM orders", tenant="A' OR '1'='1")
        assert out == "SELECT * FROM orders WHERE orders.tenant_id = 'A'' OR ''1''=''1'"
        assert assert_scoped(out, tenant="A' OR '1'='1") == 1

    def test_mysql_quoting(self):
        out = rw("SELECT * FROM `orders` o WHERE a = 'it''s'", dialect="mysql")
        assert assert_scoped(out, dialect="mysql") == 1
        assert "`orders`" in out and "'it''s'" in out

    def test_backslash_quote_is_ambiguous_and_rejected(self):
        # 'it\'s' is one literal in MySQL and two in standard SQL: never guess
        with pytest.raises(PermissionError, match="ambiguous"):
            rw("SELECT * FROM orders WHERE a = 'it\\'s'", dialect="mysql")


# -------------------------------------------------------------- rejections ---

class TestRejected:

    @pytest.mark.parametrize("sql,why", [
        ("SELECT * FROM orders; DELETE FROM orders", "multiple statements"),
        ("CREATE TABLE t2 AS SELECT * FROM orders", "Create"),
        ("ALTER TABLE orders ADD COLUMN x INT", "Alter"),
        ("DROP TABLE orders", "Drop"),
        ("TRUNCATE orders", "Truncate"),
        ("SELECT * INTO t2 FROM orders", "SELECT INTO"),
        ("MERGE INTO orders o USING items i ON o.id = i.oid WHEN MATCHED THEN UPDATE SET a = 1", "Merge"),
        ("COPY orders TO STDOUT", "Copy"),
        ("EXPLAIN SELECT * FROM orders", "Command"),
        ("TABLE orders", "TABLE command"),
        ("SELECT * FROM orders WHERE note = 'unterminated", "unterminated"),
        ("SELECT * FROM orders /* unterminated", "unterminated"),
        ("SELECT * FROM orders JOIN orders ON 1=1", "twice"),
        ("SELECT * FROM generate_series(1, 3)", "resolvable name"),
        ("SELECT * FROM orders WHERE x = __dbfw_ph_0__", "reserved"),
        ("SELECT * FROM (orders) o", "parenthesised"),
    ], ids=lambda v: v if " " not in str(v) else None)
    def test_unsafe_shapes_rejected(self, sql, why):
        with pytest.raises(PermissionError, match=why):
            rw(sql)

    def test_generate_series_allowed_when_nothing_protected_is_name_resolvable(self):
        # table functions are rejected only because they cannot be named;
        # a plain unprotected table passes untouched
        assert rw("SELECT * FROM schema_migrations") == "SELECT * FROM schema_migrations"

    def test_missing_sqlglot_raises_import_error(self, monkeypatch):
        import sql_rewriter
        monkeypatch.setattr(sql_rewriter, "sqlglot", None)
        with pytest.raises(ImportError, match="pip install"):
            sql_rewriter.rewrite("SELECT * FROM orders", TENANT, COL, is_protected, "postgresql")


# ------------------------------------------------- allow-list / review fixes ---

class TestAllowList:
    """Every statement is parsed; only SELECT/INSERT/UPDATE/DELETE heads are
    rewritten, transaction control and harmless SET/RESET pass through, the
    rest is refused whatever tables it names (review items A, C2, C5-C8, H4)."""

    @pytest.mark.parametrize("sql", [
        "BEGIN", "BEGIN WORK", "START TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ ONLY",
        "COMMIT", "END", "ROLLBACK", "ABORT", "SAVEPOINT a", "RELEASE SAVEPOINT a", "RELEASE a",
        "ROLLBACK TO SAVEPOINT a", "ROLLBACK TO a", "SET statement_timeout = 1000",
        "SET LOCAL lock_timeout TO '1s'", "SET SESSION TIME ZONE 'UTC'", "SET NAMES utf8",
        "SET @x = 1", "SET @@session.sql_mode = ''", "RESET statement_timeout",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", "SELECT 1", "SELECT now()",
        "select set_config('statement_timeout', '1s', true)",
    ])
    def test_pass_through_unchanged(self, sql):
        assert rw(sql) == sql
        assert rewrite(sql, None, COL, is_protected, "postgresql") == sql   # no-tenant mode too

    @pytest.mark.parametrize("sql,why", [
        ("SET app.current_tenant = 'B'", "app.current_tenant"),
        ("SET LOCAL app.current_tenant TO 'B'", "app.current_tenant"),
        ("set session app.current_tenant = 'B'", "app.current_tenant"),
        ('SET "app.current_tenant" = \'B\'', "app.current_tenant"),
        ('SET app."current_tenant" = \'B\'', "app.current_tenant"),
        ("SET app . Current_Tenant = 'B'", "app.current_tenant"),
        ("SET ROLE postgres", "role"), ("SET LOCAL ROLE postgres", "role"),
        ("SET SESSION AUTHORIZATION x", "authorization"),
        ("SET search_path = pg_temp, public", "search_path"),
        ("SET row_security = off", "row_security"),
        ("SET @_fw_tenant_id = 'B'", "@_fw_tenant_id"),
        ("RESET ALL", "all"), ("RESET ROLE", "role"), ("RESET app.current_tenant", "app"),
        ("RESET SESSION AUTHORIZATION", "session"),
        ("SELECT set_config('app.current_tenant', 'B', true)", "set_config"),
        ("SELECT pg_catalog.set_config('App.Current_Tenant', 'B', false)", "set_config"),
        ("SELECT set_config(name, 'B', true) FROM schema_migrations", "set_config"),
        ("SELECT * FROM set_config('x', 'y', true)", "set_config|resolvable name"),
        ("WITH s AS (SELECT set_config('role', 'x', true)) SELECT 1", "set_config"),
    ])
    def test_tenant_moving_settings_refused(self, sql, why):
        with pytest.raises(PermissionError, match=why):
            rw(sql)
        with pytest.raises(PermissionError, match=why):
            rewrite(sql, None, COL, is_protected, "postgresql")

    @pytest.mark.parametrize("sql", [
        "DO $$ BEGIN NULL; END $$", "CALL p()", "EXECUTE p", "PREPARE p AS SELECT 1",
        "DECLARE c CURSOR FOR SELECT 1", "EXPLAIN SELECT 1", "SHOW search_path", "VACUUM",
        "CREATE TABLE fresh (id INT)", "DROP TABLE schema_migrations", "GRANT SELECT ON x TO y",
        "TRUNCATE schema_migrations", "COPY schema_migrations TO STDOUT", "LOCK TABLE x",
        "DISCARD ALL", "LISTEN x", "VALUES (1)", "TABLE schema_migrations",
        "SELECT * FROM (TABLE schema_migrations) x", "WITH x AS (TABLE orders) SELECT * FROM x",
        'SELECT * FROM U&"orders"', "SELECT U&'\\0041' FROM schema_migrations",
        "SELECT * FROM schema_migrations; SELECT 1",
    ])
    def test_non_allow_listed_refused_even_without_protected_tables(self, sql):
        with pytest.raises(PermissionError):
            rw(sql)

    def test_nested_block_comments_are_ambiguous(self):
        # Postgres nests /* */, MySQL does not: the two readings differ → refuse
        with pytest.raises(PermissionError, match="ambiguous"):
            rw("SET /* x /* y */ zzz */ app.current_tenant = 'B'")
        with pytest.raises(PermissionError, match="ambiguous"):
            rw("SELECT * FROM /* a /* b */ c */ orders")
        # a plain comment is still fine
        assert assert_scoped(rw("SELECT * FROM /* a */ orders")) == 1

    def test_only_keyword_is_scoped(self):
        out = rw("SELECT * FROM ONLY orders")
        assert assert_scoped(out) == 1 and "ONLY" in out

    def test_schema_qualified_name_is_never_a_cte(self):
        out = rw("WITH orders AS (SELECT 1 AS id) SELECT * FROM public.orders")
        tree = sqlglot.parse_one(out)
        assert _has_pred(_conjuncts(tree.args["where"]), "orders", TENANT)

    def test_callback_receives_quoted_flag(self):
        seen = []

        def prot(name, quoted):
            seen.append((name, quoted))
            return False
        rw('SELECT * FROM "Orders" o JOIN items i ON 1=1 JOIN public."x" ON 1=1', prot=prot)
        assert seen == [("Orders", True), ("items", False), ("x", True)]

    def test_no_tenant_mode_refuses_protected_and_allows_unprotected(self):
        with pytest.raises(PermissionError, match="No tenant context"):
            rewrite("SELECT * FROM orders", None, COL, is_protected, "postgresql")
        with pytest.raises(PermissionError, match="No tenant context"):
            rewrite("INSERT INTO orders (a) VALUES (1)", None, COL, is_protected, "postgresql")
        sql = "SELECT * FROM schema_migrations"
        assert rewrite(sql, None, COL, is_protected, "postgresql") == sql

    def test_protect_ops_opt_out(self):
        sql = "SELECT * FROM orders"
        assert rewrite(sql, TENANT, COL, is_protected, "postgresql",
                       protect_ops={"select": False}) == sql
        assert_scoped(rewrite(sql, TENANT, COL, is_protected, "postgresql",
                              protect_ops={"insert": False}))
        with pytest.raises(PermissionError):      # opt-out never widens the allow-list
            rewrite("TRUNCATE orders", TENANT, COL, is_protected, "postgresql",
                    protect_ops={"select": False})


class TestWriteSideHardening:

    def test_on_conflict_do_update_is_guarded_by_tenant_where(self):
        """H1: the conflicting row may belong to another tenant."""
        out = rw("INSERT INTO orders (id, cid) VALUES (3, 2) "
                 "ON CONFLICT (id) DO UPDATE SET cid = EXCLUDED.cid WHERE orders.x = 1")
        ins = assert_stamped(out)
        where = _conjuncts(ins.args["conflict"].args["where"])
        assert _has_pred(where, "orders", TENANT) and len(where) == 2
        out = rw("INSERT INTO orders (id) VALUES (3) ON CONFLICT (id) DO UPDATE SET cid = 1")
        assert _has_pred(_conjuncts(parse(out, "postgresql").args["conflict"].args["where"]),
                         "orders", TENANT)
        out = rw("INSERT INTO orders (id) VALUES (3) ON CONFLICT (id) DO NOTHING")
        assert parse(out, "postgresql").args["conflict"].args.get("where") is None

    def test_mysql_on_duplicate_key_update_refused(self):
        with pytest.raises(PermissionError, match="ON DUPLICATE KEY"):
            rw("INSERT INTO orders (id, cid) VALUES (3, 2) ON DUPLICATE KEY UPDATE cid = 2",
               dialect="mysql")
        out = rw("INSERT INTO orders (id, cid) VALUES (3, 2)", dialect="mysql")
        assert_stamped(out, dialect="mysql")

    @pytest.mark.parametrize("rhs", ["(1, 'TENANT_B')", "(1, 'TENANT_A')", "ROW(1, 'TENANT_A')",
                                     "(SELECT 1, 'TENANT_A')", "(%s, %s)"])
    def test_tuple_assignment_to_tenant_column_refused(self, rhs):
        """H2 — UPDATE, ON CONFLICT and ON DUPLICATE KEY forms."""
        with pytest.raises(PermissionError, match="tuple assignment"):
            rw(f"UPDATE orders SET (cid, tenant_id) = {rhs} WHERE id = 1")
        with pytest.raises(PermissionError, match="tuple assignment"):
            rw(f"INSERT INTO orders (id) VALUES (1) ON CONFLICT (id) DO UPDATE "
               f"SET (cid, tenant_id) = {rhs}")
        with pytest.raises(PermissionError):
            rw(f"INSERT INTO orders (id) VALUES (1) ON DUPLICATE KEY UPDATE "
               f"(cid, tenant_id) = {rhs}", dialect="mysql")

    def test_tuple_assignment_without_tenant_column_allowed(self):
        assert_scoped(rw("UPDATE orders SET (cid, total) = (1, 2) WHERE id = 1"))

    def test_quoted_tenant_column_assignment_refused_case_insensitively(self):
        with pytest.raises(PermissionError, match="tenant column"):
            rw("UPDATE orders SET `TENANT_ID` = 'TENANT_B'", dialect="mysql")

    def test_column_list_alias_on_protected_table_refused(self):
        """H3 — t AS x(a, b) renames columns, incl. the tenant column."""
        with pytest.raises(PermissionError, match="column-list alias"):
            rw("SELECT * FROM orders AS t(a, b, c)")
        with pytest.raises(PermissionError, match="column-list alias"):
            rw("SELECT * FROM items i JOIN orders o(x, y) ON 1=1")
        sql = "SELECT * FROM schema_migrations AS m(v)"
        assert rw(sql) == sql


class TestDialectSafety:
    """A dialect the rewriter does not know must not silently use the generic grammar."""

    def test_unknown_dialect_is_rejected(self):
        with pytest.raises(PermissionError, match="unknown SQL dialect"):
            rewrite("SELECT * FROM orders", "A", "tenant_id", lambda n, q: True, "postgres")

    def test_only_keyword_misparse_is_rejected_under_generic_grammar(self):
        # With no dialect, sqlglot reads `ONLY orders` as table ONLY aliased orders.
        with pytest.raises(PermissionError, match="ONLY"):
            rewrite("SELECT * FROM ONLY orders", "A", "tenant_id", lambda n, q: True, None)

    def test_only_scoped_under_postgresql(self):
        out = rewrite("SELECT * FROM ONLY orders", "A", "tenant_id", lambda n, q: n == "orders", "postgresql")
        assert "ONLY orders" in out and "orders.tenant_id = 'A'" in out
