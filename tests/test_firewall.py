"""
DB Firewall — Test Suite
=========================
Tests for SQL rewriting, tenant isolation, and fail-closed behavior.
Run with: pytest tests/test_firewall.py -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
from db_firewall import (
    rewrite_query, load_config, _extract_tables,
    _is_excluded_table, TenantContext, set_tenant,
    get_tenant, clear_tenant, tenant_scope
)


@pytest.fixture
def config():
    return {
        "tenant_column": "tenant_id",
        "fail_mode": "closed",
        "protect": {"select": True, "insert": True, "update": True, "delete": True},
        "excluded_tables": ["_firewall_*", "schema_migrations", "app_config"],
    }


# ============================================================================
# SQL Rewriting Tests
# ============================================================================

class TestQueryRewriting:

    def test_simple_select(self, config):
        sql = "SELECT * FROM orders"
        result = rewrite_query(sql, "TENANT_A", config)
        assert "tenant_id = 'TENANT_A'" in result
        assert "WHERE" in result.upper()

    def test_select_with_existing_where(self, config):
        sql = "SELECT * FROM orders WHERE status = 'active'"
        result = rewrite_query(sql, "TENANT_A", config)
        assert "tenant_id = 'TENANT_A'" in result
        assert "AND" in result.upper()

    def test_select_with_join(self, config):
        sql = "SELECT o.*, c.name FROM orders o JOIN customers c ON o.customer_id = c.id"
        result = rewrite_query(sql, "TENANT_A", config)
        assert "tenant_id = 'TENANT_A'" in result

    def test_select_with_order_by(self, config):
        sql = "SELECT * FROM orders ORDER BY created_at DESC"
        result = rewrite_query(sql, "TENANT_A", config)
        assert "tenant_id = 'TENANT_A'" in result
        assert result.index("tenant_id") < result.upper().index("ORDER BY")

    def test_update_statement(self, config):
        sql = "UPDATE orders SET status = 'shipped' WHERE id = 123"
        result = rewrite_query(sql, "TENANT_A", config)
        assert "tenant_id = 'TENANT_A'" in result

    def test_delete_statement(self, config):
        sql = "DELETE FROM orders WHERE id = 123"
        result = rewrite_query(sql, "TENANT_A", config)
        assert "tenant_id = 'TENANT_A'" in result

    def test_excluded_table_not_rewritten(self, config):
        sql = "SELECT * FROM schema_migrations"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == sql

    def test_firewall_tables_excluded(self, config):
        sql = "SELECT * FROM _firewall_audit_log"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == sql

    def test_non_dml_passthrough(self, config):
        sql = "CREATE TABLE test (id INT)"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == sql

    def test_empty_query_passthrough(self, config):
        assert rewrite_query("", "TENANT_A", config) == ""
        assert rewrite_query(None, "TENANT_A", config) is None

    def test_select_protection_disabled(self, config):
        config["protect"]["select"] = False
        sql = "SELECT * FROM orders"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == sql


# ============================================================================
# Table Extraction Tests
# ============================================================================

class TestTableExtraction:

    def test_simple_from(self):
        tables = _extract_tables("SELECT * FROM orders")
        assert "orders" in tables

    def test_join(self):
        tables = _extract_tables(
            "SELECT * FROM orders o JOIN customers c ON o.cid = c.id"
        )
        assert "orders" in tables
        assert "customers" in tables

    def test_insert_into(self):
        tables = _extract_tables("INSERT INTO orders (col) VALUES (1)")
        assert "orders" in tables

    def test_update(self):
        tables = _extract_tables("UPDATE orders SET x = 1")
        assert "orders" in tables

    def test_delete_from(self):
        tables = _extract_tables("DELETE FROM orders WHERE id = 1")
        assert "orders" in tables

    def test_quoted_table(self):
        tables = _extract_tables('SELECT * FROM "orders"')
        assert "orders" in tables


# ============================================================================
# Exclusion Pattern Tests
# ============================================================================

class TestExclusions:

    def test_exact_match(self):
        assert _is_excluded_table("schema_migrations", ["schema_migrations"])

    def test_glob_pattern(self):
        assert _is_excluded_table("_firewall_audit_log", ["_firewall_*"])
        assert _is_excluded_table("_firewall_tenant_map", ["_firewall_*"])

    def test_no_match(self):
        assert not _is_excluded_table("orders", ["_firewall_*", "schema_migrations"])


# ============================================================================
# Tenant Context Tests
# ============================================================================

class TestTenantContext:

    def test_set_get_clear(self):
        set_tenant("TENANT_A")
        assert get_tenant() == "TENANT_A"
        clear_tenant()
        assert get_tenant() is None

    def test_context_manager(self):
        with tenant_scope("TENANT_B"):
            assert get_tenant() == "TENANT_B"
        assert get_tenant() is None

    def test_require_raises_without_tenant(self):
        clear_tenant()
        with pytest.raises(PermissionError):
            TenantContext.require()

    def test_require_returns_tenant(self):
        set_tenant("TENANT_C")
        assert TenantContext.require() == "TENANT_C"
        clear_tenant()


# ============================================================================
# Fail-Closed Tests
# ============================================================================

class TestFailClosed:

    def test_no_tenant_blocks_in_closed_mode(self, config):
        """Without a tenant, fail_mode=closed should not rewrite (middleware blocks)."""
        sql = "SELECT * FROM orders"
        # rewrite_query with None tenant just returns original
        # The ProtectedCursor.execute() handles the actual blocking
        result = rewrite_query(sql, None, config)
        assert "tenant_id" not in result

    def test_fail_open_passes_through(self, config):
        config["fail_mode"] = "open"
        sql = "SELECT * FROM orders"
        result = rewrite_query(sql, None, config)
        assert result == sql


# ============================================================================
# Cross-Tenant Attack Prevention Tests
# ============================================================================

class TestSecurityAttacks:

    def test_union_injection_rejected(self, config):
        """A regex rewriter cannot scope both UNION branches (the first one used
        to pass through unfiltered), so the statement is refused outright."""
        sql = "SELECT * FROM orders UNION SELECT * FROM orders WHERE tenant_id = 'TENANT_B'"
        with pytest.raises(PermissionError, match="unsupported statement shape"):
            rewrite_query(sql, "TENANT_A", config)

    @pytest.mark.parametrize("sql", [
        "SELECT a FROM orders INTERSECT SELECT a FROM orders",
        "SELECT a FROM orders EXCEPT SELECT a FROM orders WHERE tenant_id = 'B'",
        "WITH o AS (SELECT * FROM orders) SELECT * FROM o",
        "(SELECT * FROM orders)",
        "TABLE orders",
        "UPDATE orders SET status = 'x' FROM customers WHERE orders.cid = customers.id",
        "DELETE FROM orders USING customers WHERE orders.cid = customers.id",
        "SELECT * FROM orders; DELETE FROM orders",
        "SELECT * FROM orders WHERE note = 'unterminated",
        "SELECT * FROM orders /* unterminated",
    ], ids=["intersect", "except", "cte", "leading-paren", "table-cmd",
            "update-from", "delete-using", "multi-statement",
            "unterminated-literal", "unterminated-comment"])
    def test_unsafe_shapes_rejected(self, config, sql):
        with pytest.raises(PermissionError, match="unsupported statement shape"):
            rewrite_query(sql, "TENANT_A", config)

    def test_unsafe_shape_on_unprotected_table_passes_through(self, config):
        for sql in ("(SELECT * FROM schema_migrations)",
                    "TABLE schema_migrations",
                    "SELECT v FROM schema_migrations UNION SELECT v FROM _firewall_audit_log"):
            assert rewrite_query(sql, "TENANT_A", config) == sql

    def test_union_inside_string_literal_still_allowed_and_filtered(self, config):
        sql = "SELECT * FROM orders WHERE note = 'a UNION b' ORDER BY id"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == ("SELECT * FROM orders WHERE tenant_id = 'TENANT_A' AND "
                          "note = 'a UNION b' ORDER BY id")

    def test_union_inside_comment_still_allowed_and_filtered(self, config):
        sql = "SELECT * FROM orders /* UNION SELECT * FROM orders */"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == "SELECT * FROM orders WHERE tenant_id = 'TENANT_A' /* UNION SELECT * FROM orders */"

    def test_where_inside_literal_does_not_misplace_predicate(self, config):
        sql = "SELECT * FROM orders WHERE note = 'x WHERE y' AND status = 'a'"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == ("SELECT * FROM orders WHERE tenant_id = 'TENANT_A' AND "
                          "note = 'x WHERE y' AND status = 'a'")

    def test_where_in_select_list_subquery_does_not_capture_predicate(self, config):
        sql = "SELECT (SELECT count(*) FROM items WHERE qty > 1) FROM orders"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == sql + " WHERE tenant_id = 'TENANT_A'"

    def test_leading_comment_is_still_dml(self, config):
        sql = "/* hint */ SELECT * FROM orders"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == "/* hint */ SELECT * FROM orders WHERE tenant_id = 'TENANT_A'"

    def test_subquery_still_filtered(self, config):
        sql = "SELECT * FROM orders WHERE id IN (SELECT id FROM orders)"
        result = rewrite_query(sql, "TENANT_A", config)
        assert "tenant_id = 'TENANT_A'" in result

    def test_sql_comment_bypass_attempt(self, config):
        """The predicate must land BEFORE a trailing comment, not inside it."""
        sql = "SELECT * FROM orders -- WHERE tenant_id = 'TENANT_B'"
        result = rewrite_query(sql, "TENANT_A", config)
        assert result == "SELECT * FROM orders WHERE tenant_id = 'TENANT_A' -- WHERE tenant_id = 'TENANT_B'"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
