"""rewrite_query must not be injectable through the tenant id (no DB needed)."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'middleware'))
from db_firewall import rewrite_query, validate_tenant_id  # noqa: E402

CONFIG = {"tenant_column": "tenant_id", "fail_mode": "closed",
          "protect": {"select": True, "insert": True, "update": True, "delete": True},
          "excluded_tables": ["_firewall_*"]}


def test_rewrite_escapes_single_quote():
    out = rewrite_query("SELECT * FROM orders", "A' OR '1'='1", CONFIG)
    assert out == "SELECT * FROM orders WHERE tenant_id = 'A'' OR ''1''=''1'"


def test_rewrite_plain_tenant_unchanged():
    assert rewrite_query("SELECT * FROM orders", "TENANT_A", CONFIG) == \
        "SELECT * FROM orders WHERE tenant_id = 'TENANT_A'"


@pytest.mark.parametrize("bad", ["A\x00B", "A\nB", "A\rB", "A\\B", "A\\", ""])
def test_rewrite_rejects_control_chars_and_empty(bad):
    with pytest.raises(ValueError):
        rewrite_query("SELECT * FROM orders", bad, CONFIG)


def test_validate_tenant_id_rejects_non_string():
    with pytest.raises(ValueError):
        validate_tenant_id(123)
