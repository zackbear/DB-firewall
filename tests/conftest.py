import pytest


@pytest.fixture(autouse=True)
def _no_firewall_env(monkeypatch):
    """Tests must not depend on DB_FIREWALL_* variables set in the shell."""
    for key in ("DB_FIREWALL_CONFIG", "DB_FIREWALL_TENANT_COLUMN",
                "DB_FIREWALL_FAIL_MODE", "DB_FIREWALL_REWRITER"):
        monkeypatch.delenv(key, raising=False)
