import os

import pytest

# A fixed signing key for every test that migrates or sets a PostgreSQL tenant.
# Set at import, before any (module-scoped) fixture runs a migration.
TEST_TENANT_KEY = "5a" * 32
os.environ["DB_FIREWALL_TENANT_KEY"] = TEST_TENANT_KEY


@pytest.fixture(autouse=True)
def _no_firewall_env(monkeypatch):
    """Tests must not depend on DB_FIREWALL_* variables set in the shell."""
    for key in ("DB_FIREWALL_CONFIG", "DB_FIREWALL_TENANT_COLUMN",
                "DB_FIREWALL_FAIL_MODE", "DB_FIREWALL_REWRITER"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DB_FIREWALL_TENANT_KEY", TEST_TENANT_KEY)   # undo a test's delenv
