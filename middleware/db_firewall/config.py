"""DB Firewall: Configuration: defaults, explicit-path loading, env overrides."""

import copy
import os
import json
import logging
from pathlib import Path
from typing import Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger("db_firewall")

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_CONFIG = {
    "tenant_column": "tenant_id",
    "fail_mode": "closed",
    # "ast" (sqlglot, scopes CTEs/UNION/joins/INSERT..SELECT) or "regex" (legacy,
    # refuses those shapes). "ast" raises ImportError when sqlglot is missing.
    "rewriter": "ast",
    # INSERT ... (tenant_id) VALUES (%s): the bound value is the caller's, not
    # the firewall's. Refused unless this is true (then RLS WITH CHECK is the
    # only guard on it).
    "allow_tenant_placeholder": False,
    # Web integrations: trust the X-Tenant-ID request header only when an
    # upstream gateway sets it after authenticating the caller. Any client can
    # send that header, so it is off by default. ?tenant_id= is never trusted.
    "trust_tenant_header": False,
    "protect": {"select": True, "insert": True, "update": True, "delete": True},
    "audit": {"enabled": True, "table_name": "_firewall_audit_log", "retention_days": 90},
    # Empty by default: managed Postgres (Supabase, Neon, RDS) apps often connect
    # as "postgres", so a built-in bypass list would disable the firewall entirely.
    "excluded_users": [],
    "excluded_tables": [
        "_firewall_*", "schema_migrations", "alembic_version",
        "knex_migrations", "prisma_migrations", "flyway_schema_history",
        "__diesel_schema_migrations", "app_config", "feature_flags"
    ],
}


CONFIG_NAMES = (".db-firewall.yaml", ".db-firewall.yml", ".db-firewall.json")
_warned_orphan_config = False


def load_config(project_root: Optional[str] = None) -> dict:
    """Load config from an explicit path only, then apply env overrides.

    project_root (argument) or DB_FIREWALL_CONFIG (env var) may name a config
    file or a folder holding .db-firewall.yaml/.yml/.json. Neither set: built-in
    defaults. The current folder and home folder are never searched, so a file
    dropped there cannot change the policy. A named path with no config file,
    or a file that does not hold a mapping, raises: silently falling back to
    defaults could drop a custom tenant_column and leave tables unscoped.
    """
    config = copy.deepcopy(DEFAULT_CONFIG)
    explicit = project_root or os.environ.get("DB_FIREWALL_CONFIG")
    if not explicit:
        _warn_orphan_config()
        return _apply_env_overrides(config)
    cfg_path = _resolve_config_path(Path(explicit))
    config.update(_read_config_file(cfg_path))
    logger.info(f"DB Firewall: Loaded config from {cfg_path}")
    return _apply_env_overrides(config)


def _resolve_config_path(path: Path) -> Path:
    """A folder: the first config name in it. A file: itself. Missing: raise."""
    if path.is_dir():
        found = next((path / n for n in CONFIG_NAMES if (path / n).is_file()), None)
        if found is None:
            raise FileNotFoundError(f"DB Firewall: no {'/'.join(CONFIG_NAMES)} in {path}")
        return found
    if not path.is_file():
        raise FileNotFoundError(f"DB Firewall config not found: {path}")
    return path


def _read_config_file(path: Path) -> dict:
    if path.suffix != ".json" and not HAS_YAML:
        raise ImportError(f"PyYAML is required to read {path}: pip install pyyaml")
    with open(path) as f:
        try:
            data = json.load(f) if path.suffix == ".json" else yaml.safe_load(f)
        except ValueError as e:             # JSONDecodeError: name the file
            raise ValueError(f"DB Firewall: {path} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"DB Firewall: {path} must hold a mapping of settings, "
                         f"got {type(data).__name__}")
    return data


def _warn_orphan_config() -> None:
    """Upgrade aid: older versions read a config file from the current folder."""
    global _warned_orphan_config
    if _warned_orphan_config:
        return
    found = next((n for n in CONFIG_NAMES if (Path.cwd() / n).is_file()), None)
    if found:
        _warned_orphan_config = True
        logger.warning(f"DB Firewall: {found} in the current folder is NOT read. "
                       f"Set DB_FIREWALL_CONFIG={Path.cwd() / found} or pass "
                       f"load_config(project_root=...). Using built-in defaults: a "
                       f"custom tenant_column in that file is NOT applied, so tables "
                       f"that use it are unscoped.")


def _apply_env_overrides(config: dict) -> dict:
    """Environment variables win over both defaults and the config file."""
    for env, key in (("DB_FIREWALL_TENANT_COLUMN", "tenant_column"),
                     ("DB_FIREWALL_FAIL_MODE", "fail_mode"),
                     ("DB_FIREWALL_REWRITER", "rewriter")):
        if os.environ.get(env):
            config[key] = os.environ[env]
    return config
