"""DB Firewall: Configuration: defaults, explicit-path loading, env overrides."""

import copy
import os
import re
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
    # Middleware audit: one row per DB-side tenant assignment (needs the
    # migration's audit table). Off by default: no table is required.
    "audit": {"enabled": False, "table_name": "_firewall_audit_log",
              "retention_days": 90, "log_queries": False},
    # DB users (exactly as the database reports them) whose connections the
    # middleware does not scope. Empty by default: managed Postgres (Supabase,
    # Neon, RDS) apps often connect as "postgres", so a built-in bypass list
    # would disable the firewall entirely.
    "excluded_users": [],
    # protect() fallbacks when no tenant is passed and the request has none,
    # tried in order. The request tenant always comes first and cannot be moved.
    "resolution": [
        {"source": "env_var", "variable": "TENANT_ID", "enabled": True},
        {"source": "db_user_map", "table": "_firewall_tenant_map", "enabled": True},
    ],
    # Per-engine options. use_* false: do not set the DB-side tenant context
    # (middleware-only). schema: what the scanner checks. audit_table: overrides
    # audit.table_name for that engine.
    "engines": {
        "postgresql": {"use_rls": True, "schema": "public", "policy_mode": "permissive",
                       "tenant_context": "signed", "harden_signals": False, "harden": False,
                       "app_role": None, "ddl_guard": False},
        "mysql": {"use_views": True, "schema": None},
        "sqlserver": {"use_rls": True, "schema": "dbo"},
        "oracle": {"use_vpd": True, "schema": None, "audit_table": "VPD_AUDIT_LOG"},
    },
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
    validate_config(config)
    return _apply_env_overrides(config)


RESOLUTION_SOURCES = ("env_var", "db_user_map", "session_var", "connection_param")
# No "#": MySQL reads it as a comment start.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)?$")


def check_table_name(name: str) -> str:
    """name, or ValueError when it is not a plain [schema.]table identifier."""
    if not _IDENT_RE.fullmatch(str(name)):
        raise ValueError(f"DB Firewall: unsafe table name: {name!r}")
    return name


def validate_config(config: dict) -> None:
    """Fail loudly on settings the firewall would otherwise misread."""
    for entry in config.get("resolution") or []:
        if not isinstance(entry, dict) or entry.get("source") not in RESOLUTION_SOURCES:
            raise ValueError(f"DB Firewall: resolution entries need source one of "
                             f"{RESOLUTION_SOURCES}, got {entry!r}")
        if entry.get("table") is not None:
            check_table_name(entry["table"])
    mode = ((config.get("engines") or {}).get("postgresql") or {}).get("policy_mode", "permissive")
    if not isinstance(mode, str) or mode.lower() not in ("permissive", "restrictive"):
        raise ValueError(f"DB Firewall: engines.postgresql.policy_mode must be permissive "
                         f"or restrictive, got {mode!r}")
    ctx = ((config.get("engines") or {}).get("postgresql") or {}).get("tenant_context", "signed")
    if not isinstance(ctx, str) or ctx.lower() not in ("signed", "plain"):
        raise ValueError(f"DB Firewall: engines.postgresql.tenant_context must be signed "
                         f"or plain, got {ctx!r}")
    pg = (config.get("engines") or {}).get("postgresql") or {}
    for flag in ("harden_signals", "harden", "ddl_guard"):
        if not isinstance(pg.get(flag, False), bool):
            raise ValueError(f"DB Firewall: engines.postgresql.{flag} must be true or false, got {pg.get(flag)!r}")
    if pg.get("app_role") is not None and (not isinstance(pg["app_role"], str) or not pg["app_role"]):
        raise ValueError(f"DB Firewall: engines.postgresql.app_role must be a role name, got {pg['app_role']!r}")
    users = config.get("excluded_users") or []
    if not isinstance(users, list) or not all(isinstance(u, str) and u for u in users):
        raise ValueError("DB Firewall: excluded_users must be a list of user names")
    tables = [(config.get("audit") or {}).get("table_name")]
    tables += [(o or {}).get("audit_table") for o in (config.get("engines") or {}).values()]
    for t in tables:
        if t is not None:
            check_table_name(t)


def engine_options(config: dict, engine: str) -> dict:
    """engines.<engine>, over the built-in defaults for that engine."""
    opts = dict(DEFAULT_CONFIG["engines"].get(engine, {}))
    opts.update((config.get("engines") or {}).get(engine) or {})
    return opts


def db_context_enabled(config: dict, engine: str) -> bool:
    """False when engines.<engine>.use_rls / use_views / use_vpd is false."""
    return all(v for k, v in engine_options(config, engine).items() if k.startswith("use_"))


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
