"""
DB Firewall — MCP Server Wrapper
==================================
Wraps any MCP server that provides database access (SQLcl, Postgres MCP,
MySQL MCP, etc.) with automatic tenant isolation.

Usage in Claude Desktop config:

  Instead of:
    "sql_mcp": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://..."]
    }

  Use:
    "sql_mcp": {
      "command": "python",
      "args": ["-m", "hooks.mcp_wrapper", "--tenant", "TENANT_A",
               "--", "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://..."]
    }

The wrapper sits between Claude and the MCP server. Every string in a
tools/call that looks like SQL, under any key and at any depth, is scoped to
the tenant. SQL that cannot be scoped gets a JSON-RPC error and never reaches
the server. Lines that are not JSON are dropped.

Defence in depth: run the migrations and give the wrapped server a database
role without BYPASSRLS, so row-level security still blocks what a missed
string would reach.
"""

import sys
import json
import subprocess
import threading
import re
import os
from typing import Optional, Tuple

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from middleware.db_firewall import rewrite_query, load_config, validate_tenant_id

# First words of statements PostgreSQL, MySQL, SQL Server, Oracle or SQLite will
# run. A string starting with one of them is treated as SQL and scoped or refused.
SQL_KEYWORDS = frozenset("""
    ABORT ALTER ANALYZE ANALYSE ATTACH BACKUP BEGIN BINLOG BULK CACHE CALL CHECKPOINT
    CHECKSUM CLOSE CLUSTER COMMENT COMMIT COPY CREATE DBCC DEALLOCATE DECLARE DELETE
    DENY DESC DESCRIBE DETACH DISCARD DO DROP END EXEC EXECUTE EXPLAIN FETCH FLUSH
    GOTO GRANT HANDLER IF IMPORT INSERT INSTALL KILL LISTEN LOAD LOCK MERGE MOVE
    NOTIFY OPEN OPTIMIZE PRAGMA PREPARE PRINT PURGE RAISERROR REASSIGN REFRESH
    REINDEX RELEASE RENAME REPAIR REPLACE RESET RESTORE RETURN REVOKE ROLLBACK
    SAVEPOINT SECURITY SELECT SET SHOW START TABLE THROW TRUNCATE UNINSTALL UNLISTEN
    UPDATE UPSERT USE VACUUM VALUES WAITFOR WHILE WITH XA
""".split())

_LEADING_NOISE = re.compile(r"(?:\s+|--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/|[;(])*", re.S)
_FIRST_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
_ANY_KEYWORD = re.compile(r"\b(?:" + "|".join(sorted(SQL_KEYWORDS)) + r")\b", re.I)


def looks_like_sql(s: str) -> bool:
    """True when the string may run as SQL.

    ponytail: keyword heuristic. Prose that starts with a keyword ("Update the
    report") is treated as SQL and rewritten or refused. Upgrade path: a
    per-tool list of SQL argument names in config.
    """
    if any(mark in s for mark in ("/*", "--", "#")):
        # Comments can hide where a statement starts (nested /* */ in
        # PostgreSQL, /*! */ executable comments in MySQL): any keyword counts.
        return bool(_ANY_KEYWORD.search(s))
    word = _FIRST_WORD.match(s, _LEADING_NOISE.match(s).end())
    return bool(word) and word.group().upper() in SQL_KEYWORDS


def _scope(value, tenant_id: str, config: dict):
    """Rewrite every SQL-looking string at any depth. Raises when one cannot be scoped."""
    if isinstance(value, dict):
        return {k: _scope(v, tenant_id, config) for k, v in value.items()}
    if isinstance(value, list):
        return [_scope(v, tenant_id, config) for v in value]
    if isinstance(value, str) and looks_like_sql(value):
        rewritten = rewrite_query(value, tenant_id, config)
        if rewritten != value:
            print(f"[DB Firewall] Rewrote SQL: {value[:80]}... -> {rewritten[:80]}...",
                  file=sys.stderr)
        return rewritten
    return value


def intercept_sql_in_tool_call(message: dict, tenant_id: str, config: dict) -> dict:
    """
    Scope every SQL-looking string in a tools/call request's params (the tool
    name excepted), at any depth and under any key. Raises PermissionError or
    ValueError when a string cannot be safely scoped.
    """
    if message.get("method") != "tools/call":
        return message
    params = message.get("params")
    if isinstance(params, dict):
        message["params"] = {k: (v if k == "name" else _scope(v, tenant_id, config))
                             for k, v in params.items()}
    return message


def _error(message: dict, exc: Exception) -> Optional[dict]:
    """JSON-RPC error reply, or None for a notification (no id)."""
    if "id" not in message:
        return None
    return {"jsonrpc": "2.0", "id": message["id"],
            "error": {"code": -32000, "message": f"DB Firewall: refused: {exc}"}}


def _process(message, tenant_id: str, config: dict) -> Tuple[Optional[dict], Optional[dict]]:
    if not isinstance(message, dict):
        raise ValueError("not a JSON-RPC object")
    try:
        return intercept_sql_in_tool_call(message, tenant_id, config), None
    except Exception as exc:            # fail closed on anything unexpected too
        print(f"[DB Firewall] Refused tool call: {exc}", file=sys.stderr)
        return None, _error(message, exc)


def handle_line(raw: bytes, tenant_id: str, config: dict) -> Tuple[Optional[bytes], Optional[bytes]]:
    """One line from the client -> (bytes for the child, bytes for the client).

    A line that is not a JSON object or array is dropped, never passed through:
    the child may parse it differently (for example, invalid UTF-8 decoded with
    replacement characters) and run SQL this proxy never saw.
    """
    if not raw.strip():
        return None, None
    try:
        message = json.loads(raw)
        if isinstance(message, list):
            results = [_process(m, tenant_id, config) for m in message]
            fwd = [f for f, _ in results if f is not None]
            err = [e for _, e in results if e is not None]
            return ((json.dumps(fwd) + "\n").encode() if fwd else None,
                    (json.dumps(err) + "\n").encode() if err else None)
        fwd, err = _process(message, tenant_id, config)
    except (ValueError, UnicodeDecodeError) as exc:   # JSONDecodeError is a ValueError
        print(f"[DB Firewall] Dropped unparseable line: {exc}", file=sys.stderr)
        return None, None
    return ((json.dumps(fwd) + "\n").encode() if fwd is not None else None,
            (json.dumps(err) + "\n").encode() if err is not None else None)


def proxy_stdio(tenant_id: str, child_command: list, config: dict):
    """
    Start the real MCP server as a subprocess and proxy stdio,
    intercepting tool calls to inject tenant isolation.
    """
    proc = subprocess.Popen(
        child_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        bufsize=0
    )
    out_lock = threading.Lock()         # replies and child output share stdout

    def write_out(data: bytes):
        with out_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    def forward_stdin():
        """Read from our stdin (Claude), scope SQL, send to child MCP server."""
        for line in sys.stdin.buffer:
            fwd, reply = handle_line(line, tenant_id, config)
            if fwd:
                proc.stdin.write(fwd)
                proc.stdin.flush()
            if reply:
                write_out(reply)
        proc.stdin.close()

    def forward_stdout():
        """Read from child MCP server, forward to our stdout (Claude)."""
        for line in proc.stdout:
            write_out(line)

    stdin_thread = threading.Thread(target=forward_stdin, daemon=True)
    stdout_thread = threading.Thread(target=forward_stdout, daemon=True)

    stdin_thread.start()
    stdout_thread.start()

    proc.wait()
    stdout_thread.join(timeout=5)       # drain what the child wrote before exiting
    sys.exit(proc.returncode)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DB Firewall MCP Wrapper — Intercepts SQL in MCP tool calls"
    )
    parser.add_argument("--tenant", required=True, help="Tenant ID to enforce")
    parser.add_argument("--config", help="Path to .db-firewall.yaml")
    parser.add_argument(
        "child_command", nargs=argparse.REMAINDER,
        help="The real MCP server command (after --)"
    )

    args = parser.parse_args()

    # Strip leading "--" from child command
    child_cmd = args.child_command
    if child_cmd and child_cmd[0] == "--":
        child_cmd = child_cmd[1:]

    if not child_cmd:
        print("Error: No child MCP server command provided.", file=sys.stderr)
        print("Usage: python -m mcp_wrapper --tenant TENANT_A -- npx -y @mcp/server-postgres ...",
              file=sys.stderr)
        sys.exit(1)

    try:
        validate_tenant_id(args.tenant)
    except ValueError as e:
        print(f"Error: invalid --tenant: {e}", file=sys.stderr)
        sys.exit(2)

    config = load_config(args.config)

    print(f"[DB Firewall] Tenant: {args.tenant}", file=sys.stderr)
    print(f"[DB Firewall] Wrapping: {' '.join(child_cmd)}", file=sys.stderr)
    print(f"[DB Firewall] Fail mode: {config.get('fail_mode', 'closed')}", file=sys.stderr)

    proxy_stdio(args.tenant, child_cmd, config)
