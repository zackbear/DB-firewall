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
      "args": ["-m", "db_firewall.mcp_wrapper", "--tenant", "TENANT_A",
               "--", "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://..."]
    }

The wrapper sits between Claude and the MCP server, intercepting all
tool calls that contain SQL and rewriting them with tenant isolation.
"""

import sys
import json
import subprocess
import threading
import re
import os
from typing import Optional

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from middleware.db_firewall import rewrite_query, load_config


def intercept_sql_in_tool_call(message: dict, tenant_id: str, config: dict) -> dict:
    """
    Inspect a JSON-RPC message for SQL strings in tool call arguments.
    If found, rewrite them with tenant isolation.
    """
    if message.get("method") != "tools/call":
        return message

    params = message.get("params", {})
    arguments = params.get("arguments", {})

    # Common argument names that contain SQL
    sql_keys = ["query", "sql", "statement", "command", "code"]

    for key in sql_keys:
        if key in arguments and isinstance(arguments[key], str):
            original = arguments[key]
            rewritten = rewrite_query(original, tenant_id, config)
            if rewritten != original:
                arguments[key] = rewritten
                # Log the rewrite to stderr (visible in Claude Desktop logs)
                print(
                    f"[DB Firewall] Rewrote SQL in {key}: "
                    f"{original[:80]}... → {rewritten[:80]}...",
                    file=sys.stderr
                )

    return message


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

    def forward_stdin():
        """Read from our stdin (Claude), rewrite SQL, send to child MCP server."""
        for line in sys.stdin.buffer:
            try:
                message = json.loads(line)
                message = intercept_sql_in_tool_call(message, tenant_id, config)
                modified_line = json.dumps(message) + "\n"
                proc.stdin.write(modified_line.encode())
                proc.stdin.flush()
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Pass through non-JSON lines unmodified
                proc.stdin.write(line)
                proc.stdin.flush()

        proc.stdin.close()

    def forward_stdout():
        """Read from child MCP server, forward to our stdout (Claude)."""
        for line in proc.stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    stdin_thread = threading.Thread(target=forward_stdin, daemon=True)
    stdout_thread = threading.Thread(target=forward_stdout, daemon=True)

    stdin_thread.start()
    stdout_thread.start()

    proc.wait()
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

    config = load_config(args.config)

    print(f"[DB Firewall] Tenant: {args.tenant}", file=sys.stderr)
    print(f"[DB Firewall] Wrapping: {' '.join(child_cmd)}", file=sys.stderr)
    print(f"[DB Firewall] Fail mode: {config.get('fail_mode', 'closed')}", file=sys.stderr)

    proxy_stdio(args.tenant, child_cmd, config)
