# 🛡️ DB Firewall — Universal AI Agent Tenant Isolation

**One config file. Any database. Any agent. Automatic enforcement.**

When you give an AI agent access to your database, it will happily run `SELECT * FROM orders` and return *everyone's* data. DB Firewall adds an **invisible WHERE clause** at the database layer so agents can only see their tenant's rows — no matter what SQL they generate.

> Based on ["The Invisible Firewall" by Arunkumar Moola Balaji](https://medium.com/@arunkumar.mb/the-invisible-firewall-securing-ai-agents-with-oracle-vpd-180b361e2478), extended to work universally across all databases and AI agent frameworks.

---

## Quick Start

### 1. Drop the config into your project root

```bash
cp config/firewall.yaml .db-firewall.yaml
```

### 2. Run the migration for your database

```bash
# PostgreSQL
psql -f migrations/001_postgresql.sql

# MySQL
mysql < migrations/002_mysql.sql

# SQL Server
sqlcmd -i migrations/003_sqlserver.sql

# Oracle
sqlplus sys/pass@db @migrations/004_oracle.sql
```

### 3. Wrap your connections

```python
from db_firewall import protect

conn = psycopg2.connect("postgresql://...")
safe_conn = protect(conn, tenant_id="TENANT_A")

# Every query is now silently filtered
cursor = safe_conn.cursor()
cursor.execute("SELECT * FROM orders")  # Returns ONLY Tenant A's orders
```

---

## How It Works

```bash
┌─────────────┐     ┌──────────────┐     ┌──────────────────────┐
│  AI Agent    │────▶│  DB Firewall │────▶│     Database          │
│  (MCP/Lang-  │     │  Middleware   │     │                      │
│   Chain/etc) │     │              │     │  ┌──────────────────┐ │
│              │     │  Rewrites:   │     │  │ Native RLS/VPD   │ │
│  SELECT *    │     │  adds WHERE  │     │  │ (second layer)   │ │
│  FROM orders │     │  tenant_id=  │     │  └──────────────────┘ │
│              │     │  'TENANT_A'  │     │                      │
└─────────────┘     └──────────────┘     └──────────────────────┘
                    ▲ Layer 1            ▲ Layer 2
                    Middleware            Database-native
                    (all engines)         (Postgres/SQL Server/Oracle)
```

**Two layers of defense:**

1. **Middleware** — Rewrites SQL before it reaches the database (works with ALL engines)
2. **Database-native** — RLS (Postgres, SQL Server) or VPD (Oracle) as a second enforcement layer

Even if the middleware is bypassed, the database-native layer still blocks cross-tenant access.

---

## Supported Databases

| Database | Native Security | Middleware | Migration Script |
| --- | --- | --- | --- |
| **PostgreSQL** 9.5+ | ✅ Row-Level Security | ✅ | `001_postgresql.sql` |
| **MySQL** 5.7+ / MariaDB | ❌ (Views + Triggers) | ✅ | `002_mysql.sql` |
| **SQL Server** 2016+ | ✅ Security Policies | ✅ | `003_sqlserver.sql` |
| **Oracle** 10g+ | ✅ Virtual Private Database | ✅ | `004_oracle.sql` |
| **SQLite** | ❌ | ✅ (middleware only) | None needed |

## Supported Frameworks

| Framework | Integration |
| --- | --- |
| **Raw DB-API** | `protect(connection)` |
| **SQLAlchemy** | `sqlalchemy_event_hooks(engine)` |
| **Django** | Middleware class |
| **FastAPI** | `fastapi_middleware(app)` |
| **Flask** | `flask_hooks(app)` |
| **MCP Servers** | `mcp_wrapper.py` stdio proxy |
| **LangChain** | Wrap the connection before passing to agent |

---

## MCP Server Protection

Wrap any MCP database server to auto-inject tenant isolation:

**Before (UNSAFE):**

```json
{
  "sql_mcp": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://..."]
  }
}
```

**After (PROTECTED):**

```json
{
  "sql_mcp": {
    "command": "python",
    "args": [
      "-m", "hooks.mcp_wrapper",
      "--tenant", "TENANT_A",
      "--", "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://..."
    ]
  }
}
```

---

## CI/CD Security Gate

Add the scanner to your pipeline to **fail the build** if unprotected tables exist:

```yaml
# GitHub Actions
- name: DB Firewall Security Scan
  run: python -m hooks.scanner --dsn $DATABASE_URL --strict

# GitLab CI
db-security-check:
  script: python -m hooks.scanner --dsn $DATABASE_URL --strict

# Docker
RUN python -m hooks.scanner --dsn $DATABASE_URL --strict
```

The scanner returns exit code 1 if ANY table with a `tenant_id` column is missing RLS/VPD protection.

---

## Configuration

Create `.db-firewall.yaml` in your project root:

```yaml
version: "1.0"
tenant_column: "tenant_id"
fail_mode: "closed"           # "closed" = no tenant → 0 rows (SAFE)

protect:
  select: true
  insert: true
  update: true
  delete: true

audit:
  enabled: true
  retention_days: 90

excluded_users:
  - "postgres"
  - "admin"
  - "_migrator"

excluded_tables:
  - "_firewall_*"
  - "schema_migrations"
  - "app_config"
```

---

## Security Principles

| Principle | Implementation |
| --- | --- |
| **Fail closed** | No tenant context = 0 rows returned. Never defaults to "show all". |
| **Defense in depth** | Middleware + database-native RLS/VPD. Two independent layers. |
| **Full DML protection** | SELECT, INSERT, UPDATE, AND DELETE are all filtered. |
| **Audit trail** | Every tenant assignment logged with session, IP, timestamp. |
| **Zero trust the agent** | The AI doesn't know about tenancy. The database enforces it. |
| **Connection pool safe** | Context cleared on logoff/disconnect to prevent leakage. |

---

## Project Structure

```bash
db-firewall/
├── config/
│   └── firewall.yaml            # Default configuration + documentation
├── migrations/
│   ├── 001_postgresql.sql        # PostgreSQL native RLS (auto-applies to all tables)
│   ├── 002_mysql.sql             # MySQL secure views + triggers
│   ├── 003_sqlserver.sql         # SQL Server security policies
│   └── 004_oracle.sql            # Oracle VPD (production-hardened)
├── middleware/
│   └── db_firewall.py            # Universal Python middleware (DB-agnostic)
├── hooks/
│   ├── mcp_wrapper.py            # MCP server stdio proxy with SQL rewriting
│   └── scanner.py                # CI/CD security scanner
├── tests/
│   └── test_firewall.py          # Full test suite
├── SKILL.md                      # Auto-integration trigger for AI workflows
└── README.md                     # This file
```

---

## License

MIT — Use this in every production system you build. No excuses.
