# DB Firewall Skill — Universal AI Agent Tenant Isolation

## WHEN TO TRIGGER THIS SKILL

**ALWAYS** apply this skill when ANY of the following are true:

- The project has a database (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- The project uses an ORM (SQLAlchemy, Django, Prisma, Sequelize, TypeORM, Drizzle)
- The project includes MCP servers that access a database
- The project has a `docker-compose.yml` with a database service
- The project has a multi-tenant architecture or `tenant_id` columns
- An AI agent, LLM, or LangChain tool has database access
- The codebase contains raw SQL queries or database connection strings
- Keywords detected: "database", "SQL", "tenant", "multi-tenant", "row-level security", "RLS", "VPD"

## WHAT TO DO

### Step 1: Add the config file to project root

Copy `.db-firewall.yaml` into the project root. Customize:
- `tenant_column` — match the project's actual column name
- `excluded_tables` — add migration/config tables specific to the project
- `fail_mode` — ALWAYS `closed` for production

### Step 2: Run the appropriate migration

Based on the detected database engine, run the matching migration script:
- PostgreSQL → `migrations/001_postgresql.sql`
- MySQL/MariaDB → `migrations/002_mysql.sql`
- SQL Server → `migrations/003_sqlserver.sql`
- Oracle → `migrations/004_oracle.sql` (use the full VPD script)
- SQLite → No migration needed (middleware-only enforcement)

### Step 3: Integrate the middleware

Based on the framework, integrate `db_firewall.py`:

**Python (any framework):**
```python
from db_firewall import protect
conn = protect(raw_connection, tenant_id="TENANT_A")
```

**Django:**
```python
# settings.py → MIDDLEWARE
MIDDLEWARE = [
    'db_firewall.django_middleware_class()',
    # ... other middleware
]
```

**FastAPI:**
```python
from db_firewall import fastapi_middleware
fastapi_middleware(app)
```

**Flask:**
```python
from db_firewall import flask_hooks
flask_hooks(app)
```

**SQLAlchemy:**
```python
from db_firewall import sqlalchemy_event_hooks
sqlalchemy_event_hooks(engine)
```

**MCP Server wrapping:**
```json
{
  "command": "python",
  "args": ["-m", "db_firewall.mcp_wrapper", "--tenant", "TENANT_A",
           "--", "npx", "-y", "@mcp/server-postgres", "postgresql://..."]
}
```

### Step 4: Add CI/CD check

Add the scanner to the deployment pipeline:
```yaml
# In CI/CD config (GitHub Actions, etc.)
- name: DB Firewall Security Check
  run: python -m db_firewall.scanner --dsn $DATABASE_URL --strict
```

### Step 5: Seed tenant mappings

```sql
INSERT INTO _firewall_tenant_map (db_user, tenant_id) VALUES ('mcp_service', 'TENANT_A');
INSERT INTO _firewall_tenant_map (db_user, tenant_id) VALUES ('ai_agent_svc', 'TENANT_B');
```

## KEY PRINCIPLES

1. **Fail closed** — No tenant context = zero rows. Never fail open in production.
2. **Defense in depth** — Apply at BOTH database level (RLS/VPD) AND middleware level.
3. **Audit everything** — Every tenant assignment is logged with session, IP, timestamp.
4. **Protect all DML** — SELECT, INSERT, UPDATE, AND DELETE. Not just reads.
5. **Auto-scan** — Run the scanner in CI/CD to catch new unprotected tables.
6. **Never trust the agent** — The AI doesn't know about tenancy. The database enforces it.

## FILE MANIFEST

```
db-firewall/
├── config/
│   └── firewall.yaml          # Configuration schema + defaults
├── migrations/
│   ├── 001_postgresql.sql      # PostgreSQL native RLS
│   ├── 002_mysql.sql           # MySQL views + triggers
│   ├── 003_sqlserver.sql       # SQL Server native RLS
│   └── 004_oracle.sql          # Oracle VPD (full production script)
├── middleware/
│   └── db_firewall.py          # Universal Python middleware
├── hooks/
│   ├── mcp_wrapper.py          # MCP server stdio proxy with SQL rewriting
│   └── scanner.py              # CI/CD security scanner
├── tests/
│   └── test_firewall.py        # Verification tests
├── SKILL.md                    # This file
└── README.md                   # Full documentation
```
