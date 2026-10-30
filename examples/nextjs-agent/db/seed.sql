-- Two companies (tenants) in the same tables. The DB Firewall migration
-- (npm run db:migrate) then turns on row-level security for every table with
-- tenant_id. Keys include the tenant, so a duplicate or a missing parent never
-- tells one tenant about another's rows.
CREATE SCHEMA app;

CREATE TABLE app.customers (
    tenant_id text NOT NULL,
    id        int  NOT NULL,
    name      text NOT NULL,
    email     text NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, email)
);

CREATE TABLE app.invoices (
    tenant_id    text NOT NULL,
    id           int  NOT NULL,
    customer_id  int  NOT NULL,
    amount_cents int  NOT NULL CHECK (amount_cents > 0),
    status       text NOT NULL CHECK (status IN ('paid', 'unpaid')),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, customer_id) REFERENCES app.customers (tenant_id, id)
);

INSERT INTO app.customers VALUES
    ('acme',   1, 'Blue Mountain Coffee', 'orders@bluemountain.test'),
    ('acme',   2, 'Kingston Print Shop',  'hello@kingstonprint.test'),
    ('globex', 1, 'Montego Bay Resorts',  'finance@mbresorts.test'),
    ('globex', 2, 'Negril Divers',        'office@negrildivers.test');

INSERT INTO app.invoices VALUES
    ('acme',   1, 1, 125000, 'paid'),
    ('acme',   2, 1,  48000, 'unpaid'),
    ('acme',   3, 2,  23000, 'unpaid'),
    ('globex', 1, 1, 990000, 'unpaid'),
    ('globex', 2, 2,  15000, 'paid');

-- The role the MCP server connects as: a normal role (no superuser, no
-- BYPASSRLS), so the policies apply to it.
CREATE ROLE app_user LOGIN PASSWORD 'app_user_dev_password';
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_user;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
