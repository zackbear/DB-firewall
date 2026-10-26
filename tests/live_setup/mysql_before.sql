-- Test data for tests/test_mysql_live.py. Run in the test database first.
-- The test runs the migration itself through run_migration().
DROP VIEW IF EXISTS v_orders, v_vault, v_late_table;
DROP TABLE IF EXISTS orders, vault, plain, notes, late_table;
CREATE TABLE orders (id INT PRIMARY KEY, org_id VARCHAR(64));
INSERT INTO orders VALUES (1, 'A'), (2, 'B');
CREATE TABLE vault (id INT, org_id VARCHAR(64));     -- starts with "v": must still be protected
CREATE TABLE plain (id INT, tenant_id VARCHAR(64));
CREATE TABLE notes (id INT, body VARCHAR(100));
