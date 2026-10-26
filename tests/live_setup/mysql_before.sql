-- Test data for tests/test_mysql_live.py. Run in the test database BEFORE
-- migrations/002_mysql.sql (with @dbfw_tenant_column = 'org_id').
DROP VIEW IF EXISTS v_orders, v_late_table;
DROP TABLE IF EXISTS orders, plain, notes, late_table;
CREATE TABLE orders (id INT PRIMARY KEY, org_id VARCHAR(64) NOT NULL);
INSERT INTO orders VALUES (1, 'A'), (2, 'B');
CREATE TABLE plain (id INT, tenant_id VARCHAR(64));
CREATE TABLE notes (id INT, body VARCHAR(100));
