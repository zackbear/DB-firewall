"""
Attacks that tried to reach tenant B as tenant A, collected from the PR 10
reviews. tests/test_mysql_live.py runs each through protect() as tenant A and
compares the result, or the state it leaves, with the same SQL run raw where
only tenant A's rows exist. Anything else (a tenant B value in any form, a
changed B row, a changed tenant variable) is a bypass. Refusals are fine.

Tables: orders(id, org_id) with rows (1, 'A') and (2, 'B'); notes has no
tenant column. Add every new bypass here before fixing it.
"""

# (label, sql): reads aimed at row (2, 'B')
READS = [
    ("baseline", "SELECT id, org_id FROM orders"),
    ("comma after derived table", "SELECT o.id, o.org_id FROM (SELECT 1) t, orders o"),
    ("comma join", "SELECT o.id, o.org_id FROM notes n, orders o"),
    ("comma with AS", "SELECT o.id, o.org_id FROM (SELECT 1) AS t, orders AS o"),
    ("STRAIGHT_JOIN", "SELECT o.id, o.org_id FROM (SELECT 1) t STRAIGHT_JOIN orders o"),
    ("parenthesised table", "SELECT id, org_id FROM (orders)"),
    ("parenthesised, no space", "SELECT id, org_id FROM(orders)o"),
    ("scalar subquery, no FROM", "SELECT (SELECT org_id FROM orders WHERE id = 2) x"),
    ("scalar subquery, derived FROM", "SELECT (SELECT org_id FROM orders WHERE id = 2) x FROM (SELECT 1) t"),
    ("UNION", "SELECT id, org_id FROM orders UNION SELECT id, org_id FROM orders"),
    ("# comment after appended WHERE", "SELECT id, org_id FROM orders # x"),
    ("-- without space", "SELECT id, org_id FROM orders --x"),
    ("CTE", "WITH x AS (SELECT * FROM orders) SELECT id, org_id FROM x"),
    ("FOR UPDATE", "SELECT id, org_id FROM orders FOR UPDATE"),
    ("nested join parens", "SELECT o.id, o.org_id FROM (notes n, orders o)"),
    ("LATERAL", "SELECT o.id, o.org_id FROM (SELECT 1) t, LATERAL (SELECT * FROM orders) o"),
    ("TABLE command", "TABLE orders"),
    ("derived then table", "SELECT * FROM (SELECT 1) t, orders"),
    ("executable comment widens WHERE", "SELECT id, org_id FROM orders WHERE id > 0 /*! OR 1=1 */"),
    ("-- without space is not a comment", "SELECT id, org_id FROM orders --id-2"),
    ("scalar subquery over a scoped FROM", "SELECT (SELECT org_id FROM orders WHERE id = 2) x FROM orders"),
    ("versioned executable comment", "SELECT id FROM orders /*!80000 , (SELECT org_id FROM orders WHERE id = 2) */"),
    ("MariaDB executable comment", "SELECT id, org_id FROM orders WHERE id > 0 /*M! OR 1=1 */"),
    ("BINARY cast of the tenant", "SELECT id, BINARY org_id FROM orders"),
    ("GROUP_CONCAT", "SELECT GROUP_CONCAT(org_id) FROM orders"),
    ("LOWER of the tenant", "SELECT (SELECT LOWER(org_id) FROM orders WHERE id = 2) x FROM orders"),
    ("HEX of the tenant", "SELECT (SELECT HEX(org_id) FROM orders WHERE id = 2) x FROM orders"),
    ("CAST of the id", "SELECT (SELECT CAST(id AS CHAR) FROM orders WHERE id = 2) x FROM orders"),
]

# (label, sql): writes and bypass attempts
WRITES = [
    ("set variable behind #", "SET @x = 1 # @_fw_tenant_id = 'B'"),
    ("set variable, multi-assignment", "SET @a = 1, @_fw_tenant_id = '__BYPASS__'"),
    ("set variable, escaped name", "SET @'_fw_tenant_i\\d' = '__BYPASS__'"),
    ("set variable, accented name", "SET @_fw_tenänt_id = '__BYPASS__'"),
    ("assign variable in SELECT", "SELECT @'_fw_tenant_i\\d' := '__BYPASS__'"),
    ("insert B", "INSERT INTO orders VALUES (50, 'B')"),
    ("insert B from derived table", "INSERT INTO orders (id, org_id) SELECT 51, 'B' FROM (SELECT 1) t"),
    ("multi-table update", "UPDATE orders o, (SELECT 1) t SET o.id = 99 WHERE o.id = 2"),
    ("update behind #", "UPDATE orders SET id = 99 WHERE id = 2 # x"),
    ("multi-table delete", "DELETE o FROM (SELECT 1) t, orders o WHERE o.id = 2"),
    ("delete behind #", "DELETE FROM orders WHERE id = 2 # x"),
    ("update all behind #", "UPDATE orders SET id = id + 100 # x"),
    ("delete all behind #", "DELETE FROM orders # x"),
    ("executable comment delete", "/*!DELETE FROM orders*/"),
    ("retag own row as B", "UPDATE orders SET org_id = 'B' WHERE id = 1"),
    ("retag own row as C", "UPDATE orders SET org_id = 'C' WHERE id = 1"),
    ("null the tenant", "UPDATE orders SET org_id = NULL WHERE id = 1"),
    ("insert NULL tenant", "INSERT INTO orders VALUES (52, NULL)"),
    ("set variable, backticked name", "SET @`_fw_tenant_id` = 'B'"),
    ('set variable, double-quoted name', 'SET @"_fw_tenant_id" = \'B\''),
    ("pool hook as the app user (mapped to B)", "CALL _firewall_init_connection()"),
    ("PREPARE", "PREPARE s FROM 'SET @_fw_tenant_id = 1'"),
    ("DO", "DO (SELECT 1)"),
    ("HANDLER", "HANDLER orders OPEN"),
    ("MariaDB executable comment delete", "/*M!DELETE FROM orders*/"),
    ("copy every tenant into notes", "INSERT INTO notes (id, body) SELECT id, org_id FROM orders"),
    ("copy B into notes by subquery",
     "INSERT INTO notes (id, body) SELECT 7, (SELECT org_id FROM orders WHERE id = 2) FROM orders"),
]
