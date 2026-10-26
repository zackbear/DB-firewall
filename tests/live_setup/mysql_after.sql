-- Run AFTER the migration.
DELETE FROM _firewall_tenant_map;
INSERT INTO _firewall_tenant_map (db_user, tenant_id) VALUES (SUBSTRING_INDEX(CURRENT_USER(), '@', 1), 'A');
