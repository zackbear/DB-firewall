-- Run as the schema owner AFTER migrations/004_oracle.sql (see test_oracle_live.py).
INSERT INTO TENANT_USER_MAP (db_user, tenant_id) VALUES (USER, 'A');
COMMIT;
EXIT
