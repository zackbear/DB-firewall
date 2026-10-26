-- Run as the schema owner AFTER migrations/004_oracle.sql (see test_oracle_live.py).
CREATE TABLE LATE_TABLE (id NUMBER, org_id VARCHAR2(64));
INSERT INTO TENANT_USER_MAP (db_user, tenant_id) VALUES (USER, 'A');
COMMIT;
EXIT
