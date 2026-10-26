-- Test data for tests/test_oracle_live.py. Run as the schema owner BEFORE the
-- migration; tests/oracle_after_migration.sql runs after it.
BEGIN
  FOR t IN (SELECT table_name FROM user_tables
            WHERE table_name IN ('ORDERS', 'PLAIN', 'NOTES', 'LATE_TABLE',
                                 'VPD_AUDIT_LOG', 'TENANT_USER_MAP')) LOOP
    EXECUTE IMMEDIATE 'DROP TABLE ' || t.table_name || ' PURGE';
  END LOOP;
END;
/
CREATE TABLE ORDERS (id NUMBER PRIMARY KEY, org_id VARCHAR2(64) NOT NULL);
INSERT INTO ORDERS VALUES (1, 'A');
INSERT INTO ORDERS VALUES (2, 'B');
CREATE TABLE PLAIN (id NUMBER, tenant_id VARCHAR2(64));
CREATE TABLE NOTES (id NUMBER, body VARCHAR2(100));
COMMIT;
EXIT
