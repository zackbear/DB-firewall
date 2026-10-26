-- Test data for tests/test_sqlserver_live.py. Run in the test database BEFORE
-- the migration. Also drops what an earlier run left behind.
DECLARE @p NVARCHAR(256), @s NVARCHAR(MAX);
DECLARE pc CURSOR FOR SELECT QUOTENAME(SCHEMA_NAME(schema_id)) + '.' + QUOTENAME(name) FROM sys.security_policies;
OPEN pc; FETCH NEXT FROM pc INTO @p;
WHILE @@FETCH_STATUS = 0 BEGIN SET @s = 'DROP SECURITY POLICY ' + @p; EXEC sp_executesql @s; FETCH NEXT FROM pc INTO @p; END
CLOSE pc; DEALLOCATE pc;
DROP TABLE IF EXISTS dbo.orders, dbo.plain, dbo.notes, dbo.late_table;
CREATE TABLE dbo.orders (id INT PRIMARY KEY, org_id NVARCHAR(64) NOT NULL);
INSERT INTO dbo.orders VALUES (1, N'A'), (2, N'B');
CREATE TABLE dbo.plain (id INT, tenant_id NVARCHAR(64));
CREATE TABLE dbo.notes (id INT, body NVARCHAR(100));
