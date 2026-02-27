-- ============================================================================
-- ORACLE VPD: AI AGENT TENANT ISOLATION — PRODUCTION BUILD
-- ============================================================================
-- Purpose:  Enforce row-level security at the database layer so that
--           AI agents (MCP servers, LangChain, SQLcl, JDBC) can NEVER
--           access data outside the authenticated tenant's scope.
--
-- Based on: "The Invisible Firewall" — Arunkumar Moola Balaji
-- Adapted:  Production-hardened with audit logging, error handling,
--           multi-table support, and DML protection.
--
-- Usage:    Run as SYS or a DBA-privileged user.
--           Customize TENANT_TABLES and SCHEMA_OWNER before deploying.
-- ============================================================================


-- ============================================================================
-- 0. CONFIGURATION — EDIT THESE BEFORE DEPLOYING
-- ============================================================================

DEFINE SCHEMA_OWNER   = 'APP_USER'
DEFINE CONTEXT_NAME   = 'CTX_SAAS'
DEFINE PACKAGE_NAME   = 'PKG_SAAS_SECURITY'
DEFINE POLICY_PREFIX   = 'VPD_TENANT_ISOLATION'
DEFINE AUDIT_TABLE     = 'VPD_AUDIT_LOG'


-- ============================================================================
-- 1. CREATE THE APPLICATION CONTEXT ("Secure Vault")
-- ============================================================================
-- This is the in-memory session store that holds the current tenant identity.
-- Only our trusted package can write to it.

CREATE OR REPLACE CONTEXT &CONTEXT_NAME
  USING &SCHEMA_OWNER..&PACKAGE_NAME;


-- ============================================================================
-- 2. AUDIT LOG TABLE
-- ============================================================================
-- Track every tenant context assignment for compliance (GDPR, HIPAA, SOC2).

CREATE TABLE &SCHEMA_OWNER..&AUDIT_TABLE (
  audit_id        NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  session_id      NUMBER          NOT NULL,
  db_user         VARCHAR2(128)   NOT NULL,
  os_user         VARCHAR2(128),
  ip_address      VARCHAR2(64),
  tenant_id       VARCHAR2(128)   NOT NULL,
  assigned_at     TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
  auth_method     VARCHAR2(50)    DEFAULT 'LOGON_TRIGGER',
  module          VARCHAR2(256),
  action          VARCHAR2(256)
);

CREATE INDEX &SCHEMA_OWNER..idx_vpd_audit_tenant
  ON &SCHEMA_OWNER..&AUDIT_TABLE (tenant_id, assigned_at);

CREATE INDEX &SCHEMA_OWNER..idx_vpd_audit_session
  ON &SCHEMA_OWNER..&AUDIT_TABLE (session_id);


-- ============================================================================
-- 3. TENANT MAPPING TABLE
-- ============================================================================
-- Maps database users → tenant IDs. This is the source of truth.
-- For AI agents, each agent connection should have a dedicated DB user
-- or use a proxy user mapped here.

CREATE TABLE &SCHEMA_OWNER..TENANT_USER_MAP (
  db_user         VARCHAR2(128)   NOT NULL,
  tenant_id       VARCHAR2(128)   NOT NULL,
  is_active       CHAR(1)         DEFAULT 'Y' CHECK (is_active IN ('Y','N')),
  created_at      TIMESTAMP       DEFAULT SYSTIMESTAMP,
  updated_at      TIMESTAMP       DEFAULT SYSTIMESTAMP,
  CONSTRAINT pk_tenant_user_map PRIMARY KEY (db_user)
);

-- Seed your tenants:
-- INSERT INTO TENANT_USER_MAP (db_user, tenant_id) VALUES ('AI_AGENT_TENANT_A', 'TENANT_A');
-- INSERT INTO TENANT_USER_MAP (db_user, tenant_id) VALUES ('AI_AGENT_TENANT_B', 'TENANT_B');
-- INSERT INTO TENANT_USER_MAP (db_user, tenant_id) VALUES ('MCP_SERVICE_USER',  'TENANT_A');
-- COMMIT;


-- ============================================================================
-- 4. TRUSTED SECURITY PACKAGE
-- ============================================================================
-- This is the ONLY code that can write to the context.
-- Contains: set_tenant, clear_tenant, get_tenant, validate_tenant.

CREATE OR REPLACE PACKAGE &SCHEMA_OWNER..&PACKAGE_NAME AS

  -- Set the tenant context for the current session
  PROCEDURE set_tenant(p_tenant_id IN VARCHAR2);

  -- Clear the tenant context (for connection pool cleanup)
  PROCEDURE clear_tenant;

  -- Read the current tenant (for debugging / audit)
  FUNCTION get_tenant RETURN VARCHAR2;

  -- Validate that a tenant mapping exists for the current user
  FUNCTION validate_tenant RETURN VARCHAR2;

  -- Called by logon trigger — auto-resolves tenant from user mapping
  PROCEDURE auto_assign_tenant;

END &PACKAGE_NAME;
/


CREATE OR REPLACE PACKAGE BODY &SCHEMA_OWNER..&PACKAGE_NAME AS

  -- --------------------------------------------------------
  -- SET TENANT: Assigns tenant context + writes audit log
  -- --------------------------------------------------------
  PROCEDURE set_tenant(p_tenant_id IN VARCHAR2) IS
  BEGIN
    IF p_tenant_id IS NULL THEN
      RAISE_APPLICATION_ERROR(-20001, 'VPD: tenant_id cannot be NULL');
    END IF;

    DBMS_SESSION.SET_CONTEXT('&CONTEXT_NAME', 'tenant_id', p_tenant_id);

    -- Audit the assignment
    INSERT INTO &SCHEMA_OWNER..&AUDIT_TABLE
      (session_id, db_user, os_user, ip_address, tenant_id, auth_method, module, action)
    VALUES (
      SYS_CONTEXT('USERENV', 'SESSIONID'),
      SYS_CONTEXT('USERENV', 'SESSION_USER'),
      SYS_CONTEXT('USERENV', 'OS_USER'),
      SYS_CONTEXT('USERENV', 'IP_ADDRESS'),
      p_tenant_id,
      'SET_TENANT',
      SYS_CONTEXT('USERENV', 'MODULE'),
      SYS_CONTEXT('USERENV', 'ACTION')
    );
    COMMIT;

  EXCEPTION
    WHEN OTHERS THEN
      -- Log but don't block — audit failure shouldn't prevent access
      NULL;
  END set_tenant;

  -- --------------------------------------------------------
  -- CLEAR TENANT: For connection pool reset / logout
  -- --------------------------------------------------------
  PROCEDURE clear_tenant IS
  BEGIN
    DBMS_SESSION.CLEAR_CONTEXT('&CONTEXT_NAME');
  END clear_tenant;

  -- --------------------------------------------------------
  -- GET TENANT: Returns current session tenant
  -- --------------------------------------------------------
  FUNCTION get_tenant RETURN VARCHAR2 IS
  BEGIN
    RETURN SYS_CONTEXT('&CONTEXT_NAME', 'tenant_id');
  END get_tenant;

  -- --------------------------------------------------------
  -- VALIDATE TENANT: Checks mapping table, returns tenant_id
  -- --------------------------------------------------------
  FUNCTION validate_tenant RETURN VARCHAR2 IS
    v_tenant_id VARCHAR2(128);
  BEGIN
    SELECT tenant_id INTO v_tenant_id
    FROM &SCHEMA_OWNER..TENANT_USER_MAP
    WHERE db_user = SYS_CONTEXT('USERENV', 'SESSION_USER')
      AND is_active = 'Y';

    RETURN v_tenant_id;

  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      RETURN NULL;
    WHEN TOO_MANY_ROWS THEN
      RAISE_APPLICATION_ERROR(-20002, 'VPD: Multiple active tenant mappings found');
  END validate_tenant;

  -- --------------------------------------------------------
  -- AUTO ASSIGN: Called by logon trigger
  -- --------------------------------------------------------
  PROCEDURE auto_assign_tenant IS
    v_tenant_id VARCHAR2(128);
  BEGIN
    v_tenant_id := validate_tenant();

    IF v_tenant_id IS NOT NULL THEN
      set_tenant(v_tenant_id);
    ELSE
      -- SECURITY: No mapping = no context = VPD returns NO rows
      -- This is the safe default. Unmapped users see nothing.
      NULL;
    END IF;

  EXCEPTION
    WHEN OTHERS THEN
      -- Fail closed: if anything goes wrong, tenant stays NULL → 0 rows
      NULL;
  END auto_assign_tenant;

END &PACKAGE_NAME;
/


-- ============================================================================
-- 5. VPD POLICY FUNCTION
-- ============================================================================
-- Returns the WHERE clause predicate. If no tenant is set, returns '1=0'
-- (deny all) as a fail-closed safety measure.

CREATE OR REPLACE FUNCTION &SCHEMA_OWNER..fn_tenant_isolation (
  p_schema IN VARCHAR2,
  p_object IN VARCHAR2
) RETURN VARCHAR2 AS
  v_tenant VARCHAR2(128);
BEGIN
  v_tenant := SYS_CONTEXT('&CONTEXT_NAME', 'tenant_id');

  -- FAIL CLOSED: No tenant context = see nothing
  IF v_tenant IS NULL THEN
    RETURN '1=0';
  END IF;

  -- Return the invisible WHERE clause
  RETURN 'tenant_id = SYS_CONTEXT(''' || '&CONTEXT_NAME' || ''', ''tenant_id'')';
END;
/


-- ============================================================================
-- 6. APPLY VPD POLICIES TO ALL TENANT TABLES
-- ============================================================================
-- Add every table that contains a tenant_id column.
-- Covers SELECT, INSERT, UPDATE, DELETE — full DML protection.
--
-- IMPORTANT: Extend this list for your schema. Every table with tenant_id
-- should be listed here.

BEGIN
  -- ============================================
  -- TABLE: ORDERS
  -- ============================================
  DBMS_RLS.ADD_POLICY (
    object_schema   => '&SCHEMA_OWNER',
    object_name     => 'ORDERS',
    policy_name     => '&POLICY_PREFIX._ORDERS',
    function_schema => '&SCHEMA_OWNER',
    policy_function => 'FN_TENANT_ISOLATION',
    statement_types => 'SELECT,INSERT,UPDATE,DELETE',
    update_check    => TRUE,
    enable          => TRUE
  );

  -- ============================================
  -- TABLE: CUSTOMERS
  -- ============================================
  DBMS_RLS.ADD_POLICY (
    object_schema   => '&SCHEMA_OWNER',
    object_name     => 'CUSTOMERS',
    policy_name     => '&POLICY_PREFIX._CUSTOMERS',
    function_schema => '&SCHEMA_OWNER',
    policy_function => 'FN_TENANT_ISOLATION',
    statement_types => 'SELECT,INSERT,UPDATE,DELETE',
    update_check    => TRUE,
    enable          => TRUE
  );

  -- ============================================
  -- TABLE: INVOICES
  -- ============================================
  DBMS_RLS.ADD_POLICY (
    object_schema   => '&SCHEMA_OWNER',
    object_name     => 'INVOICES',
    policy_name     => '&POLICY_PREFIX._INVOICES',
    function_schema => '&SCHEMA_OWNER',
    policy_function => 'FN_TENANT_ISOLATION',
    statement_types => 'SELECT,INSERT,UPDATE,DELETE',
    update_check    => TRUE,
    enable          => TRUE
  );

  -- ============================================
  -- TABLE: TRANSACTIONS
  -- ============================================
  DBMS_RLS.ADD_POLICY (
    object_schema   => '&SCHEMA_OWNER',
    object_name     => 'TRANSACTIONS',
    policy_name     => '&POLICY_PREFIX._TRANSACTIONS',
    function_schema => '&SCHEMA_OWNER',
    policy_function => 'FN_TENANT_ISOLATION',
    statement_types => 'SELECT,INSERT,UPDATE,DELETE',
    update_check    => TRUE,
    enable          => TRUE
  );

  -- ADD MORE TABLES HERE:
  -- Copy the block above and change object_name and policy_name.

END;
/


-- ============================================================================
-- 7. LOGON TRIGGER — AUTO-SET TENANT FOR AI AGENTS
-- ============================================================================
-- When any DB user connects (including MCP agents, JDBC connections,
-- LangChain tools), this trigger fires and sets the tenant context
-- automatically from the mapping table.

CREATE OR REPLACE TRIGGER trg_vpd_logon_set_tenant
  AFTER LOGON ON DATABASE
BEGIN
  -- Skip for SYS/SYSTEM/DBA accounts
  IF SYS_CONTEXT('USERENV', 'SESSION_USER') NOT IN ('SYS', 'SYSTEM') THEN
    &SCHEMA_OWNER..&PACKAGE_NAME..auto_assign_tenant;
  END IF;

EXCEPTION
  WHEN OTHERS THEN
    -- Fail closed: trigger error = no context = 0 rows visible
    NULL;
END;
/


-- ============================================================================
-- 8. CONNECTION POOL CLEANUP TRIGGER (Optional but recommended)
-- ============================================================================
-- Clears tenant context on logoff to prevent context leaking
-- between sessions in a connection pool.

CREATE OR REPLACE TRIGGER trg_vpd_logoff_clear_tenant
  BEFORE LOGOFF ON DATABASE
BEGIN
  IF SYS_CONTEXT('USERENV', 'SESSION_USER') NOT IN ('SYS', 'SYSTEM') THEN
    &SCHEMA_OWNER..&PACKAGE_NAME..clear_tenant;
  END IF;

EXCEPTION
  WHEN OTHERS THEN
    NULL;
END;
/


-- ============================================================================
-- 9. VERIFICATION QUERIES — RUN AFTER DEPLOYMENT
-- ============================================================================

-- Check that policies are active:
SELECT object_name, policy_name, enable, sel, ins, upd, del
FROM DBA_POLICIES
WHERE pf_owner = '&SCHEMA_OWNER'
ORDER BY object_name;

-- Check context exists:
SELECT namespace, schema, package
FROM DBA_CONTEXT
WHERE namespace = '&CONTEXT_NAME';

-- Check triggers:
SELECT trigger_name, triggering_event, status
FROM DBA_TRIGGERS
WHERE trigger_name LIKE 'TRG_VPD%';

-- Check tenant mappings:
SELECT * FROM &SCHEMA_OWNER..TENANT_USER_MAP;

-- Test isolation (run as a mapped user):
-- SELECT PKG_SAAS_SECURITY.get_tenant FROM DUAL;
-- SELECT * FROM ORDERS;  -- Should only return rows for your tenant


-- ============================================================================
-- 10. ROLLBACK SCRIPT (Keep in version control)
-- ============================================================================
/*
  -- Remove policies
  BEGIN
    DBMS_RLS.DROP_POLICY('&SCHEMA_OWNER', 'ORDERS',       '&POLICY_PREFIX._ORDERS');
    DBMS_RLS.DROP_POLICY('&SCHEMA_OWNER', 'CUSTOMERS',    '&POLICY_PREFIX._CUSTOMERS');
    DBMS_RLS.DROP_POLICY('&SCHEMA_OWNER', 'INVOICES',     '&POLICY_PREFIX._INVOICES');
    DBMS_RLS.DROP_POLICY('&SCHEMA_OWNER', 'TRANSACTIONS', '&POLICY_PREFIX._TRANSACTIONS');
  END;
  /

  DROP TRIGGER trg_vpd_logon_set_tenant;
  DROP TRIGGER trg_vpd_logoff_clear_tenant;
  DROP FUNCTION &SCHEMA_OWNER..fn_tenant_isolation;
  DROP PACKAGE &SCHEMA_OWNER..&PACKAGE_NAME;
  DROP CONTEXT &CONTEXT_NAME;
  DROP TABLE &SCHEMA_OWNER..&AUDIT_TABLE;
  DROP TABLE &SCHEMA_OWNER..TENANT_USER_MAP;
*/


-- ============================================================================
-- END OF PRODUCTION VPD CONFIGURATION
-- ============================================================================
