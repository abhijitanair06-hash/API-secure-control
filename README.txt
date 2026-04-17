===============================================================
  PROJECT : Secure API Access Control using DBMS
  README / EXECUTION GUIDE
===============================================================

Run files in this order in MySQL Workbench or mysql CLI:

  1.  01_schema.sql          -- Create all tables + indexes
  2.  02_sample_data.sql     -- Insert sample data
  3.  03_triggers.sql        -- Load triggers
  4.  04_stored_procedures.sql -- Load stored procedures
  5.  05_transactions.sql    -- Run transaction demos
  6.  06_queries.sql         -- Analytical queries
  7.  07_demo_run.sql        -- Full presentation demo

---------------------------------------------------------------
TABLES
---------------------------------------------------------------
  api_clients   -- API consumers / applications
  scopes        -- Permissions (read:data, write:data, etc.)
  tokens        -- Access tokens with status tracking
  token_scopes  -- Many-to-many: token <-> permission
  api_requests  -- Every API call logged with verdict
  audit_logs    -- Immutable security trail

---------------------------------------------------------------
TRIGGERS (6)
---------------------------------------------------------------
  trg_auto_expire_token_before_insert  -- auto-expire on insert
  trg_auto_expire_token_before_update  -- auto-expire on update
  trg_set_revoked_at                   -- stamp revoke time
  trg_block_inactive_client_request    -- block inactive clients
  trg_audit_token_status_change        -- audit token changes
  trg_audit_client_status_change       -- audit client changes
  trg_audit_new_client                 -- audit new registrations

---------------------------------------------------------------
STORED PROCEDURES (4)
---------------------------------------------------------------
  validate_api_request  -- Core: checks token, returns allow/deny
  issue_token           -- Generates token + assigns scopes
  revoke_token          -- Revokes by token hash
  get_client_report     -- Full client summary report

---------------------------------------------------------------
TRANSACTIONS (3 scenarios)
---------------------------------------------------------------
  1. Register client + issue token (atomic)
  2. Deactivate client + revoke all tokens (atomic)
  3. Token rotation with audit trail

---------------------------------------------------------------
TOKEN VALIDATION LOGIC
---------------------------------------------------------------
  1. Token found?          NO  -> DENY
  2. Client active?        NO  -> DENY
  3. Status = revoked?     YES -> DENY
  4. Token expired?        YES -> DENY
  5. Has required scope?   NO  -> DENY
  6. All checks pass       ->  ALLOW

===============================================================
