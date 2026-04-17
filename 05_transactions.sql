-- ============================================================
--  PROJECT : Secure API Access Control using DBMS
--  FILE    : 05_transactions.sql
--  PURPOSE : Demonstrates ACID transactions for critical ops
-- ============================================================

-- -------------------------------------------------------
-- TRANSACTION 1 : Register a new API client + issue token
--   Atomic: either both the client AND token are created,
--   or neither is (rollback on any failure).
-- -------------------------------------------------------
START TRANSACTION;

    -- Step A: Register the new client
    INSERT INTO api_clients (client_name, client_secret, owner_email)
    VALUES ('PaymentGateway', SHA2('secret_pay_2026', 256), 'dev@payment.io');

    -- Step B: Issue a token for that client (30-day validity)
    SET @new_client_id = LAST_INSERT_ID();

    INSERT INTO tokens (client_id, token_hash, status, expires_at)
    VALUES (
        @new_client_id,
        SHA2(CONCAT('token_pay_', NOW()), 256),
        'active',
        DATE_ADD(NOW(), INTERVAL 30 DAY)
    );

    SET @new_token_id = LAST_INSERT_ID();

    -- Step C: Assign scopes — read:data and write:data only
    INSERT INTO token_scopes (token_id, scope_id)
    SELECT @new_token_id, scope_id
    FROM   scopes
    WHERE  scope_name IN ('read:data', 'write:data');

COMMIT;
-- If any INSERT above fails, run ROLLBACK; instead of COMMIT;

-- -------------------------------------------------------
-- TRANSACTION 2 : Revoke all tokens of a client atomically
--   Used when a client is compromised or deactivated.
-- -------------------------------------------------------
START TRANSACTION;

    -- Disable the client
    UPDATE api_clients
    SET    is_active = FALSE
    WHERE  client_id = 4;           -- LegacyIntegration

    -- Revoke every active/expired token of that client
    UPDATE tokens
    SET    status     = 'revoked',
           revoked_at = NOW()
    WHERE  client_id = 4
      AND  status != 'revoked';

    -- Log the mass revocation event manually
    INSERT INTO audit_logs (event_type, table_name, record_id, new_value)
    VALUES ('MASS_REVOCATION', 'api_clients', 4,
            'All tokens revoked due to account deactivation');

COMMIT;

-- -------------------------------------------------------
-- TRANSACTION 3 : Token rotation
--   Revoke the old token and issue a fresh one atomically.
--   Ensures there is never a window with NO valid token.
-- -------------------------------------------------------
START TRANSACTION;

    -- Revoke old token (token_id = 1)
    UPDATE tokens
    SET    status     = 'revoked',
           revoked_at = NOW()
    WHERE  token_id = 1;

    -- Issue replacement token for same client
    INSERT INTO tokens (client_id, token_hash, status, expires_at)
    VALUES (
        1,                                               -- MobileApp_Android
        SHA2(CONCAT('token_mobile_rotated_', NOW()), 256),
        'active',
        DATE_ADD(NOW(), INTERVAL 90 DAY)
    );

    SET @rotated_token_id = LAST_INSERT_ID();

    -- Copy same scopes from old token to new token
    INSERT INTO token_scopes (token_id, scope_id)
    SELECT @rotated_token_id, scope_id
    FROM   token_scopes
    WHERE  token_id = 1;

    -- Audit entry
    INSERT INTO audit_logs (event_type, table_name, record_id, old_value, new_value)
    VALUES ('TOKEN_ROTATION', 'tokens', 1,
            'old_token_id=1',
            CONCAT('new_token_id=', @rotated_token_id));

COMMIT;

-- -------------------------------------------------------
-- SAVEPOINT example : Partial rollback inside a transaction
-- -------------------------------------------------------
START TRANSACTION;

    INSERT INTO audit_logs (event_type, table_name, record_id, new_value)
    VALUES ('TEST_EVENT', 'tokens', 999, 'savepoint demo start');

    SAVEPOINT sp_before_risky_op;

    -- Simulate a risky operation (e.g., scope assignment)
    INSERT INTO token_scopes (token_id, scope_id) VALUES (6, 1);  -- may already exist

    -- If the above caused a problem, rollback only to savepoint
    -- ROLLBACK TO SAVEPOINT sp_before_risky_op;

    -- Otherwise release the savepoint and commit
    RELEASE SAVEPOINT sp_before_risky_op;

COMMIT;
