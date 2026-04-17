-- ============================================================
-- MASTER SETUP FILE - Run this in MySQL Workbench
-- ============================================================
CREATE DATABASE IF NOT EXISTS api_security_db;
USE api_security_db;

-- ====== 01_schema.sql ======
-- ============================================================
--  PROJECT : Secure API Access Control using DBMS
--  FILE    : 01_schema.sql
--  PURPOSE : Creates all tables, constraints, and indexes
-- ============================================================

-- Drop tables in reverse dependency order (safe re-run)
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS token_scopes;
DROP TABLE IF EXISTS api_requests;
DROP TABLE IF EXISTS tokens;
DROP TABLE IF EXISTS scopes;
DROP TABLE IF EXISTS api_clients;

-- -------------------------------------------------------
-- 1. API CLIENTS
--    Represents applications / consumers of the API
-- -------------------------------------------------------
CREATE TABLE api_clients (
    client_id     INT            AUTO_INCREMENT PRIMARY KEY,
    client_name   VARCHAR(100)   NOT NULL,
    client_secret VARCHAR(255)   NOT NULL,          -- hashed secret
    owner_email   VARCHAR(150)   NOT NULL UNIQUE,
    is_active     BOOLEAN        NOT NULL DEFAULT TRUE,
    created_at    DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_email CHECK (owner_email LIKE '%@%.%')
);

-- -------------------------------------------------------
-- 2. SCOPES  (permissions)
--    e.g. read:data, write:data, admin:all
-- -------------------------------------------------------
CREATE TABLE scopes (
    scope_id    INT          AUTO_INCREMENT PRIMARY KEY,
    scope_name  VARCHAR(80)  NOT NULL UNIQUE,
    description VARCHAR(255)
);

-- -------------------------------------------------------
-- 3. TOKENS
--    Access tokens issued to clients
-- -------------------------------------------------------
CREATE TABLE tokens (
    token_id    INT            AUTO_INCREMENT PRIMARY KEY,
    client_id   INT            NOT NULL,
    token_hash  VARCHAR(255)   NOT NULL UNIQUE,      -- SHA-256 hash of token
    status      ENUM('active', 'expired', 'revoked') NOT NULL DEFAULT 'active',
    issued_at   DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME       NOT NULL,
    revoked_at  DATETIME       DEFAULT NULL,

    CONSTRAINT fk_token_client
        FOREIGN KEY (client_id) REFERENCES api_clients(client_id)
        ON DELETE CASCADE,

    CONSTRAINT chk_expiry CHECK (expires_at > issued_at)
);

-- -------------------------------------------------------
-- 4. TOKEN_SCOPES  (many-to-many: tokens <-> scopes)
--    Which permissions does each token carry?
-- -------------------------------------------------------
CREATE TABLE token_scopes (
    token_id  INT NOT NULL,
    scope_id  INT NOT NULL,
    PRIMARY KEY (token_id, scope_id),

    CONSTRAINT fk_ts_token
        FOREIGN KEY (token_id) REFERENCES tokens(token_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ts_scope
        FOREIGN KEY (scope_id) REFERENCES scopes(scope_id)
        ON DELETE CASCADE
);

-- -------------------------------------------------------
-- 5. API_REQUESTS
--    Log of every inbound API call and its verdict
-- -------------------------------------------------------
CREATE TABLE api_requests (
    request_id   INT            AUTO_INCREMENT PRIMARY KEY,
    token_id     INT            DEFAULT NULL,        -- NULL if token not found
    endpoint     VARCHAR(200)   NOT NULL,
    method       ENUM('GET','POST','PUT','DELETE','PATCH') NOT NULL,
    required_scope VARCHAR(80)  NOT NULL,
    status       ENUM('allowed','denied')            NOT NULL,
    deny_reason  VARCHAR(200)   DEFAULT NULL,
    requested_at DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_req_token
        FOREIGN KEY (token_id) REFERENCES tokens(token_id)
        ON DELETE SET NULL
);

-- -------------------------------------------------------
-- 6. AUDIT_LOGS
--    Immutable security audit trail (appended by triggers)
-- -------------------------------------------------------
CREATE TABLE audit_logs (
    log_id      INT           AUTO_INCREMENT PRIMARY KEY,
    event_type  VARCHAR(80)   NOT NULL,
    table_name  VARCHAR(80)   NOT NULL,
    record_id   INT           NOT NULL,
    old_value   TEXT          DEFAULT NULL,
    new_value   TEXT          DEFAULT NULL,
    logged_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- -------------------------------------------------------
-- INDEXES for fast lookups
-- -------------------------------------------------------
CREATE INDEX idx_token_hash     ON tokens(token_hash);
CREATE INDEX idx_token_status   ON tokens(status);
CREATE INDEX idx_token_client   ON tokens(client_id);
CREATE INDEX idx_req_token      ON api_requests(token_id);
CREATE INDEX idx_req_time       ON api_requests(requested_at);


-- ====== 02_sample_data.sql ======
-- ============================================================
--  PROJECT : Secure API Access Control using DBMS
--  FILE    : 02_sample_data.sql
--  PURPOSE : Inserts realistic sample data for demonstration
-- ============================================================

-- -------------------------------------------------------
-- API Clients
-- -------------------------------------------------------
INSERT INTO api_clients (client_name, client_secret, owner_email, is_active) VALUES
('MobileApp_Android',  SHA2('secret_mobile_android', 256),  'dev.android@appco.com',    TRUE),
('WebDashboard',       SHA2('secret_web_dashboard',  256),  'dev.web@appco.com',         TRUE),
('ReportingService',   SHA2('secret_reporting',      256),  'dev.report@analytics.com',  TRUE),
('LegacyIntegration',  SHA2('secret_legacy_xyz',     256),  'ops@legacycorp.com',        FALSE),  -- disabled client
('AdminTool',          SHA2('secret_admin_2024',     256),  'admin@appco.com',           TRUE);

-- -------------------------------------------------------
-- Scopes (permissions)
-- -------------------------------------------------------
INSERT INTO scopes (scope_name, description) VALUES
('read:data',    'Read-only access to general data'),
('write:data',   'Create and update data records'),
('delete:data',  'Permanently delete data records'),
('read:users',   'View user profile information'),
('write:users',  'Modify user accounts'),
('admin:all',    'Full administrative access â€” all operations');

-- -------------------------------------------------------
-- Tokens
-- -------------------------------------------------------
INSERT INTO tokens (client_id, token_hash, status, issued_at, expires_at) VALUES
-- MobileApp_Android  â†’ active token
(1, SHA2('token_mobile_001', 256), 'active',
    '2026-04-01 09:00:00', '2026-12-31 23:59:59'),

-- WebDashboard â†’ active token
(2, SHA2('token_web_001', 256),    'active',
    '2026-04-01 10:00:00', '2026-12-31 23:59:59'),

-- ReportingService â†’ expired token
(3, SHA2('token_report_old', 256), 'expired',
    '2025-01-01 00:00:00', '2025-06-30 23:59:59'),

-- ReportingService â†’ active replacement token
(3, SHA2('token_report_002', 256), 'active',
    '2026-03-01 00:00:00', '2026-09-01 00:00:00'),

-- LegacyIntegration â†’ revoked token
(4, SHA2('token_legacy_001', 256), 'revoked',
    '2025-06-01 00:00:00', '2026-06-01 00:00:00'),

-- AdminTool â†’ active token
(5, SHA2('token_admin_001', 256),  'active',
    '2026-04-15 08:00:00', '2026-05-15 08:00:00');

-- -------------------------------------------------------
-- Token Scopes  (assign permissions to each token)
-- -------------------------------------------------------
-- Mobile App â†’ can read data and read users
INSERT INTO token_scopes VALUES (1, 1), (1, 4);

-- Web Dashboard â†’ can read + write data
INSERT INTO token_scopes VALUES (2, 1), (2, 2);

-- Reporting (old expired) â†’ read:data only
INSERT INTO token_scopes VALUES (3, 1);

-- Reporting (new) â†’ read:data, read:users
INSERT INTO token_scopes VALUES (4, 1), (4, 4);

-- Legacy (revoked) â†’ read:data
INSERT INTO token_scopes VALUES (5, 1);

-- Admin Tool â†’ all scopes
INSERT INTO token_scopes VALUES (6, 1), (6, 2), (6, 3), (6, 4), (6, 5), (6, 6);

-- -------------------------------------------------------
-- API Requests  (simulated log of incoming calls)
-- -------------------------------------------------------
INSERT INTO api_requests
    (token_id, endpoint, method, required_scope, status, deny_reason, requested_at)
VALUES
-- âœ… Valid mobile read
(1, '/api/v1/products',     'GET',    'read:data',   'allowed', NULL,
    '2026-04-10 08:15:00'),

-- âœ… Valid dashboard write
(2, '/api/v1/orders',       'POST',   'write:data',  'allowed', NULL,
    '2026-04-10 09:30:00'),

-- âŒ Expired token attempt
(3, '/api/v1/reports',      'GET',    'read:data',   'denied',  'Token is expired',
    '2026-04-10 10:00:00'),

-- âŒ Revoked token attempt
(5, '/api/v1/customers',    'GET',    'read:data',   'denied',  'Token has been revoked',
    '2026-04-10 10:05:00'),

-- âŒ Mobile tries to delete â€” lacks scope
(1, '/api/v1/products/42',  'DELETE', 'delete:data', 'denied',  'Insufficient scope: delete:data required',
    '2026-04-10 11:00:00'),

-- âœ… Admin reads users
(6, '/api/v1/users',        'GET',    'read:users',  'allowed', NULL,
    '2026-04-10 12:00:00'),

-- âŒ Unknown/missing token (token_id = NULL)
(NULL, '/api/v1/secret',    'POST',   'admin:all',   'denied',  'Token not found',
    '2026-04-10 13:30:00'),

-- âœ… Report service reads data
(4, '/api/v1/analytics',    'GET',    'read:data',   'allowed', NULL,
    '2026-04-11 09:00:00');


-- ====== 03_triggers.sql ======
-- ============================================================
--  PROJECT : Secure API Access Control using DBMS
--  FILE    : 03_triggers.sql
--  PURPOSE : Automatic enforcement via database triggers
-- ============================================================

DELIMITER $$

-- -------------------------------------------------------
-- TRIGGER 1 : Auto-expire tokens before insert/update
--             Sets status = 'expired' if expires_at is past
-- -------------------------------------------------------
CREATE TRIGGER trg_auto_expire_token_before_insert
BEFORE INSERT ON tokens
FOR EACH ROW
BEGIN
    IF NEW.expires_at <= NOW() THEN
        SET NEW.status = 'expired';
    END IF;
END$$

CREATE TRIGGER trg_auto_expire_token_before_update
BEFORE UPDATE ON tokens
FOR EACH ROW
BEGIN
    IF NEW.expires_at <= NOW() AND NEW.status = 'active' THEN
        SET NEW.status = 'expired';
    END IF;
END$$

-- -------------------------------------------------------
-- TRIGGER 2 : Record revoked_at timestamp automatically
--             when a token's status changes to 'revoked'
-- -------------------------------------------------------
CREATE TRIGGER trg_set_revoked_at
BEFORE UPDATE ON tokens
FOR EACH ROW
BEGIN
    IF NEW.status = 'revoked' AND OLD.status != 'revoked' THEN
        SET NEW.revoked_at = NOW();
    END IF;
END$$

-- -------------------------------------------------------
-- TRIGGER 3 : Block API requests from INACTIVE clients
--             Prevents inserting an 'allowed' request
--             if the owning client is disabled
-- -------------------------------------------------------
CREATE TRIGGER trg_block_inactive_client_request
BEFORE INSERT ON api_requests
FOR EACH ROW
BEGIN
    DECLARE v_is_active BOOLEAN;

    IF NEW.token_id IS NOT NULL THEN
        SELECT c.is_active INTO v_is_active
        FROM tokens t
        JOIN api_clients c ON t.client_id = c.client_id
        WHERE t.token_id = NEW.token_id;

        IF v_is_active = FALSE AND NEW.status = 'allowed' THEN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Request blocked: client account is inactive.';
        END IF;
    END IF;
END$$

-- -------------------------------------------------------
-- TRIGGER 4 : Audit log â€” capture every token status change
-- -------------------------------------------------------
CREATE TRIGGER trg_audit_token_status_change
AFTER UPDATE ON tokens
FOR EACH ROW
BEGIN
    IF OLD.status != NEW.status THEN
        INSERT INTO audit_logs (event_type, table_name, record_id, old_value, new_value)
        VALUES (
            'TOKEN_STATUS_CHANGE',
            'tokens',
            NEW.token_id,
            CONCAT('status=', OLD.status),
            CONCAT('status=', NEW.status)
        );
    END IF;
END$$

-- -------------------------------------------------------
-- TRIGGER 5 : Audit log â€” capture every client activation change
-- -------------------------------------------------------
CREATE TRIGGER trg_audit_client_status_change
AFTER UPDATE ON api_clients
FOR EACH ROW
BEGIN
    IF OLD.is_active != NEW.is_active THEN
        INSERT INTO audit_logs (event_type, table_name, record_id, old_value, new_value)
        VALUES (
            'CLIENT_STATUS_CHANGE',
            'api_clients',
            NEW.client_id,
            CONCAT('is_active=', OLD.is_active),
            CONCAT('is_active=', NEW.is_active)
        );
    END IF;
END$$

-- -------------------------------------------------------
-- TRIGGER 6 : Audit log â€” capture new client registration
-- -------------------------------------------------------
CREATE TRIGGER trg_audit_new_client
AFTER INSERT ON api_clients
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (event_type, table_name, record_id, new_value)
    VALUES (
        'CLIENT_REGISTERED',
        'api_clients',
        NEW.client_id,
        CONCAT('client_name=', NEW.client_name, ', email=', NEW.owner_email)
    );
END$$

DELIMITER ;


-- ====== 04_stored_procedures.sql ======
-- ============================================================
--  PROJECT : Secure API Access Control using DBMS
--  FILE    : 04_stored_procedures.sql
--  PURPOSE : Encapsulated business logic in stored procedures
-- ============================================================

DELIMITER $$

-- -------------------------------------------------------
-- PROCEDURE 1 : validate_api_request
--   Core procedure â€” the heart of the project.
--   Checks a token hash + required scope and decides
--   ALLOW or DENY.  Logs the result to api_requests.
--
--   IN  : p_token_hash     (the token string sent by caller)
--         p_endpoint       (API path being called)
--         p_method         (HTTP method)
--         p_required_scope (scope the endpoint needs)
--   OUT : p_result         ('allowed' or 'denied')
--         p_reason         (human-readable verdict message)
-- -------------------------------------------------------
CREATE PROCEDURE validate_api_request (
    IN  p_token_hash     VARCHAR(255),
    IN  p_endpoint       VARCHAR(200),
    IN  p_method         VARCHAR(10),
    IN  p_required_scope VARCHAR(80),
    OUT p_result         VARCHAR(10),
    OUT p_reason         VARCHAR(200)
)
BEGIN
    DECLARE v_token_id   INT      DEFAULT NULL;
    DECLARE v_status     VARCHAR(20);
    DECLARE v_expires_at DATETIME;
    DECLARE v_client_id  INT;
    DECLARE v_is_active  BOOLEAN;
    DECLARE v_scope_ok   INT      DEFAULT 0;

    -- Step 1: Look up the token
    SELECT token_id, status, expires_at, client_id
    INTO   v_token_id, v_status, v_expires_at, v_client_id
    FROM   tokens
    WHERE  token_hash = p_token_hash
    LIMIT  1;

    -- Step 2: Token not found?
    IF v_token_id IS NULL THEN
        SET p_result = 'denied';
        SET p_reason = 'Token not found';
        INSERT INTO api_requests
            (token_id, endpoint, method, required_scope, status, deny_reason)
        VALUES
            (NULL, p_endpoint, p_method, p_required_scope, 'denied', p_reason);
        LEAVE validate_api_request;   -- exit early (MySQL label exit)
    END IF;

    -- Step 3: Check if owning client is active
    SELECT is_active INTO v_is_active
    FROM   api_clients
    WHERE  client_id = v_client_id;

    IF v_is_active = FALSE THEN
        SET p_result = 'denied';
        SET p_reason = 'Client account is inactive';
        INSERT INTO api_requests
            (token_id, endpoint, method, required_scope, status, deny_reason)
        VALUES (v_token_id, p_endpoint, p_method, p_required_scope, 'denied', p_reason);
        LEAVE validate_api_request;
    END IF;

    -- Step 4: Check token status
    IF v_status = 'revoked' THEN
        SET p_result = 'denied';
        SET p_reason = 'Token has been revoked';
        INSERT INTO api_requests
            (token_id, endpoint, method, required_scope, status, deny_reason)
        VALUES (v_token_id, p_endpoint, p_method, p_required_scope, 'denied', p_reason);
        LEAVE validate_api_request;
    END IF;

    IF v_status = 'expired' OR v_expires_at <= NOW() THEN
        -- Auto-fix status if needed
        UPDATE tokens SET status = 'expired' WHERE token_id = v_token_id AND status = 'active';
        SET p_result = 'denied';
        SET p_reason = 'Token is expired';
        INSERT INTO api_requests
            (token_id, endpoint, method, required_scope, status, deny_reason)
        VALUES (v_token_id, p_endpoint, p_method, p_required_scope, 'denied', p_reason);
        LEAVE validate_api_request;
    END IF;

    -- Step 5: Check scope permission
    SELECT COUNT(*) INTO v_scope_ok
    FROM   token_scopes ts
    JOIN   scopes s ON ts.scope_id = s.scope_id
    WHERE  ts.token_id = v_token_id
      AND  s.scope_name = p_required_scope;

    IF v_scope_ok = 0 THEN
        SET p_result = 'denied';
        SET p_reason = CONCAT('Insufficient scope: ', p_required_scope, ' required');
        INSERT INTO api_requests
            (token_id, endpoint, method, required_scope, status, deny_reason)
        VALUES (v_token_id, p_endpoint, p_method, p_required_scope, 'denied', p_reason);
        LEAVE validate_api_request;
    END IF;

    -- Step 6: All checks passed â†’ ALLOW
    SET p_result = 'allowed';
    SET p_reason = 'Access granted';
    INSERT INTO api_requests
        (token_id, endpoint, method, required_scope, status, deny_reason)
    VALUES (v_token_id, p_endpoint, p_method, p_required_scope, 'allowed', NULL);

END$$

-- -------------------------------------------------------
-- PROCEDURE 2 : issue_token
--   Creates a new token for a client with given scopes.
--   Returns the plain token string (caller should store
--   only the hash â€” this is for demo/teaching purposes).
--
--   IN  : p_client_id    (which client gets the token)
--         p_valid_days   (how many days until expiry)
--         p_scope_names  (comma-separated scope list)
--   OUT : p_token_value  (the generated token string)
--         p_token_id     (new token's ID)
-- -------------------------------------------------------
CREATE PROCEDURE issue_token (
    IN  p_client_id   INT,
    IN  p_valid_days  INT,
    IN  p_scope_names TEXT,
    OUT p_token_value VARCHAR(255),
    OUT p_token_id    INT
)
BEGIN
    DECLARE v_token_str  VARCHAR(255);
    DECLARE v_hash       VARCHAR(255);
    DECLARE v_expires    DATETIME;
    DECLARE v_scope_name VARCHAR(80);
    DECLARE v_scope_id   INT;
    DECLARE v_pos        INT DEFAULT 1;
    DECLARE v_next_pos   INT;
    DECLARE v_part       VARCHAR(80);

    -- Generate a pseudo-random token string
    SET v_token_str = CONCAT(
        SHA2(CONCAT(p_client_id, NOW(), RAND()), 256),
        HEX(RAND() * 100000)
    );
    SET v_hash    = SHA2(v_token_str, 256);
    SET v_expires = DATE_ADD(NOW(), INTERVAL p_valid_days DAY);

    -- Insert the token
    INSERT INTO tokens (client_id, token_hash, status, expires_at)
    VALUES (p_client_id, v_hash, 'active', v_expires);

    SET p_token_id    = LAST_INSERT_ID();
    SET p_token_value = v_token_str;

    -- Parse comma-separated scopes and link them
    SET p_scope_names = CONCAT(TRIM(p_scope_names), ',');
    WHILE LOCATE(',', p_scope_names, v_pos) > 0 DO
        SET v_next_pos = LOCATE(',', p_scope_names, v_pos);
        SET v_part     = TRIM(SUBSTRING(p_scope_names, v_pos, v_next_pos - v_pos));

        IF v_part != '' THEN
            SELECT scope_id INTO v_scope_id
            FROM   scopes
            WHERE  scope_name = v_part
            LIMIT  1;

            IF v_scope_id IS NOT NULL THEN
                INSERT IGNORE INTO token_scopes (token_id, scope_id)
                VALUES (p_token_id, v_scope_id);
            END IF;
        END IF;

        SET v_pos = v_next_pos + 1;
    END WHILE;
END$$

-- -------------------------------------------------------
-- PROCEDURE 3 : revoke_token
--   Revokes a token by its hash.  Logs to audit table.
-- -------------------------------------------------------
CREATE PROCEDURE revoke_token (
    IN  p_token_hash VARCHAR(255),
    OUT p_success    BOOLEAN,
    OUT p_message    VARCHAR(200)
)
BEGIN
    DECLARE v_token_id INT;
    DECLARE v_status   VARCHAR(20);

    SELECT token_id, status
    INTO   v_token_id, v_status
    FROM   tokens
    WHERE  token_hash = p_token_hash
    LIMIT  1;

    IF v_token_id IS NULL THEN
        SET p_success = FALSE;
        SET p_message = 'Token not found';
    ELSEIF v_status = 'revoked' THEN
        SET p_success = FALSE;
        SET p_message = 'Token is already revoked';
    ELSE
        UPDATE tokens
        SET    status = 'revoked', revoked_at = NOW()
        WHERE  token_id = v_token_id;

        SET p_success = TRUE;
        SET p_message = CONCAT('Token #', v_token_id, ' successfully revoked');
    END IF;
END$$

-- -------------------------------------------------------
-- PROCEDURE 4 : get_client_report
--   Summary report of a client's tokens and usage
-- -------------------------------------------------------
CREATE PROCEDURE get_client_report (IN p_client_id INT)
BEGIN
    -- Client info
    SELECT client_id, client_name, owner_email, is_active, created_at
    FROM   api_clients
    WHERE  client_id = p_client_id;

    -- Token summary
    SELECT
        t.token_id,
        t.status,
        t.issued_at,
        t.expires_at,
        t.revoked_at,
        GROUP_CONCAT(s.scope_name ORDER BY s.scope_name SEPARATOR ', ') AS scopes
    FROM tokens t
    LEFT JOIN token_scopes ts ON t.token_id = ts.token_id
    LEFT JOIN scopes s        ON ts.scope_id = s.scope_id
    WHERE t.client_id = p_client_id
    GROUP BY t.token_id;

    -- Request summary
    SELECT
        r.request_id,
        r.endpoint,
        r.method,
        r.required_scope,
        r.status,
        r.deny_reason,
        r.requested_at
    FROM api_requests r
    JOIN tokens t ON r.token_id = t.token_id
    WHERE t.client_id = p_client_id
    ORDER BY r.requested_at DESC;
END$$

DELIMITER ;


-- ====== 05_transactions.sql ======
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

    -- Step C: Assign scopes â€” read:data and write:data only
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


