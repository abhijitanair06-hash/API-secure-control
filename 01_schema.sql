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
