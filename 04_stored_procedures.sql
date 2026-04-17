-- ============================================================
--  PROJECT : Secure API Access Control using DBMS
--  FILE    : 04_stored_procedures.sql
--  PURPOSE : Encapsulated business logic in stored procedures
-- ============================================================

DELIMITER $$

-- -------------------------------------------------------
-- PROCEDURE 1 : validate_api_request
--   Core procedure — the heart of the project.
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
validate_api_request: BEGIN
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

    -- Step 6: All checks passed → ALLOW
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
--   only the hash — this is for demo/teaching purposes).
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
