-- ============================================================
--  PROJECT : Secure API Access Control using DBMS
--  FILE    : 07_demo_run.sql
--  PURPOSE : Step-by-step demo script for viva / presentation
--            Run each section separately and show results
-- ============================================================

-- ============================================================
-- STEP 1 : Setup  (run 01_schema.sql then 02_sample_data.sql)
-- ============================================================
-- Already done.  Verify setup:
SELECT 'Clients:'  AS entity, COUNT(*) AS count FROM api_clients
UNION ALL
SELECT 'Scopes:',  COUNT(*) FROM scopes
UNION ALL
SELECT 'Tokens:',  COUNT(*) FROM tokens
UNION ALL
SELECT 'Requests:', COUNT(*) FROM api_requests;

-- ============================================================
-- STEP 2 : Show all tokens and their status
-- ============================================================
SELECT t.token_id, c.client_name, t.status, t.expires_at
FROM tokens t
JOIN api_clients c ON t.client_id = c.client_id;

-- ============================================================
-- STEP 3 : Test validate_api_request procedure
-- ============================================================

-- 3a : Valid token with correct scope → should be ALLOWED
CALL validate_api_request(
    SHA2('token_mobile_001', 256),    -- token hash
    '/api/v1/products',               -- endpoint
    'GET',                            -- method
    'read:data',                      -- required scope
    @result, @reason
);
SELECT @result AS verdict, @reason AS message;

-- 3b : Valid token but wrong scope → should be DENIED
CALL validate_api_request(
    SHA2('token_mobile_001', 256),
    '/api/v1/products/99',
    'DELETE',
    'delete:data',                    -- mobile does NOT have this
    @result, @reason
);
SELECT @result AS verdict, @reason AS message;

-- 3c : Expired token → should be DENIED
CALL validate_api_request(
    SHA2('token_report_old', 256),
    '/api/v1/reports',
    'GET',
    'read:data',
    @result, @reason
);
SELECT @result AS verdict, @reason AS message;

-- 3d : Revoked token → should be DENIED
CALL validate_api_request(
    SHA2('token_legacy_001', 256),
    '/api/v1/data',
    'GET',
    'read:data',
    @result, @reason
);
SELECT @result AS verdict, @reason AS message;

-- 3e : Token that does not exist → should be DENIED
CALL validate_api_request(
    SHA2('this_token_does_not_exist', 256),
    '/api/v1/secret',
    'POST',
    'admin:all',
    @result, @reason
);
SELECT @result AS verdict, @reason AS message;

-- ============================================================
-- STEP 4 : Issue a new token using the procedure
-- ============================================================
CALL issue_token(
    2,                          -- WebDashboard client
    60,                         -- valid for 60 days
    'read:data,write:data',     -- scopes
    @token_val, @token_id
);
SELECT @token_val AS new_token_string, @token_id AS new_token_id;

-- ============================================================
-- STEP 5 : Revoke a token
-- ============================================================
CALL revoke_token(SHA2('token_web_001', 256), @ok, @msg);
SELECT @ok AS success, @msg AS message;

-- Verify token status changed
SELECT token_id, status, revoked_at FROM tokens WHERE token_id = 2;

-- ============================================================
-- STEP 6 : Check audit log after above operations
-- ============================================================
SELECT event_type, table_name, record_id, old_value, new_value, logged_at
FROM audit_logs
ORDER BY logged_at DESC
LIMIT 10;

-- ============================================================
-- STEP 7 : Full client report using stored procedure
-- ============================================================
CALL get_client_report(1);     -- MobileApp_Android

-- ============================================================
-- STEP 8 : Show request statistics (allowed vs denied)
-- ============================================================
SELECT
    r.status,
    COUNT(*) AS count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM api_requests), 1) AS percentage
FROM api_requests r
GROUP BY r.status;
