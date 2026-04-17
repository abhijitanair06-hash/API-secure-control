-- ============================================================
--  PROJECT : Secure API Access Control using DBMS
--  FILE    : 06_queries.sql
--  PURPOSE : Analytical & operational SQL queries for demo
-- ============================================================

-- -------------------------------------------------------
-- Q1 : List ALL tokens with client name and scope list
-- -------------------------------------------------------
SELECT
    t.token_id,
    c.client_name,
    t.status,
    t.issued_at,
    t.expires_at,
    GROUP_CONCAT(s.scope_name ORDER BY s.scope_name SEPARATOR ' | ') AS scopes
FROM tokens t
JOIN api_clients c ON t.client_id = c.client_id
LEFT JOIN token_scopes ts ON t.token_id = ts.token_id
LEFT JOIN scopes s ON ts.scope_id = s.scope_id
GROUP BY t.token_id, c.client_name, t.status, t.issued_at, t.expires_at
ORDER BY t.token_id;

-- -------------------------------------------------------
-- Q2 : Show ALL denied requests with reason
-- -------------------------------------------------------
SELECT
    r.request_id,
    COALESCE(c.client_name, 'Unknown') AS client,
    r.endpoint,
    r.method,
    r.required_scope,
    r.deny_reason,
    r.requested_at
FROM api_requests r
LEFT JOIN tokens t ON r.token_id = t.token_id
LEFT JOIN api_clients c ON t.client_id = c.client_id
WHERE r.status = 'denied'
ORDER BY r.requested_at DESC;

-- -------------------------------------------------------
-- Q3 : Count requests per client (allowed vs denied)
-- -------------------------------------------------------
SELECT
    c.client_name,
    COUNT(r.request_id)                                        AS total_requests,
    SUM(r.status = 'allowed')                                  AS allowed,
    SUM(r.status = 'denied')                                   AS denied,
    ROUND(SUM(r.status = 'allowed') / COUNT(r.request_id) * 100, 1) AS success_rate_pct
FROM api_requests r
JOIN tokens t ON r.token_id = t.token_id
JOIN api_clients c ON t.client_id = c.client_id
GROUP BY c.client_id, c.client_name
ORDER BY total_requests DESC;

-- -------------------------------------------------------
-- Q4 : Find all ACTIVE tokens that expire within 30 days
--       (useful for alerting clients to renew)
-- -------------------------------------------------------
SELECT
    t.token_id,
    c.client_name,
    c.owner_email,
    t.expires_at,
    DATEDIFF(t.expires_at, NOW()) AS days_remaining
FROM tokens t
JOIN api_clients c ON t.client_id = c.client_id
WHERE t.status = 'active'
  AND t.expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAY)
ORDER BY days_remaining ASC;

-- -------------------------------------------------------
-- Q5 : Full audit trail — most recent events first
-- -------------------------------------------------------
SELECT
    log_id,
    event_type,
    table_name,
    record_id,
    old_value,
    new_value,
    logged_at
FROM audit_logs
ORDER BY logged_at DESC;

-- -------------------------------------------------------
-- Q6 : Which scopes are most frequently used in requests?
-- -------------------------------------------------------
SELECT
    required_scope,
    COUNT(*)                          AS total_requests,
    SUM(status = 'allowed')           AS allowed,
    SUM(status = 'denied')            AS denied
FROM api_requests
GROUP BY required_scope
ORDER BY total_requests DESC;

-- -------------------------------------------------------
-- Q7 : Clients that have NEVER made a successful request
--       (security concern — dead clients with active tokens)
-- -------------------------------------------------------
SELECT
    c.client_id,
    c.client_name,
    c.owner_email,
    c.is_active
FROM api_clients c
WHERE c.client_id NOT IN (
    SELECT DISTINCT t.client_id
    FROM api_requests r
    JOIN tokens t ON r.token_id = t.token_id
    WHERE r.status = 'allowed'
);

-- -------------------------------------------------------
-- Q8 : Validate a token manually (simulate the check)
--       Replace the SHA2 value with an actual token hash
-- -------------------------------------------------------
SELECT
    t.token_id,
    c.client_name,
    t.status,
    t.expires_at,
    CASE
        WHEN c.is_active = FALSE         THEN 'DENY — client inactive'
        WHEN t.status = 'revoked'        THEN 'DENY — token revoked'
        WHEN t.expires_at <= NOW()       THEN 'DENY — token expired'
        ELSE                                  'PASS — token is valid'
    END AS validity_check
FROM tokens t
JOIN api_clients c ON t.client_id = c.client_id
WHERE t.token_hash = SHA2('token_mobile_001', 256);

-- -------------------------------------------------------
-- Q9 : Tokens that are marked 'active' but actually expired
--       (data consistency check)
-- -------------------------------------------------------
SELECT token_id, client_id, expires_at, status
FROM tokens
WHERE status = 'active'
  AND expires_at < NOW();

-- -------------------------------------------------------
-- Q10 : Top 3 most-called endpoints
-- -------------------------------------------------------
SELECT
    endpoint,
    method,
    COUNT(*) AS call_count
FROM api_requests
GROUP BY endpoint, method
ORDER BY call_count DESC
LIMIT 3;
