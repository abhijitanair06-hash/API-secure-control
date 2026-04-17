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
('admin:all',    'Full administrative access — all operations');

-- -------------------------------------------------------
-- Tokens
-- -------------------------------------------------------
INSERT INTO tokens (client_id, token_hash, status, issued_at, expires_at) VALUES
-- MobileApp_Android  → active token
(1, SHA2('token_mobile_001', 256), 'active',
    '2026-04-01 09:00:00', '2026-12-31 23:59:59'),

-- WebDashboard → active token
(2, SHA2('token_web_001', 256),    'active',
    '2026-04-01 10:00:00', '2026-12-31 23:59:59'),

-- ReportingService → expired token
(3, SHA2('token_report_old', 256), 'expired',
    '2025-01-01 00:00:00', '2025-06-30 23:59:59'),

-- ReportingService → active replacement token
(3, SHA2('token_report_002', 256), 'active',
    '2026-03-01 00:00:00', '2026-09-01 00:00:00'),

-- LegacyIntegration → revoked token
(4, SHA2('token_legacy_001', 256), 'revoked',
    '2025-06-01 00:00:00', '2026-06-01 00:00:00'),

-- AdminTool → active token
(5, SHA2('token_admin_001', 256),  'active',
    '2026-04-15 08:00:00', '2026-05-15 08:00:00');

-- -------------------------------------------------------
-- Token Scopes  (assign permissions to each token)
-- -------------------------------------------------------
-- Mobile App → can read data and read users
INSERT INTO token_scopes VALUES (1, 1), (1, 4);

-- Web Dashboard → can read + write data
INSERT INTO token_scopes VALUES (2, 1), (2, 2);

-- Reporting (old expired) → read:data only
INSERT INTO token_scopes VALUES (3, 1);

-- Reporting (new) → read:data, read:users
INSERT INTO token_scopes VALUES (4, 1), (4, 4);

-- Legacy (revoked) → read:data
INSERT INTO token_scopes VALUES (5, 1);

-- Admin Tool → all scopes
INSERT INTO token_scopes VALUES (6, 1), (6, 2), (6, 3), (6, 4), (6, 5), (6, 6);

-- -------------------------------------------------------
-- API Requests  (simulated log of incoming calls)
-- -------------------------------------------------------
INSERT INTO api_requests
    (token_id, endpoint, method, required_scope, status, deny_reason, requested_at)
VALUES
-- ✅ Valid mobile read
(1, '/api/v1/products',     'GET',    'read:data',   'allowed', NULL,
    '2026-04-10 08:15:00'),

-- ✅ Valid dashboard write
(2, '/api/v1/orders',       'POST',   'write:data',  'allowed', NULL,
    '2026-04-10 09:30:00'),

-- ❌ Expired token attempt
(3, '/api/v1/reports',      'GET',    'read:data',   'denied',  'Token is expired',
    '2026-04-10 10:00:00'),

-- ❌ Revoked token attempt
(5, '/api/v1/customers',    'GET',    'read:data',   'denied',  'Token has been revoked',
    '2026-04-10 10:05:00'),

-- ❌ Mobile tries to delete — lacks scope
(1, '/api/v1/products/42',  'DELETE', 'delete:data', 'denied',  'Insufficient scope: delete:data required',
    '2026-04-10 11:00:00'),

-- ✅ Admin reads users
(6, '/api/v1/users',        'GET',    'read:users',  'allowed', NULL,
    '2026-04-10 12:00:00'),

-- ❌ Unknown/missing token (token_id = NULL)
(NULL, '/api/v1/secret',    'POST',   'admin:all',   'denied',  'Token not found',
    '2026-04-10 13:30:00'),

-- ✅ Report service reads data
(4, '/api/v1/analytics',    'GET',    'read:data',   'allowed', NULL,
    '2026-04-11 09:00:00');
