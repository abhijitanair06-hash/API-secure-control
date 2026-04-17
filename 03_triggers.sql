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
-- TRIGGER 4 : Audit log — capture every token status change
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
-- TRIGGER 5 : Audit log — capture every client activation change
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
-- TRIGGER 6 : Audit log — capture new client registration
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
