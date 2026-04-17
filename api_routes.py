# ============================================================
#  api_routes.py — All API Route Definitions
#  PERSON  : Krishna
#  PURPOSE : Define endpoints; bridge frontend <-> database
# ============================================================

from flask import Blueprint, request, jsonify
import hashlib
from db import execute_query, call_procedure

# Create a Blueprint so routes are modular
api = Blueprint("api", __name__, url_prefix="/api")


# ------------------------------------------------------------------
# Helper: SHA-256 hash (mirrors SQL's SHA2(str, 256))
# ------------------------------------------------------------------
def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ==================================================================
# ROUTE 1 : POST /api/validate
#   Validates a token against an endpoint + required scope.
#   Calls stored procedure: validate_api_request
#   Body: { token, endpoint, method, required_scope }
# ==================================================================
@api.route("/validate", methods=["POST"])
def validate_token():
    data = request.get_json()
    token_raw    = data.get("token", "").strip()
    endpoint     = data.get("endpoint", "/api/v1/resource").strip()
    method       = data.get("method", "GET").strip().upper()
    required_scope = data.get("required_scope", "read:data").strip()

    if not token_raw:
        return jsonify({"error": "Token is required"}), 400

    token_hash = sha256(token_raw)

    try:
        # OUT params: p_result, p_reason (2 out params)
        result = call_procedure(
            "validate_api_request",
            args=(token_hash, endpoint, method, required_scope, "", ""),
            out_count=2
        )
        verdict, reason = result["out_params"]
        return jsonify({
            "verdict": verdict,
            "reason": reason,
            "token_hash": token_hash[:16] + "..."  # partial hash for display
        }), 200

    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 2 : GET /api/tokens
#   Returns list of all tokens with client name and scopes
# ==================================================================
@api.route("/tokens", methods=["GET"])
def get_tokens():
    query = """
        SELECT
            t.token_id,
            c.client_name,
            t.status,
            DATE_FORMAT(t.issued_at,  '%Y-%m-%d %H:%i') AS issued_at,
            DATE_FORMAT(t.expires_at, '%Y-%m-%d %H:%i') AS expires_at,
            DATE_FORMAT(t.revoked_at, '%Y-%m-%d %H:%i') AS revoked_at,
            GROUP_CONCAT(s.scope_name ORDER BY s.scope_name SEPARATOR ', ') AS scopes
        FROM tokens t
        JOIN api_clients c ON t.client_id = c.client_id
        LEFT JOIN token_scopes ts ON t.token_id = ts.token_id
        LEFT JOIN scopes s        ON ts.scope_id = s.scope_id
        GROUP BY t.token_id, c.client_name, t.status, t.issued_at, t.expires_at, t.revoked_at
        ORDER BY t.token_id
    """
    try:
        tokens = execute_query(query, fetch=True, many=True)
        return jsonify(tokens), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 3 : POST /api/tokens/issue
#   Issues a new token for a client
#   Body: { client_id, valid_days, scopes }
# ==================================================================
@api.route("/tokens/issue", methods=["POST"])
def issue_token():
    data       = request.get_json()
    client_id  = data.get("client_id")
    valid_days = data.get("valid_days", 30)
    scopes     = data.get("scopes", "read:data")

    if not client_id:
        return jsonify({"error": "client_id is required"}), 400

    try:
        result = call_procedure(
            "issue_token",
            args=(int(client_id), int(valid_days), scopes, "", 0),
            out_count=2
        )
        token_value, token_id = result["out_params"]
        return jsonify({
            "message": "Token issued successfully",
            "token": token_value,
            "token_id": token_id
        }), 201

    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 4 : POST /api/tokens/revoke
#   Revokes a token by its raw value
#   Body: { token }
# ==================================================================
@api.route("/tokens/revoke", methods=["POST"])
def revoke_token():
    data      = request.get_json()
    token_raw = data.get("token", "").strip()

    if not token_raw:
        return jsonify({"error": "Token is required"}), 400

    token_hash = sha256(token_raw)

    try:
        result = call_procedure(
            "revoke_token",
            args=(token_hash, False, ""),
            out_count=2
        )
        success, message = result["out_params"]
        status_code = 200 if success else 400
        return jsonify({"success": bool(success), "message": message}), status_code

    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 5 : GET /api/clients
#   Returns list of all registered API clients
# ==================================================================
@api.route("/clients", methods=["GET"])
def get_clients():
    query = """
        SELECT
            client_id,
            client_name,
            owner_email,
            is_active,
            DATE_FORMAT(created_at, '%Y-%m-%d') AS created_at
        FROM api_clients
        ORDER BY client_id
    """
    try:
        clients = execute_query(query, fetch=True, many=True)
        return jsonify(clients), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 6 : GET /api/requests
#   Returns recent API request log with deny reasons
#   Query param: ?limit=20 (default 20)
# ==================================================================
@api.route("/requests", methods=["GET"])
def get_requests():
    limit = int(request.args.get("limit", 20))
    query = """
        SELECT
            r.request_id,
            COALESCE(c.client_name, 'Unknown') AS client_name,
            r.endpoint,
            r.method,
            r.required_scope,
            r.status,
            r.deny_reason,
            DATE_FORMAT(r.requested_at, '%Y-%m-%d %H:%i:%s') AS requested_at
        FROM api_requests r
        LEFT JOIN tokens t ON r.token_id = t.token_id
        LEFT JOIN api_clients c ON t.client_id = c.client_id
        ORDER BY r.requested_at DESC
        LIMIT %s
    """
    try:
        rows = execute_query(query, params=(limit,), fetch=True, many=True)
        return jsonify(rows), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 7 : GET /api/audit
#   Returns audit log entries (most recent first)
# ==================================================================
@api.route("/audit", methods=["GET"])
def get_audit():
    query = """
        SELECT
            log_id,
            event_type,
            table_name,
            record_id,
            old_value,
            new_value,
            DATE_FORMAT(logged_at, '%Y-%m-%d %H:%i:%s') AS logged_at
        FROM audit_logs
        ORDER BY logged_at DESC
        LIMIT 50
    """
    try:
        rows = execute_query(query, fetch=True, many=True)
        return jsonify(rows), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 8 : GET /api/stats
#   Dashboard summary statistics
# ==================================================================
@api.route("/stats", methods=["GET"])
def get_stats():
    try:
        total_clients  = execute_query("SELECT COUNT(*) AS n FROM api_clients", fetch=True)
        active_tokens  = execute_query("SELECT COUNT(*) AS n FROM tokens WHERE status='active'", fetch=True)
        expired_tokens = execute_query("SELECT COUNT(*) AS n FROM tokens WHERE status='expired'", fetch=True)
        revoked_tokens = execute_query("SELECT COUNT(*) AS n FROM tokens WHERE status='revoked'", fetch=True)
        total_requests = execute_query("SELECT COUNT(*) AS n FROM api_requests", fetch=True)
        allowed        = execute_query("SELECT COUNT(*) AS n FROM api_requests WHERE status='allowed'", fetch=True)
        denied         = execute_query("SELECT COUNT(*) AS n FROM api_requests WHERE status='denied'", fetch=True)

        return jsonify({
            "total_clients":  total_clients["n"],
            "active_tokens":  active_tokens["n"],
            "expired_tokens": expired_tokens["n"],
            "revoked_tokens": revoked_tokens["n"],
            "total_requests": total_requests["n"],
            "allowed":        allowed["n"],
            "denied":         denied["n"],
        }), 200

    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 9 : GET /api/scopes
#   Returns all available permission scopes
# ==================================================================
@api.route("/scopes", methods=["GET"])
def get_scopes():
    query = "SELECT scope_id, scope_name, description FROM scopes ORDER BY scope_id"
    try:
        rows = execute_query(query, fetch=True, many=True)
        return jsonify(rows), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# ==================================================================
# ROUTE 10 : GET /api/client/<client_id>/report
#   Full report for one client (calls stored procedure)
# ==================================================================
@api.route("/client/<int:client_id>/report", methods=["GET"])
def client_report(client_id):
    try:
        result = call_procedure("get_client_report", args=(client_id,), out_count=0)
        sets = result["result_sets"]
        return jsonify({
            "client_info":  sets[0] if len(sets) > 0 else [],
            "tokens":       sets[1] if len(sets) > 1 else [],
            "requests":     sets[2] if len(sets) > 2 else [],
        }), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
