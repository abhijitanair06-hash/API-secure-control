# ============================================================
#  app.py — Flask Application Entry Point
#  PERSON  : Rushab
#  PURPOSE : Start Flask server, enable CORS, register routes
# ============================================================

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import os

# Load environment variables FIRST
load_dotenv()

# Path to frontend folder
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

# ------------------------------------------------------------------
# Create Flask application instance
# ------------------------------------------------------------------
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

# ------------------------------------------------------------------
# Enable CORS — allow all origins including file:// (null origin)
# ------------------------------------------------------------------
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)

# ------------------------------------------------------------------
# Register API routes from api_routes.py (Krishna's module)
# ------------------------------------------------------------------
from api_routes import api as api_blueprint
app.register_blueprint(api_blueprint)

# ------------------------------------------------------------------
# Health check route — quick way to verify server is running
# ------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "message": "API Access Control Backend is running"
    }), 200

# ------------------------------------------------------------------
# Serve frontend dashboard at http://localhost:5000/
# ------------------------------------------------------------------
@app.route("/")
@app.route("/dashboard")
def serve_frontend():
    return send_from_directory(FRONTEND_DIR, "index.html")


# ------------------------------------------------------------------
# Global error handlers
# ------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500

# ------------------------------------------------------------------
# Start the development server
# ------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 5000))
    print(f"\n{'='*55}")
    print(f"  Secure API Access Control — Backend Server")
    print(f"  Running at : http://127.0.0.1:{port}")
    print(f"  Health     : http://127.0.0.1:{port}/health")
    print(f"{'='*55}\n")
    app.run(debug=True, port=port)
