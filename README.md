# Secure API Access Control using DBMS

## 📌 Overview
This project is a full-stack web application that demonstrates a robust, secure API access control system managed through a relational database. It simulates how modern platforms manage API keys, access tokens, scopes, and client permissions while maintaining a strict audit trail of every request.

## 🛠️ Tech Stack
- **Database:** MySQL 8.x
- **Backend:** Python / Flask
- **Frontend:** HTML5, CSS3, Vanilla JavaScript

## 🏗️ Project Structure
```text
DBMS/
│
├── backend/                  # Python Flask API server
│   ├── app.py                # Application entry point
│   ├── api_routes.py         # Flask routing and logic
│   ├── db.py                 # Database connection handling
│   ├── requirements.txt      # Python dependencies
│   └── .env                  # Environment variables (DB credentials)
│
├── frontend/                 # Web interface
│   ├── index.html            # Dashboard HTML
│   ├── style.css             # UI styling
│   └── script.js             # API integration and dynamic UI logic
│
└── *.sql                     # Database schema, triggers, and routines
```

## 🗄️ Database Architecture

### Core Tables
- `api_clients` - Registers API consumers/applications.
- `scopes` - Defines available permissions (e.g., `read:data`, `write:data`).
- `tokens` - Stores access tokens along with their status (active, revoked, expired).
- `token_scopes` - Junction table for many-to-many relationship between tokens and scopes.
- `api_requests` - Logs every API call made and its verdict (allow/deny).
- `audit_logs` - Maintains an immutable security trail for system changes.

### Database Logic
The system heavily utilizes native DBMS features for integrity and security:
- **Triggers (6):** Automate token expiration, status changes, and insert detailed audit logs for client and token modifications.
- **Stored Procedures (4):**
  - `validate_api_request`: The core logic that checks token validity and returns an allow/deny verdict.
  - `issue_token`: Generates a token and securely assigns scopes.
  - `revoke_token`: Revokes a token securely by its hash.
  - `get_client_report`: Generates a full summary report for a client.
- **Transactions:** Ensures atomic operations for registering clients + issuing tokens, and deactivating clients + revoking tokens.

### Token Validation Flow
1. Token found? -> `NO: DENY`
2. Client active? -> `NO: DENY`
3. Status = revoked? -> `YES: DENY`
4. Token expired? -> `YES: DENY`
5. Has required scope? -> `NO: DENY`
6. All checks pass -> `ALLOW`

## 🚀 Setup & Installation

### 1. Database Initialization
You can execute the SQL scripts via MySQL Workbench or the `mysql` CLI.
Either run the master script:
```sql
SOURCE MASTER_SETUP.sql;
```

**OR** run them in the following sequence:
1. `01_schema.sql` (Creates tables & indexes)
2. `02_sample_data.sql` (Inserts initial data)
3. `03_triggers.sql` (Loads database triggers)
4. `04_stored_procedures.sql` (Loads procedures)
5. `05_transactions.sql` (Demo transactions)
6. `06_queries.sql` (Analytical queries)
7. `07_demo_run.sql` (Full presentation demo)

### 2. Backend Setup
1. Navigate to the `backend` directory:
   ```bash
   cd backend
   ```
2. (Optional but recommended) Create and activate a virtual environment.
3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure your environment variables. Ensure your `.env` file has your MySQL credentials:
   ```env
   DB_HOST=localhost
   DB_USER=your_mysql_username
   DB_PASS=your_mysql_password
   DB_NAME=api_access_control
   ```
5. Start the Flask server:
   ```bash
   python app.py
   ```

### 3. Frontend Setup
The frontend runs entirely in the browser using Vanilla JS.
1. Simply open `frontend/index.html` in any modern web browser.
2. Ensure the backend server is running so the dashboard can fetch and display real-time data.
