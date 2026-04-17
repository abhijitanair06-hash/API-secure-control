# ============================================================
#  db.py — Database Connection Manager
#  PERSON  : Krishna
#  PURPOSE : Creates and manages MySQL connections using .env
# ============================================================

import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()


def get_connection():
    """
    Opens and returns a new MySQL database connection.
    Reads credentials from environment variables (.env).
    Raises an exception if connection fails.
    """
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", 3306)),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "api_security_db"),
            autocommit=False          # We control commits explicitly
        )
        return connection
    except Error as e:
        raise ConnectionError(f"[DB] Failed to connect to MySQL: {e}")


def execute_query(query, params=None, fetch=False, many=False):
    """
    Executes a SQL query.

    Args:
        query  (str)  : The SQL statement to run.
        params (tuple): Optional parameters for parameterized queries.
        fetch  (bool) : If True, returns fetched rows (SELECT).
        many   (bool) : If True, returns all rows; else returns first row.

    Returns:
        list | dict | None
    """
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)   # rows as dicts
        cursor.execute(query, params or ())

        if fetch:
            if many:
                result = cursor.fetchall()
            else:
                result = cursor.fetchone()
            return result
        else:
            connection.commit()
            return {"affected_rows": cursor.rowcount,
                    "last_insert_id": cursor.lastrowid}

    except Error as e:
        if connection:
            connection.rollback()
        raise RuntimeError(f"[DB] Query error: {e}")
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def call_procedure(proc_name, args=(), out_count=0):
    """
    Calls a stored procedure using raw SQL (SET @var + CALL + SELECT @var).
    This approach works reliably across all mysql-connector-python versions.

    Args:
        proc_name (str)   : Name of the stored procedure.
        args      (tuple) : All params (IN first, then OUT placeholders as '').
        out_count (int)   : Number of OUT parameters at the END of args.

    Returns:
        dict: { 'result_sets': [...], 'out_params': [...] }
    """
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        in_count  = len(args) - out_count
        in_args   = args[:in_count]

        # Build: SET @out0='', @out1='', ...
        out_vars  = [f"@_out{i}" for i in range(out_count)]
        if out_vars:
            set_sql = "SET " + ", ".join(f"{v}=''" for v in out_vars)
            cursor.execute(set_sql)

        # Build: CALL proc(?, ?, ..., @out0, @out1, ...)
        in_placeholders  = ["%s"] * in_count
        all_placeholders = in_placeholders + out_vars
        call_sql = f"CALL {proc_name}({', '.join(all_placeholders)})"
        cursor.execute(call_sql, in_args)
        connection.commit()

        # Collect SELECT result sets emitted during the procedure
        result_sets = []
        try:
            # Consume all result sets from the CALL
            while True:
                rows = cursor.fetchall()
                if rows:
                    result_sets.append(rows)
                if not cursor.nextset():
                    break
        except Exception:
            pass

        # Fetch OUT param values
        out_params = []
        if out_vars:
            cursor.execute(f"SELECT {', '.join(out_vars)}")
            row = cursor.fetchone()
            if row:
                out_params = list(row.values())

        return {
            "result_sets": result_sets,
            "out_params": out_params
        }

    except Error as e:
        if connection:
            try: connection.rollback()
            except: pass
        raise RuntimeError(f"[DB] Procedure error: {e}")
    finally:
        if cursor:
            try: cursor.close()
            except: pass
        if connection and connection.is_connected():
            connection.close()



