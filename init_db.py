import sqlite3

def initialize_database():
    conn = sqlite3.connect("mailroom.db")
    init_sql = """
    CREATE TABLE IF NOT EXISTS evaluation_state (
        evaluation_id TEXT PRIMARY KEY,
        receipt_verification_key TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS dossier_proposals (
        dossier_id TEXT NOT NULL,
        content_fingerprint TEXT NOT NULL,
        evaluation_id TEXT NOT NULL,
        call_id TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        payload TEXT,
        evidence TEXT NOT NULL,
        raw_dossier_content TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (dossier_id, content_fingerprint)
    );
    CREATE TABLE IF NOT EXISTS committed_receipts (
        receipt_id TEXT PRIMARY KEY,
        evaluation_id TEXT NOT NULL,
        dossier_id TEXT NOT NULL,
        call_id TEXT NOT NULL,
        action TEXT NOT NULL,
        proposal_digest TEXT NOT NULL,
        committed_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.executescript(init_sql)
        conn.commit()
        print("SQLite Database initialized successfully.")
    except Exception as e:
        conn.rollback()
        print(f"Error provisioning database tables: {e}")
        raise e
    finally:
        conn.close()

if __name__ == "__main__":
    initialize_database()
