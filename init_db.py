import os
import psycopg2 # Use sqlite3 if deploying with an embedded local file engine

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost:5432/mailroom_db")

INIT_SQL = """
CREATE TABLE IF NOT EXISTS evaluation_state (
    evaluation_id TEXT PRIMARY KEY,
    receipt_verification_key TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dossier_proposals (
    dossier_id TEXT NOT NULL,
    content_fingerprint TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target JSONB,  -- Notice change from TEXT to JSONB to match structured targets
    payload JSONB,
    evidence TEXT NOT NULL,
    raw_dossier_content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (dossier_id, content_fingerprint)
);

CREATE TABLE IF NOT EXISTS committed_receipts (
    receipt_id TEXT PRIMARY KEY,
    evaluation_id TEXT NOT NULL,
    dossier_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    action TEXT NOT NULL,
    proposal_digest TEXT NOT NULL,
    committed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
"""

def initialize_database():
    """Establishes connection and provisions the schema state."""
    # Note: If using SQLite, substitute with: sqlite3.connect("mailroom.db")
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cursor:
            cursor.execute(INIT_SQL)
        conn.commit()
        print("Database schema successfully verified and deployed.")
    except Exception as e:
        conn.rollback()
        print(f"Failed to provision tables: {e}")
        raise e
    finally:
        conn.close()

if __name__ == "__main__":
    initialize_database()
