import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS shares(
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    filename TEXT NOT NULL,

    owner_email TEXT NOT NULL,
    shared_with_email TEXT NOT NULL,

    permission TEXT NOT NULL DEFAULT 'download',

    expires_at TEXT,
    created_at TEXT,

    revoked INTEGER DEFAULT 0
)
""")

conn.commit()
conn.close()

print("✅ Done. 'shares' table created (or already existed).")