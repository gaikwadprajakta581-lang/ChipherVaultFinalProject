import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS file_versions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    original_filename TEXT NOT NULL,
    version_number INTEGER NOT NULL,

    stored_filename TEXT NOT NULL,
    owner_email TEXT NOT NULL,

    file_size INTEGER,
    uploaded_at TEXT,

    is_current INTEGER DEFAULT 1
)
""")

conn.commit()
conn.close()

print("✅ Done. 'file_versions' table created (or already existed).")