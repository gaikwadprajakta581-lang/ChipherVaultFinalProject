import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS password_resets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    email TEXT NOT NULL,
    token TEXT NOT NULL,

    created_at TEXT,
    expires_at TEXT,

    used INTEGER DEFAULT 0
)
""")

conn.commit()
conn.close()

print("✅ Done. 'password_resets' table created (or already existed).")