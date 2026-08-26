import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS activity_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_email TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,

    ip_address TEXT,
    timestamp TEXT
)
""")

conn.commit()
conn.close()

print("✅ Done. 'activity_log' table created (or already existed).")