import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN storage_limit_mb INTEGER DEFAULT 500")
    print("✅ 'storage_limit_mb' column added.")
except sqlite3.OperationalError:
    print("ℹ️ 'storage_limit_mb' column already exists.")

conn.commit()
conn.close()

print("✅ Done.")