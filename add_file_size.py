import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

try:
    cursor.execute(
        "ALTER TABLE files ADD COLUMN file_size INTEGER DEFAULT 0"
    )
    print("✅ Added column: file_size")
except sqlite3.OperationalError:
    print("ℹ️ Column file_size already exists, skipping.")

conn.commit()
conn.close()

print("\nDone. Database updated with file_size column.")