import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

try:
    cursor.execute(
        "ALTER TABLE files ADD COLUMN filepath TEXT"
    )
    print("✅ filepath column added successfully.")

except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e).lower():
        print("ℹ️ filepath column already exists.")
    else:
        print("❌ Error:", e)

conn.commit()
conn.close()

print("Done.")