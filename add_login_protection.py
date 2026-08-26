import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Add failed_attempts column (tracks wrong password count)
try:
    cursor.execute(
        "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0"
    )
    print("✅ Added column: failed_attempts")
except sqlite3.OperationalError:
    print("ℹ️ Column failed_attempts already exists, skipping.")

# Add locked_until column (stores lock expiry time as text)
try:
    cursor.execute(
        "ALTER TABLE users ADD COLUMN locked_until TEXT"
    )
    print("✅ Added column: locked_until")
except sqlite3.OperationalError:
    print("ℹ️ Column locked_until already exists, skipping.")

conn.commit()
conn.close()

print("\nDone. Database updated for login protection.")
