import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("database.db")
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute("SELECT id, email, password FROM users")
users = cursor.fetchall()

updated_count = 0

for user in users:

    old_password = user["password"]

    # Already hashed passwords start with a known prefix
    # (werkzeug uses formats like "pbkdf2:sha256:...")
    # Skip if already hashed, so running this script twice is safe.
    if old_password.startswith("pbkdf2:") or old_password.startswith("scrypt:"):
        continue

    new_hashed_password = generate_password_hash(old_password)

    cursor.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (new_hashed_password, user["id"])
    )

    updated_count += 1

    print(f"✅ Migrated: {user['email']}")

conn.commit()
conn.close()

print(f"\nDone. {updated_count} password(s) migrated to hashed format.")