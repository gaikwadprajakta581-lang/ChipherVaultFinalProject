import sqlite3

DB_NAME = "database.db"

conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT,
    storage_limit_mb INTEGER DEFAULT 500
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS files(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    email TEXT,
    upload_date TEXT,
    file_size INTEGER DEFAULT 0,
    filepath TEXT
)
""")

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

print("Database ready successfully.")
