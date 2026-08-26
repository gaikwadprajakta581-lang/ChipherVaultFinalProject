from flask import Flask, render_template, request, redirect, send_file, session
import sqlite3
import os
import secrets
import shutil
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from encryption import encrypt_file
from decryption import decrypt_file
from rsa_keys import generate_keys
from hybrid_encryption import encrypt_aes_key, decrypt_aes_key


app = Flask(__name__)

# Secret key for login session
app.secret_key = "hybrid-encrypted-cloud-storage-secret-key"
MAX_ATTEMPTS = 5 
# =========================================================
# FOLDERS
# =========================================================

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted_files"
DECRYPTED_FOLDER = "decrypted_files"
KEY_FOLDER = "keys"
RECYCLE_BIN_FOLDER = "recycle_bin"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER
app.config["DECRYPTED_FOLDER"] = DECRYPTED_FOLDER


# Create folders if they don't exist
for folder in [
    UPLOAD_FOLDER,
    ENCRYPTED_FOLDER,
    DECRYPTED_FOLDER,
    KEY_FOLDER
]:
    if not os.path.exists(folder):
        os.makedirs(folder)
if not os.path.exists(RECYCLE_BIN_FOLDER):
    os.makedirs(RECYCLE_BIN_FOLDER)

# =========================================================
# DATABASE
# =========================================================

def get_db():
    # Give SQLite time to wait for another connection instead of
    # immediately raising "database is locked" during concurrent requests.
    conn = sqlite3.connect("database.db", timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def ensure_database():
    """Create all tables/columns needed by the application."""
    conn = sqlite3.connect("database.db", timeout=30)
    cur = conn.cursor()
    cur.execute("PRAGMA busy_timeout = 30000")
    cur.execute("PRAGMA journal_mode = WAL")

    cur.execute("""
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            email TEXT,
            upload_date TEXT,
            file_size INTEGER DEFAULT 0,
            filepath TEXT
        )
    """)
    cur.execute("""
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
    cur.execute("""
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_resets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            created_at TEXT,
            expires_at TEXT,
            used INTEGER DEFAULT 0
        )
    """)

    # Add columns to older databases when they are missing.
    for table, column, definition in [
        ("users", "failed_attempts", "INTEGER DEFAULT 0"),
        ("users", "locked_until", "TEXT"),
        ("users", "storage_limit_mb", "INTEGER DEFAULT 500"),
        ("files", "file_size", "INTEGER DEFAULT 0"),
        ("files", "filepath", "TEXT"),
    ]:
        cols = {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # Remove obsolete 2FA columns from older project databases.
    user_cols = {row[1] for row in cur.execute("PRAGMA table_info(users)")}
    for obsolete in ("otp_code", "otp_expires_at"):
        if obsolete in user_cols:
            try:
                cur.execute(f"ALTER TABLE users DROP COLUMN {obsolete}")
            except sqlite3.OperationalError:
                # If an older SQLite build cannot drop a column, the columns
                # remain unused and do not affect the application.
                pass

    conn.commit()
    conn.close()

ensure_database()


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


# =========================================================
# LOGIN
# =========================================================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        )
        user = cursor.fetchone()

        if user is None:
            conn.close()
            return "Invalid Email or Password"

        # -----------------------------------------------------
        # Check if account is currently locked
        # -----------------------------------------------------

        if user["locked_until"]:

            locked_until = datetime.strptime(
                user["locked_until"], "%Y-%m-%d %H:%M:%S"
            )

            if datetime.now() < locked_until:

                conn.close()

                remaining = int((locked_until - datetime.now()).total_seconds() / 60) + 1

                return f"🔒 Account locked due to too many failed attempts. Try again in {remaining} minute(s)."

        # -----------------------------------------------------
        # Check password
        # -----------------------------------------------------

        if check_password_hash(user["password"], password):

            # Correct password: reset failed attempts and lock
            cursor.execute(
                """
                UPDATE users
                SET failed_attempts = 0, locked_until = NULL
                WHERE email = ?
                """,
                (email,)
            )
            conn.commit()

            session["email"] = email
            session["fullname"] = user["fullname"]
            return redirect("/dashboard")
        else:

            # Wrong password: increment failed attempts
            new_attempts = user["failed_attempts"] + 1

            if new_attempts >= MAX_ATTEMPTS:

                lock_time = datetime.now() + timedelta(minutes=15)

                cursor.execute(
                    """
                    UPDATE users
                    SET failed_attempts = ?, locked_until = ?
                    WHERE email = ?
                    """,
                    (
                        new_attempts,
                        lock_time.strftime("%Y-%m-%d %H:%M:%S"),
                        email
                    )
                )

                conn.commit()
                conn.close()

                return "🔒 Too many failed attempts. Account locked for 15 minutes."

            else:

                cursor.execute(
                    """
                    UPDATE users
                    SET failed_attempts = ?
                    WHERE email = ?
                    """,
                    (new_attempts, email)
                )

                conn.commit()
                conn.close()

                remaining_tries = MAX_ATTEMPTS - new_attempts

                return f"Invalid Email or Password. {remaining_tries} attempt(s) remaining before lock."

    return render_template("login.html")


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        fullname = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not fullname or not email or not password:
            return "All fields are required. Please fill the form completely."

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            conn.close()

            return "Email already registered. Please Login."
        hashed_password = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users(fullname, email, password)
            VALUES (?, ?, ?)
            """,
            (fullname, email, hashed_password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")

# =========================================================
# LOGIN REQUIRED FUNCTION
# =========================================================

def login_required():

    if "email" not in session:
        return False

    return True


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    # Count only current user's files
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM files
        WHERE email = ?
        """,
        (user_email,)
    )

    total_files = cursor.fetchone()[0]

    conn.close()

    # For now decrypted files count is 0.
    # Actual decrypted files are generated only when user decrypts.
    decrypted_files = 0

    return render_template(
        "dashboard.html",
        total_files=total_files,
        decrypted_files=decrypted_files
    )

# ---------------- PROFILE ----------------
@app.route("/profile")
def profile():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (user_email,)
    )
    user = cursor.fetchone()

    cursor.execute(
        "SELECT filename FROM files WHERE email = ?",
        (user_email,)
    )
    rows = cursor.fetchall()

    conn.close()

    # Keep session fullname in sync with the database
    if user:
        session["fullname"] = user["fullname"]

    # -----------------------------------------------------
    # Stats: split user's files into active vs trashed
    # by checking where the physical file currently lives
    # -----------------------------------------------------

    total_files = 0
    trashed_files = 0

    for row in rows:

        filename = row["filename"]

        recycle_path = os.path.join(RECYCLE_BIN_FOLDER, filename)

        if os.path.exists(recycle_path):
            trashed_files += 1
        else:
            total_files += 1

    return render_template(
        "profile.html",
        total_files=total_files,
        trashed_files=trashed_files
    )
# =========================================================
# ACTIVITY LOG HELPER
# =========================================================

def log_activity(user_email, action, details=""):
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO activity_log(user_email, action, details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_email,
                action,
                details,
                request.remote_addr,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )

        conn.commit()
        conn.close()
    except Exception as e:
        print("⚠️ Activity log error:", e)
        # =========================================================
# STORAGE QUOTA HELPERS
# =========================================================

def get_used_storage_bytes(cursor, user_email):
    cursor.execute(
        "SELECT filepath FROM files WHERE email = ?",
        (user_email,)
    )
    rows = cursor.fetchall()

    total = 0
    for row in rows:
        fp = os.path.join(app.config["ENCRYPTED_FOLDER"], row["filepath"])
        if os.path.exists(fp):
            total += os.path.getsize(fp)

    return total


def get_user_quota_mb(cursor, user_email):
    cursor.execute(
        "SELECT storage_limit_mb FROM users WHERE email = ?",
        (user_email,)
    )
    row = cursor.fetchone()

    if row and row["storage_limit_mb"]:
        return row["storage_limit_mb"]

    return 500   # default
# =========================================================
# FILE VERSIONING HELPERS
# =========================================================

def get_next_version_number(cursor, original_filename, owner_email):
    cursor.execute(
        """
        SELECT MAX(version_number) as max_v FROM file_versions
        WHERE original_filename = ? AND owner_email = ?
        """,
        (original_filename, owner_email)
    )
    row = cursor.fetchone()
    if row and row["max_v"]:
        return row["max_v"] + 1
    return 1


def save_new_version(cursor, original_filename, stored_filename, owner_email, file_size):
    # पूर्वीचं current version असेल तर ते unset करा
    cursor.execute(
        """
        UPDATE file_versions SET is_current = 0
        WHERE original_filename = ? AND owner_email = ?
        """,
        (original_filename, owner_email)
    )

    version_number = get_next_version_number(cursor, original_filename, owner_email)

    cursor.execute(
        """
        INSERT INTO file_versions(
            original_filename, version_number, stored_filename,
            owner_email, file_size, uploaded_at, is_current
        )
        VALUES (?, ?, ?, ?, ?, ?, 1)
        """,
        (
            original_filename, version_number, stored_filename,
            owner_email, file_size, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    return version_number
# =========================================================
# UPLOAD + ENCRYPT
# =========================================================

# =========================================================
# UPLOAD + ENCRYPT
# =========================================================

@app.route("/upload", methods=["POST"])
def upload():

    if not login_required():
        return redirect("/login")

    # -----------------------------------------------------
    # Check file
    # -----------------------------------------------------

    file = request.files.get("file")

    if file is None or file.filename == "":
        return "No file selected."

    # -----------------------------------------------------
    # Current logged-in user
    # -----------------------------------------------------

    user_email = session.get("email")

    if not user_email:
        return redirect("/login")

    # -----------------------------------------------------
    # Open database
    # -----------------------------------------------------

    conn = get_db()
    cursor = conn.cursor()

    # -----------------------------------------------------
    # Storage quota
    # -----------------------------------------------------

    used_bytes = get_used_storage_bytes(
        cursor,
        user_email
    )

    quota_mb = get_user_quota_mb(
        cursor,
        user_email
    )

    quota_bytes = quota_mb * 1024 * 1024

    # -----------------------------------------------------
    # Check uploaded file size
    # -----------------------------------------------------

    file.seek(0)

    file_data = file.read()

    incoming_file_size = len(file_data)

    file.seek(0)

    if used_bytes + incoming_file_size > quota_bytes:

        conn.close()

        return render_template(
            "upload.html",
            error=(
                f"❌ Storage limit exceeded! "
                f"You have used "
                f"{round(used_bytes / 1024 / 1024, 2)} MB "
                f"of {quota_mb} MB."
            )
        )

    # -----------------------------------------------------
    # Secure filename
    # -----------------------------------------------------

    original_filename = secure_filename(
        file.filename
    )

    if original_filename == "":
        conn.close()
        return "Invalid filename."

    # -----------------------------------------------------
    # Save original file temporarily
    # -----------------------------------------------------

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        original_filename
    )

    file.save(filepath)

    # -----------------------------------------------------
    # Encrypt file using AES-256
    # -----------------------------------------------------

    encrypted_filename = (
        original_filename + ".enc"
    )

    encrypted_path = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        encrypted_filename
    )

    aes_key = encrypt_file(
        filepath,
        encrypted_path
    )

    # -----------------------------------------------------
    # Encrypt AES key using RSA-2048
    # -----------------------------------------------------

    encrypt_aes_key(
        aes_key,
        original_filename
    )

    # -----------------------------------------------------
    # Encrypted file size
    # -----------------------------------------------------

    file_size = os.path.getsize(
        encrypted_path
    )

    # -----------------------------------------------------
    # Save file information
    # -----------------------------------------------------

    cursor.execute(
        """
        INSERT INTO files
        (
            filename,
            email,
            upload_date,
            file_size,
            filepath
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            encrypted_filename,
            user_email,
            datetime.now().strftime(
                "%d-%m-%Y %H:%M"
            ),
            file_size,
            encrypted_filename
        )
    )

    conn.commit()
    conn.close()

    # -----------------------------------------------------
    # Delete original unencrypted file
    # -----------------------------------------------------

    if os.path.exists(filepath):
        os.remove(filepath)

    # -----------------------------------------------------
    # Activity log
    # -----------------------------------------------------

    log_activity(
        user_email,
        "UPLOAD",
        f"Uploaded file: {original_filename}"
    )

    # -----------------------------------------------------
    # Done
    # -----------------------------------------------------

    return redirect("/myfiles")

# =========================================================
# DECRYPT INDEX
# =========================================================

@app.route("/decrypt")
def decrypt_index():

    if not login_required():
        return redirect("/login")

    return redirect("/myfiles")


# =========================================================
# DECRYPT FILE
# =========================================================

@app.route("/decrypt/<filename>")
def decrypt(filename):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    # -----------------------------------------------------
    # Check file ownership
    # -----------------------------------------------------

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM files
        WHERE filename = ? AND email = ?
        """,
        (filename, user_email)
    )

    file_record = cursor.fetchone()

    conn.close()

    if file_record is None:
        return "❌ Access Denied: This file does not belong to your account."

    # -----------------------------------------------------
    # Original filename
    # -----------------------------------------------------

    original_name = filename.replace(".enc", "")

    # -----------------------------------------------------
    # Encrypted file
    # -----------------------------------------------------

    encrypted_file = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        filename
    )

    if not os.path.exists(encrypted_file):
        return "Encrypted file not found."

    # -----------------------------------------------------
    # Get AES key using RSA
    # -----------------------------------------------------

    aes_key = decrypt_aes_key(original_name)

    # -----------------------------------------------------
    # Output file
    # -----------------------------------------------------

    output_file = os.path.join(
        app.config["DECRYPTED_FOLDER"],
        original_name
    )

    # -----------------------------------------------------
    # Decrypt
    # -----------------------------------------------------

    decrypt_file(
        encrypted_file,
        output_file,
        aes_key
    )

    # -----------------------------------------------------
    # Download decrypted file
    # -----------------------------------------------------

    return send_file(
        output_file,
        as_attachment=True,
        download_name=original_name
    )


# =========================================================
# MY FILES
# =========================================================

@app.route("/myfiles")
def myfiles():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    search = request.args.get("search", "")

    conn = get_db()
    cursor = conn.cursor()

    # IMPORTANT:
    # Only current user's files are selected
    if search:

        cursor.execute(
            """
            SELECT filename, upload_date, file_size
            FROM files
            WHERE email = ?
            AND filename LIKE ?
            ORDER BY id DESC
            """,
            (
                user_email,
                "%" + search + "%"
            )
        )

    else:

        cursor.execute(
            """
            SELECT filename, upload_date, file_size
            FROM files
            WHERE email = ?
            ORDER BY id DESC
            """,
            (user_email,)
        )

    rows = cursor.fetchall()

    conn.close()

    # -----------------------------------------------------
    # Build file list with human-readable size
    # -----------------------------------------------------

    files = []
    total_storage = 0

    for row in rows:

        size_bytes = row["file_size"] or 0
        total_storage += size_bytes

        if size_bytes >= 1024 * 1024:
            size_display = f"{size_bytes / (1024 * 1024):.2f} MB"
        elif size_bytes >= 1024:
            size_display = f"{size_bytes / 1024:.2f} KB"
        else:
            size_display = f"{size_bytes} B"

        files.append({
            "filename": row["filename"],
            "upload_date": row["upload_date"] or "Unknown",
            "size": size_display
        })

    if total_storage >= 1024 * 1024:
        total_storage_display = f"{total_storage / (1024 * 1024):.2f} MB"
    elif total_storage >= 1024:
        total_storage_display = f"{total_storage / 1024:.2f} KB"
    else:
        total_storage_display = f"{total_storage} B"

    return render_template(
        "myfiles.html",
        files=files,
        search=search,
        total_storage=total_storage_display
    )

# =========================================================
# DOWNLOAD ENCRYPTED FILE
# =========================================================

@app.route("/download/<filename>")
def download(filename):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    # -----------------------------------------------------
    # Check ownership
    # -----------------------------------------------------

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM files
        WHERE filename = ? AND email = ?
        """,
        (filename, user_email)
    )

    file_record = cursor.fetchone()

    conn.close()

    if file_record is None:
        return "❌ Access Denied: You cannot download this file."

    # -----------------------------------------------------
    # File path
    # -----------------------------------------------------

    filepath = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        filename
    )

    if not os.path.exists(filepath):
        return "File Not Found!"

    original_name = filename[:-4] if filename.endswith(".enc") else filename

    response = send_file(
        filepath,
        as_attachment=True,
        download_name=original_name
    )
    log_activity(user_email, "DOWNLOAD", f"Downloaded file: {filename}")
    return response


# =========================================================
# DELETE FILE
# =========================================================

# ---------------- MOVE FILE TO RECYCLE BIN ----------------

@app.route("/delete/<filename>")
def delete_file(filename):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    # -----------------------------------------------------
    # Check ownership
    # -----------------------------------------------------

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM files WHERE filename = ? AND email = ?",
        (filename, user_email)
    )

    file_record = cursor.fetchone()

    conn.close()

    if file_record is None:
        return "❌ Access Denied: This file does not belong to your account."

    encrypted_path = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        filename
    )

    recycle_path = os.path.join(
        RECYCLE_BIN_FOLDER,
        filename
    )

    if not os.path.exists(encrypted_path):
        return "File Not Found!"

    # Move encrypted file to Recycle Bin
    shutil.move(
        encrypted_path,
        recycle_path
    )

    # Move AES key also
    original_name = filename.replace(".enc", "")

    key_path = os.path.join(
        "keys",
        original_name + ".key"
    )

    recycle_key_path = os.path.join(
        RECYCLE_BIN_FOLDER,
        original_name + ".key"
    )

    if os.path.exists(key_path):
        shutil.move(
            key_path,
            recycle_key_path
        )

    log_activity(user_email, "DELETE", f"Moved file to Recycle Bin: {filename}")
    return redirect("/myfiles")


# =========================================================
# RECYCLE BIN
# =========================================================

@app.route("/trash")
def trash():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT filename, file_size, upload_date
        FROM files
        WHERE email = ?
        ORDER BY id DESC
        """,
        (user_email,)
    )

    rows = cursor.fetchall()

    conn.close()

    # Only show files that are actually sitting in the
    # recycle bin folder right now
    files = []

    for row in rows:

        filename = row["filename"]

        recycle_path = os.path.join(
            RECYCLE_BIN_FOLDER,
            filename
        )

        if os.path.exists(recycle_path):
            files.append({
                "filename": filename,
                "size": row["file_size"] if "file_size" in row.keys() else None,
                "deleted_at": row["upload_date"] if "upload_date" in row.keys() else None
            })

    return render_template("trash.html", files=files)

# =========================================================
# FILE VERSIONS
# =========================================================
@app.route("/versions")
def versions():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT filename, file_size, upload_date
        FROM files
        WHERE email = ?
        ORDER BY id DESC
        """,
        (user_email,)
    )

    rows = cursor.fetchall()

    conn.close()

    versions = []

    for row in rows:

        versions.append({
            "filename": row["filename"],
            "version": 1,
            "size": row["file_size"],
            "created_at": row["upload_date"]
        })

    return render_template(
        "versions.html",
        versions=versions
    )
# ---------------- RESTORE FILE FROM RECYCLE BIN ----------------

@app.route("/restore/<filename>")
def restore(filename):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    # -----------------------------------------------------
    # Check ownership
    # -----------------------------------------------------

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM files WHERE filename = ? AND email = ?",
        (filename, user_email)
    )

    file_record = cursor.fetchone()

    conn.close()

    if file_record is None:
        return "❌ Access Denied: This file does not belong to your account."

    recycle_path = os.path.join(
        RECYCLE_BIN_FOLDER,
        filename
    )

    encrypted_path = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        filename
    )

    if not os.path.exists(recycle_path):
        return "File Not Found in Recycle Bin!"

    # Move encrypted file back to encrypted_files
    shutil.move(
        recycle_path,
        encrypted_path
    )

    # Move AES key back also
    original_name = filename.replace(".enc", "")

    recycle_key_path = os.path.join(
        RECYCLE_BIN_FOLDER,
        original_name + ".key"
    )

    key_path = os.path.join(
        "keys",
        original_name + ".key"
    )

    if os.path.exists(recycle_key_path):
        shutil.move(
            recycle_key_path,
            key_path
        )

    log_activity(user_email, "RESTORE", f"Restored file: {filename}")
    return redirect("/myfiles")


# ---------------- PERMANENTLY DELETE FILE ----------------

@app.route("/permanent-delete/<filename>")
def permanent_delete(filename):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    # -----------------------------------------------------
    # Check ownership
    # -----------------------------------------------------

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM files WHERE filename = ? AND email = ?",
        (filename, user_email)
    )

    file_record = cursor.fetchone()

    if file_record is None:
        conn.close()
        return "❌ Access Denied: This file does not belong to your account."

    recycle_path = os.path.join(
        RECYCLE_BIN_FOLDER,
        filename
    )

    original_name = filename.replace(".enc", "")

    recycle_key_path = os.path.join(
        RECYCLE_BIN_FOLDER,
        original_name + ".key"
    )

    if os.path.exists(recycle_path):
        os.remove(recycle_path)

    if os.path.exists(recycle_key_path):
        os.remove(recycle_key_path)

    # Remove the DB record too — file is gone for good
    cursor.execute(
        "DELETE FROM files WHERE filename = ? AND email = ?",
        (filename, user_email)
    )

    conn.commit()
    conn.close()

    log_activity(user_email, "PERMANENT_DELETE", f"Permanently deleted file: {filename}")
    return redirect("/trash")
# =========================================================
# FILE VERSION HISTORY
# =========================================================

@app.route("/versions/<filename>")
def file_versions(filename):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM file_versions
        WHERE original_filename = ? AND owner_email = ?
        ORDER BY version_number DESC
        """,
        (filename, user_email)
    )

    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return "❌ No version history found for this file."

    versions = [dict(row) for row in rows]

    return render_template("versions.html", filename=filename, versions=versions)


# ---------------- DOWNLOAD A SPECIFIC VERSION ----------------

@app.route("/download-version/<int:version_id>")
def download_version(version_id):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM file_versions WHERE id = ? AND owner_email = ?",
        (version_id, user_email)
    )
    version_record = cursor.fetchone()
    conn.close()

    if version_record is None:
        return "❌ Access Denied: This version does not belong to you."

    filepath = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        version_record["stored_filename"]
    )

    if not os.path.exists(filepath):
        return "File Not Found!"

    return send_file(filepath, as_attachment=True)


# ---------------- RESTORE AN OLD VERSION AS CURRENT ----------------

@app.route("/restore-version/<int:version_id>")
def restore_version(version_id):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM file_versions WHERE id = ? AND owner_email = ?",
        (version_id, user_email)
    )
    version_record = cursor.fetchone()

    if version_record is None:
        conn.close()
        return "❌ Access Denied: This version does not belong to you."

    cursor.execute(
        """
        UPDATE file_versions SET is_current = 0
        WHERE original_filename = ? AND owner_email = ?
        """,
        (version_record["original_filename"], user_email)
    )

    cursor.execute(
        "UPDATE file_versions SET is_current = 1 WHERE id = ?",
        (version_id,)
    )

    # main files table मधलं pointer पण update करा जेणेकरून normal download restored version देईल
    cursor.execute(
        "UPDATE files SET filename = ? WHERE filename = ? AND email = ?",
        (version_record["stored_filename"], version_record["original_filename"], user_email)
    )

    conn.commit()
    conn.close()

    return redirect(f"/versions/{version_record['original_filename']}")
# =========================================================
# SECURE FILE SHARING
# =========================================================

@app.route("/share/<filename>", methods=["GET", "POST"])
def share_file(filename):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    # Confirm the file belongs to the current user
    cursor.execute(
        "SELECT * FROM files WHERE filename = ? AND email = ?",
        (filename, user_email)
    )
    file_record = cursor.fetchone()

    if file_record is None:
        conn.close()
        return "❌ Access Denied: This file does not belong to your account."

    if request.method == "POST":

        shared_with_email = request.form.get("shared_with_email", "").strip().lower()
        permission = request.form.get("permission", "download")
        expiry_days = request.form.get("expiry_days", "7")

        if not shared_with_email:
            conn.close()
            return render_template(
                "share.html",
                filename=filename,
                error="Please enter an email to share with."
            )

        if shared_with_email == user_email:
            conn.close()
            return render_template(
                "share.html",
                filename=filename,
                error="You cannot share a file with yourself."
            )

        # The recipient must be a registered user
        cursor.execute(
            "SELECT * FROM users WHERE email = ?",
            (shared_with_email,)
        )
        target_user = cursor.fetchone()

        if target_user is None:
            conn.close()
            return render_template(
                "share.html",
                filename=filename,
                error="No registered user found with that email."
            )

        try:
            expiry_days_int = int(expiry_days)
        except ValueError:
            expiry_days_int = 7

        expires_at = (
            datetime.now() + timedelta(days=expiry_days_int)
        ).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            INSERT INTO shares(
                filename, owner_email, shared_with_email,
                permission, expires_at, created_at, revoked
            )
            VALUES (?, ?, ?, ?, ?, ?, 0)
            """,
            (
                filename,
                user_email,
                shared_with_email,
                permission,
                expires_at,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )

        conn.commit()
        conn.close()

        log_activity(
            user_email,
            "SHARE",
            f"Shared '{filename}' with {shared_with_email}"
        )
        return redirect("/my-shares")

    conn.close()
    return render_template("share.html", filename=filename)

# ---------------- MY SHARES (files I shared) ----------------

@app.route("/my-shares")
def my_shares():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM shares
        WHERE owner_email = ?
        ORDER BY id DESC
        """,
        (user_email,)
    )

    rows = cursor.fetchall()

    conn.close()

    shares = []
    now = datetime.now()

    for row in rows:

        expired = False

        if row["expires_at"]:
            expires_dt = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
            if now > expires_dt:
                expired = True

        shares.append({
            "id": row["id"],
            "filename": row["filename"],
            "shared_with_email": row["shared_with_email"],
            "permission": row["permission"],
            "expires_at": row["expires_at"],
            "revoked": bool(row["revoked"]),
            "expired": expired
        })

    return render_template("my_shares.html", shares=shares)


# ---------------- SHARED WITH ME ----------------

@app.route("/shared-with-me")
def shared_with_me():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM shares
        WHERE shared_with_email = ? AND revoked = 0
        ORDER BY id DESC
        """,
        (user_email,)
    )

    rows = cursor.fetchall()

    conn.close()

    now = datetime.now()
    shares = []

    for row in rows:

        if row["expires_at"]:
            expires_dt = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
            if now > expires_dt:
                continue

        shares.append({
            "id": row["id"],
            "filename": row["filename"],
            "owner_email": row["owner_email"],
            "permission": row["permission"],
            "expires_at": row["expires_at"]
        })

    return render_template("shared_with_me.html", shares=shares)


# ---------------- DOWNLOAD A SHARED FILE ----------------

@app.route("/shared-download/<int:share_id>")
def shared_download(share_id):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM shares WHERE id = ? AND shared_with_email = ?",
        (share_id, user_email)
    )
    share_record = cursor.fetchone()

    conn.close()

    if share_record is None:
        return "❌ Access Denied: This file has not been shared with you."

    if share_record["revoked"]:
        return "❌ This share has been revoked by the owner."

    if share_record["expires_at"]:
        expires_dt = datetime.strptime(share_record["expires_at"], "%Y-%m-%d %H:%M:%S")
        if datetime.now() > expires_dt:
            return "⏰ This share link has expired."

    filename = share_record["filename"]

    filepath = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        filename
    )

    if not os.path.exists(filepath):
        return "File Not Found!"

    return send_file(
        filepath,
        as_attachment=True
    )


# ---------------- REVOKE A SHARE ----------------

@app.route("/revoke-share/<int:share_id>")
def revoke_share(share_id):

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM shares WHERE id = ? AND owner_email = ?",
        (share_id, user_email)
    )
    share_record = cursor.fetchone()

    if share_record is None:
        conn.close()
        return "❌ Access Denied: This share does not belong to you."

    cursor.execute(
        "UPDATE shares SET revoked = 1 WHERE id = ?",
        (share_id,)
    )

    conn.commit()
    conn.close()

    log_activity(user_email, "REVOKE_SHARE", f"Revoked share id {share_id}")
    return redirect("/my-shares")
# =========================================================
# CHANGE PASSWORD
# =========================================================

@app.route("/change-password", methods=["GET", "POST"])
def change_password():

    if not login_required():
        return redirect("/login")

    if request.method == "POST":

        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        user_email = session["email"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email = ?",
            (user_email,)
        )
        user = cursor.fetchone()

        # -----------------------------------------------------
        # Verify current password is correct
        # -----------------------------------------------------

        if not user or not check_password_hash(user["password"], current_password):
            conn.close()
            return render_template(
                "change_password.html",
                error="❌ Current password is incorrect."
            )

        # -----------------------------------------------------
        # Verify new passwords match
        # -----------------------------------------------------

        if new_password != confirm_password:
            conn.close()
            return render_template(
                "change_password.html",
                error="❌ New passwords do not match."
            )

        if len(new_password) < 6:
            conn.close()
            return render_template(
                "change_password.html",
                error="❌ New password must be at least 6 characters."
            )

        # -----------------------------------------------------
        # Save new hashed password
        # -----------------------------------------------------

        new_hashed_password = generate_password_hash(new_password)

        cursor.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (new_hashed_password, user_email)
        )

        conn.commit()
        conn.close()

        return render_template(
            "change_password.html",
            success="✅ Password changed successfully."
        )

    return render_template("change_password.html")
# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")

# =========================================================
# VIEW ACTIVITY LOG
# =========================================================

@app.route("/activity-log")
def activity_log():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM activity_log
        WHERE user_email = ?
        ORDER BY id DESC
        LIMIT 100
        """,
        (user_email,)
    )

    rows = cursor.fetchall()
    conn.close()

    logs = [dict(row) for row in rows]

    return render_template("activity_log.html", logs=logs)
# =========================================================
# STORAGE USAGE
# =========================================================

@app.route("/storage-usage")
def storage_usage():

    if not login_required():
        return redirect("/login")

    user_email = session["email"]

    conn = get_db()
    cursor = conn.cursor()

    used_bytes = get_used_storage_bytes(cursor, user_email)
    quota_mb = get_user_quota_mb(cursor, user_email)

    conn.close()

    used_mb = round(used_bytes / 1024 / 1024, 2)
    percent_used = round((used_mb / quota_mb) * 100, 1) if quota_mb else 0

    return render_template(
        "storage_usage.html",
        used_mb=used_mb,
        quota_mb=quota_mb,
        percent_used=min(percent_used, 100)
    )
# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        # Do not reveal whether an email exists in a real deployment.
        if user is None:
            conn.close()
            return render_template(
                "forgot_password.html",
                message="If that email is registered, a reset link will be generated."
            )

        token = secrets.token_urlsafe(32)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expires_at = (
            datetime.now() + timedelta(minutes=30)
        ).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            "INSERT INTO password_resets(email, token, created_at, expires_at, used) "
            "VALUES (?, ?, ?, ?, 0)",
            (email, token, created_at, expires_at)
        )
        conn.commit()
        conn.close()

        reset_link = f"/reset-password/{token}"
        return render_template(
            "forgot_password.html",
            message="Reset link generated successfully.",
            reset_link=reset_link
        )

    return render_template("forgot_password.html")


# ---------------- RESET PASSWORD (via token) ----------------

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM password_resets WHERE token = ?",
        (token,)
    )
    reset_record = cursor.fetchone()

    if reset_record is None:
        conn.close()
        return "❌ Invalid or expired reset link."

    if reset_record["used"]:
        conn.close()
        return "❌ This reset link has already been used."

    expires_dt = datetime.strptime(reset_record["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.now() > expires_dt:
        conn.close()
        return "⏰ This reset link has expired. Please request a new one."

    if request.method == "POST":

        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_password or len(new_password) < 6:
            conn.close()
            return render_template(
                "reset_password.html",
                token=token,
                error="Password must be at least 6 characters."
            )

        if new_password != confirm_password:
            conn.close()
            return render_template(
                "reset_password.html",
                token=token,
                error="Passwords do not match."
            )

        hashed_password = generate_password_hash(new_password)

        cursor.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (hashed_password, reset_record["email"])
        )

        cursor.execute(
            "UPDATE password_resets SET used = 1 WHERE token = ?",
            (token,)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    conn.close()

    return render_template("reset_password.html", token=token)
# =========================================================
# RUN APP
# =========================================================

if __name__ == "__main__":

    app.run(debug=True)