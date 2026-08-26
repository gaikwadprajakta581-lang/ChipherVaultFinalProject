# Hybrid Encrypted Cloud Storage

## Features
- User registration and login
- Login protection after repeated failed attempts
- AES-256 file encryption
- RSA-2048 protection of per-file AES keys
- Upload, encrypted download, decrypt, delete and recycle bin
- Permanent delete and restore
- File sharing
- Activity log
- Storage quota
- Password change and password reset link
- No 2FA / OTP

## Run on Windows

1. Open PowerShell in this project folder.
2. Install dependencies:
   `py -m pip install -r requirements.txt`
3. Start the application:
   `py app.py`
4. Open:
   `http://127.0.0.1:5000`

Do not run `app.py` by itself in PowerShell. Use `py app.py`.

## Notes
- Keep `keys/private.pem` private.
- The included `database.db` contains the existing users/files from the project.
- The application also creates missing database tables/columns automatically.
