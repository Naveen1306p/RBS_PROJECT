# Welcomely

A responsive welcome page with account signup, sign-in, and secure password reset, built with Flask and SQLite.

## Features

- Signup and sign-in with Werkzeug password hashing
- CSRF-protected forms and Flask-Login sessions
- Password reset links with cryptographically random, single-use tokens that expire after 30 minutes
- Generic password-reset confirmation to avoid revealing whether an email is registered
- Responsive landing page and account screens

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "replace-this-with-a-long-random-secret"
python app.py
```

Open http://127.0.0.1:5000. The SQLite database is created in `instance\accounts.sqlite3`. In development, reset links are written to the Flask server log. Use that link to complete a reset.

## Email configuration

Set these environment variables to deliver reset links by email:

```powershell
$env:MAIL_SERVER = "smtp.example.com"
$env:MAIL_PORT = "587"
$env:MAIL_USERNAME = "your-smtp-user"
$env:MAIL_PASSWORD = "your-smtp-password"
$env:MAIL_FROM = "noreply@example.com"
```

## Production

Set `APP_ENV=production`, a unique high-entropy `SECRET_KEY`, and working SMTP settings. Deploy behind HTTPS and a production WSGI server (for example Waitress or Gunicorn where supported); do not use Flask's development server in production. Set `DATABASE_PATH` to a persistent writable path if needed. Configure rate limiting at the reverse proxy or hosting layer before exposing authentication endpoints publicly.

## Tests

```powershell
python -m unittest discover -s tests -v
```
