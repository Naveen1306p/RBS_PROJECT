import hashlib
import os
import secrets
import smtplib
import sqlite3
import ssl
from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from flask import (
    Flask,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import EmailField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class User(UserMixin):
    def __init__(self, user_id, email, password_hash):
        self.id = user_id
        self.email = email
        self.password_hash = password_hash


class SignupForm(FlaskForm):
    email = EmailField("Email address", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=10, max=128)],
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = EmailField("Email address", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class ForgotPasswordForm(FlaskForm):
    email = EmailField("Email address", validators=[DataRequired(), Email(), Length(max=254)])
    submit = SubmitField("Send reset link")


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New password",
        validators=[DataRequired(), Length(min=10, max=128)],
    )
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Update password")


class LogoutForm(FlaskForm):
    submit = SubmitField("Sign out")


login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message_category = "info"


def _utc_now():
    return datetime.now(timezone.utc)


def _get_db():
    if "db" not in g:
        db = sqlite3.connect(current_app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        g.db = db
    return g.db


def _init_db(app):
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(app.config["DATABASE"])) as db:
        with db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at TEXT NOT NULL,
                    used_at TEXT
                )
                """
            )
            db.execute("PRAGMA foreign_keys = ON")


def _send_reset_email(email, reset_url):
    host = current_app.config.get("MAIL_SERVER")
    if not host:
        if current_app.config["ENVIRONMENT"] == "development":
            current_app.logger.warning("Password reset link for %s: %s", email, reset_url)
            return
        raise RuntimeError("MAIL_SERVER must be configured to send password reset emails.")

    message = EmailMessage()
    message["Subject"] = "Reset your password"
    message["From"] = current_app.config["MAIL_FROM"]
    message["To"] = email
    message.set_content(
        "We received a request to reset your password.\n\n"
        f"Use this one-time link within 30 minutes:\n{reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )

    port = current_app.config["MAIL_PORT"]
    with smtplib.SMTP(host, port, timeout=15) as server:
        server.starttls(context=ssl.create_default_context())
        username = current_app.config.get("MAIL_USERNAME")
        if username:
            server.login(username, current_app.config["MAIL_PASSWORD"])
        server.send_message(message)


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    default_database = (
        "/tmp/accounts.sqlite3"
        if os.environ.get("VERCEL")
        else str(Path(app.instance_path) / "accounts.sqlite3")
    )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "local-development-key-change-me"),
        DATABASE=os.environ.get("DATABASE_PATH", default_database),
        ENVIRONMENT=os.environ.get("APP_ENV", "development"),
        MAIL_SERVER=os.environ.get("MAIL_SERVER"),
        MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
        MAIL_FROM=os.environ.get("MAIL_FROM", "noreply@example.com"),
        RESET_TOKEN_MINUTES=30,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("APP_ENV") == "production",
    )
    if test_config:
        app.config.update(test_config)
    if app.config["ENVIRONMENT"] == "production":
        if app.config["SECRET_KEY"] == "local-development-key-change-me":
            raise RuntimeError("Set a unique SECRET_KEY before running in production.")
        if not app.config["MAIL_SERVER"]:
            raise RuntimeError("Configure MAIL_SERVER before running in production.")

    _init_db(app)
    login_manager.init_app(app)

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @login_manager.user_loader
    def load_user(user_id):
        row = _get_db().execute(
            "SELECT id, email, password_hash FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        return User(row["id"], row["email"], row["password_hash"])

    @app.context_processor
    def inject_logout_form():
        return {"logout_form": LogoutForm()}

    @app.get("/")
    def home():
        return render_template("home.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = SignupForm()
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            db = _get_db()
            try:
                cursor = db.execute(
                    "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                    (email, generate_password_hash(form.password.data), _utc_now().isoformat()),
                )
                db.commit()
            except sqlite3.IntegrityError:
                form.email.errors.append("An account with this email already exists.")
            else:
                login_user(User(cursor.lastrowid, email, ""))
                flash("Your account is ready. Welcome!", "success")
                return redirect(url_for("dashboard"))
        return render_template("signup.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            row = _get_db().execute(
                "SELECT id, email, password_hash FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            if row is not None and check_password_hash(row["password_hash"], form.password.data):
                login_user(User(row["id"], row["email"], row["password_hash"]))
                flash("You are signed in.", "success")
                return redirect(url_for("dashboard"))
            flash("Email or password is incorrect.", "error")
        return render_template("login.html", form=form)

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.post("/logout")
    @login_required
    def logout():
        form = LogoutForm()
        if form.validate_on_submit():
            logout_user()
            flash("You have been signed out.", "info")
            return redirect(url_for("home"))
        flash("Your sign-out request could not be verified. Please try again.", "error")
        return redirect(url_for("dashboard"))

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        form = ForgotPasswordForm()
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            row = _get_db().execute(
                "SELECT id, email FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            if row is not None:
                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                expires_at = (_utc_now() + timedelta(minutes=app.config["RESET_TOKEN_MINUTES"])).isoformat()
                db = _get_db()
                db.execute(
                    "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                    (_utc_now().isoformat(), row["id"]),
                )
                db.execute(
                    "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    (token_hash, row["id"], expires_at),
                )
                db.commit()
                reset_url = url_for("reset_password", token=raw_token, _external=True)
                try:
                    _send_reset_email(row["email"], reset_url)
                except (OSError, RuntimeError, smtplib.SMTPException):
                    current_app.logger.exception("Could not send password reset email.")
            flash("If an account exists for that email, a reset link has been sent.", "info")
            return redirect(url_for("login"))
        return render_template("forgot_password.html", form=form)

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = _get_db().execute(
            """
            SELECT token_hash, user_id, expires_at, used_at
            FROM password_reset_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if (
            row is None
            or row["used_at"] is not None
            or datetime.fromisoformat(row["expires_at"]) <= _utc_now()
        ):
            flash("That reset link is invalid or has expired. Request a new one.", "error")
            return redirect(url_for("forgot_password"))

        form = ResetPasswordForm()
        if form.validate_on_submit():
            db = _get_db()
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(form.password.data), row["user_id"]),
            )
            db.execute(
                "UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ?",
                (_utc_now().isoformat(), token_hash),
            )
            db.commit()
            flash("Your password has been updated. Sign in with your new password.", "success")
            return redirect(url_for("login"))
        return render_template("reset_password.html", form=form)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=app.config["ENVIRONMENT"] == "development")
