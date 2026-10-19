import csv
import getpass
import hashlib
import hmac
import io
import os
import secrets
import smtplib
import sqlite3
import ssl
import sys
import time
from datetime import timedelta
from email.message import EmailMessage

from flask import (Flask, Response, abort, g, jsonify, redirect,
                   render_template_string, request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

DB = os.environ.get("DB_PATH", "/var/lib/overtime/overtime.db")
MIN_PW = 8
MAX_FAILS = 5        # failed logins allowed per IP...
FAIL_WINDOW = 600    # ...within this many seconds
RESET_TTL = 600      # an emailed reset code works for this many seconds...
RESET_TRIES = 5      # ...and for this many guesses

app = Flask(__name__)
# Trust one proxy hop (nginx proxy manager) for client IP / scheme / host
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=90),
)

FAILS = {}


@app.before_request
def _nonce():
    # per-request nonce for the inline <script>/<style> blocks, used by the CSP below
    g.csp_nonce = secrets.token_urlsafe(16)


@app.after_request
def _security_headers(resp):
    nonce = g.get("csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# ---------- database ----------

def get_setting(conn, key):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_setting(conn, key, value):
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def new_epoch():
    return secrets.token_hex(8)


# Companies belong to one user; a name only has to be unique within that user's bank.
COMPANIES_SQL = (
    "CREATE TABLE IF NOT EXISTS {} ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "user_id INTEGER REFERENCES users(id),"
    "name TEXT NOT NULL COLLATE NOCASE,"
    "UNIQUE (user_id, name))"
)


def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "day TEXT NOT NULL,"
        "hours REAL NOT NULL,"
        "note TEXT DEFAULT '')"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
        "pw_hash TEXT NOT NULL,"
        "is_admin INTEGER NOT NULL DEFAULT 0,"
        "disabled INTEGER NOT NULL DEFAULT 0,"
        "epoch TEXT NOT NULL)"
    )
    if "email" not in [r[1] for r in conn.execute("PRAGMA table_info(users)")]:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
    # one pending password-reset code per user, stored hashed, valid for RESET_TTL seconds
    conn.execute(
        "CREATE TABLE IF NOT EXISTS reset_codes ("
        "user_id INTEGER PRIMARY KEY REFERENCES users(id),"
        "code_hash TEXT NOT NULL,"
        "created INTEGER NOT NULL,"
        "tries INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute(COMPANIES_SQL.format("companies"))
    if "user_id" not in [r[1] for r in conn.execute("PRAGMA table_info(companies)")]:
        # single-user database: rebuild companies with an owner column, keeping ids so entries still match
        conn.execute(COMPANIES_SQL.format("companies_new"))
        conn.execute("INSERT INTO companies_new (id, name) SELECT id, name FROM companies")
        conn.execute("DROP TABLE companies")
        conn.execute("ALTER TABLE companies_new RENAME TO companies")
    cols = [r[1] for r in conn.execute("PRAGMA table_info(entries)")]
    if "company_id" not in cols:
        conn.execute("ALTER TABLE entries ADD COLUMN company_id INTEGER REFERENCES companies(id)")
    old_hash = get_setting(conn, "pw_hash")
    if old_hash and not conn.execute("SELECT 1 FROM users").fetchone():
        # the single password from before accounts existed becomes the first admin, named 'admin'
        conn.execute("INSERT INTO users (username, pw_hash, is_admin, epoch) VALUES ('admin', ?, 1, ?)",
                     (old_hash, get_setting(conn, "pw_epoch") or new_epoch()))
        conn.execute("DELETE FROM settings WHERE key IN ('pw_hash', 'pw_epoch')")
    owner = conn.execute("SELECT id FROM users WHERE is_admin = 1 ORDER BY id").fetchone()
    if owner:
        conn.execute("UPDATE companies SET user_id = ? WHERE user_id IS NULL", (owner[0],))
    if conn.execute("SELECT COUNT(*) FROM entries WHERE company_id IS NULL").fetchone()[0]:
        # entries from before companies existed: park them under a company you can rename in Settings
        uid = owner[0] if owner else None
        row = conn.execute("SELECT id FROM companies WHERE name = 'Unassigned' AND user_id IS ?", (uid,)).fetchone()
        cid = row[0] if row else conn.execute(
            "INSERT INTO companies (user_id, name) VALUES (?, 'Unassigned')", (uid,)).lastrowid
        conn.execute("UPDATE entries SET company_id = ? WHERE company_id IS NULL", (cid,))
    conn.commit()
    if not get_setting(conn, "secret_key"):
        set_setting(conn, "secret_key", secrets.token_hex(32))
    key = get_setting(conn, "secret_key")
    conn.close()
    try:
        os.chmod(DB, 0o600)
    except OSError:
        pass
    return key


app.secret_key = init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


# ---------- auth ----------

OPEN_ENDPOINTS = {"login", "setup", "forgot", "reset", "manifest", "icon"}

IDLE_OPTIONS = [(5, "5 minutes"), (15, "15 minutes"), (30, "30 minutes"),
                (60, "1 hour"), (240, "4 hours"), (0, "Never")]

_dummy_hash = []


def idle_minutes(conn):
    try:
        v = int(get_setting(conn, "idle_minutes") or 30)
    except ValueError:
        v = 30
    return v if v in dict(IDLE_OPTIONS) else 30


def locked_out(ip):
    now = time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW]
    return len(FAILS[ip]) >= MAX_FAILS


def clean_username(raw):
    return "".join(str(raw or "").split())[:32]


def password_problem(pw, confirm=None):
    if len(pw) < MIN_PW:
        return f"Use at least {MIN_PW} characters."
    if confirm is not None and pw != confirm:
        return "Passwords don't match."
    return None


def user_by_name(name):
    return db().execute("SELECT * FROM users WHERE username = ?", (name,)).fetchone()


def user_by_login(raw):
    """Sign-in and reset accept either the username or the account's email address."""
    s = str(raw or "").strip()
    if "@" in s:
        return db().execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE AND email != ''", (s,)).fetchone()
    return user_by_name(clean_username(s))


def email_taken(email, user_id=None):
    return bool(email) and db().execute(
        "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND id IS NOT ?", (email, user_id)).fetchone() is not None


def set_user_password(uid, pw):
    """Store a new password and rotate the user's epoch, which signs out their other sessions."""
    epoch = new_epoch()
    db().execute("UPDATE users SET pw_hash = ?, epoch = ? WHERE id = ?", (generate_password_hash(pw), epoch, uid))
    db().commit()
    return epoch


def uid():
    return g.user["id"]


@app.before_request
def gate():
    g.user = None
    if request.endpoint is None or request.endpoint in OPEN_ENDPOINTS:
        return None
    conn = db()
    if not conn.execute("SELECT 1 FROM users").fetchone():
        return redirect(url_for("setup"))
    u = conn.execute("SELECT * FROM users WHERE id = ?", (session.get("uid"),)).fetchone()
    if u and not u["disabled"] and session.get("v") == u["epoch"]:
        now = int(time.time())
        limit = idle_minutes(conn) * 60
        if limit and now - (session.get("t") or now) > limit:
            session.clear()  # idle too long: fall through to the sign-in redirect / 401
        else:
            session["t"] = now
            g.user = u
            if request.endpoint.startswith("admin_") and not u["is_admin"]:
                abort(403)
            return None
    if request.path.startswith("/api/"):
        return jsonify(error="auth"), 401
    return redirect(url_for("login"))


def log_in(u):
    session.clear()
    session.permanent = True
    session["uid"] = u["id"]
    session["v"] = u["epoch"]
    session["t"] = int(time.time())


def page(mode, title, err=None, msg=None, **kw):
    return render_template_string(AUTH, head=HEAD, css=CSS, ticks_js=TICKS_JS, mode=mode, title=title,
                                  err=err, msg=msg, nonce=g.csp_nonce, me=g.get("user"), **kw)


@app.route("/setup", methods=["GET", "POST"])
def setup():
    conn = db()
    if conn.execute("SELECT 1 FROM users").fetchone():
        return redirect(url_for("login"))
    err = None
    if request.method == "POST":
        name = clean_username(request.form.get("username"))
        pw = request.form.get("password", "")
        err = "Enter a username." if not name else password_problem(pw, request.form.get("confirm", ""))
        if "@" in name:
            err = "Usernames can't contain @."
        if not err:
            conn.execute("INSERT INTO users (username, pw_hash, is_admin, epoch) VALUES (?, ?, 1, ?)",
                         (name, generate_password_hash(pw), new_epoch()))
            u = user_by_name(name)
            conn.execute("UPDATE companies SET user_id = ? WHERE user_id IS NULL", (u["id"],))
            conn.commit()
            log_in(u)
            return redirect(url_for("index"))
    return page("setup", "Create the admin account", err=err)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not db().execute("SELECT 1 FROM users").fetchone():
        return redirect(url_for("setup"))
    err = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        u = user_by_login(request.form.get("username"))
        pw = request.form.get("password", "")
        if locked_out(ip):
            err = "Too many attempts. Try again in a few minutes."
        elif u and check_password_hash(u["pw_hash"], pw):
            if u["disabled"]:
                err = "This account is disabled. Ask an admin to turn it back on."
            else:
                FAILS.pop(ip, None)
                log_in(u)
                return redirect(url_for("index"))
        else:
            if not u:
                # do the same hashing work for unknown usernames, so timing doesn't reveal which exist
                if not _dummy_hash:
                    _dummy_hash.append(generate_password_hash(secrets.token_hex(8)))
                check_password_hash(_dummy_hash[0], pw)
            FAILS.setdefault(ip, []).append(time.time())
            time.sleep(1)
            err = "Wrong username or password."
    return page("login", "Sign in", err=err, username=request.form.get("username", ""), can_reset=smtp_ready())


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- email + password reset by one-time code ----------

SMTP_KEYS = ("smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_password", "smtp_from")
SMTP_SECURITY = [("starttls", "STARTTLS (usually port 587)"), ("ssl", "SSL/TLS (usually port 465)"),
                 ("none", "None (local relay only)")]


def smtp_conf():
    conf = {k: get_setting(db(), k) or "" for k in SMTP_KEYS}
    conf["smtp_security"] = conf["smtp_security"] or "starttls"
    return conf


def smtp_ready(conf=None):
    conf = conf or smtp_conf()
    return bool(conf["smtp_host"] and conf["smtp_from"])


def send_mail(to, subject, body, conf=None):
    """Send a plain-text email with the app's SMTP settings. Raises on any failure."""
    conf = conf or smtp_conf()
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = conf["smtp_from"], to, subject
    msg.set_content(body)
    tls = conf["smtp_security"]
    port = int(conf["smtp_port"] or (465 if tls == "ssl" else 587))
    ctx = ssl.create_default_context()
    if tls == "ssl":
        server = smtplib.SMTP_SSL(conf["smtp_host"], port, context=ctx, timeout=15)
    else:
        server = smtplib.SMTP(conf["smtp_host"], port, timeout=15)
    with server:
        if tls == "starttls":
            server.starttls(context=ctx)
        if conf["smtp_user"]:
            server.login(conf["smtp_user"], conf["smtp_password"])
        server.send_message(msg)


def code_hash(code):
    return hashlib.sha256((app.secret_key + code).encode()).hexdigest()


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if not smtp_ready():
        return redirect(url_for("login"))
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if locked_out(ip):
            return page("forgot", "Reset your password", err="Too many attempts. Try again in a few minutes.")
        name = str(request.form.get("username", "")).strip()[:254]
        u = user_by_login(name)
        now = int(time.time())
        pending = u and db().execute("SELECT created FROM reset_codes WHERE user_id = ?", (u["id"],)).fetchone()
        # one email per minute per account, so the form can't be used to flood someone's inbox
        if u and u["email"] and not u["disabled"] and not (pending and now - pending["created"] < 60):
            code = f"{secrets.randbelow(10 ** 6):06d}"
            db().execute("INSERT OR REPLACE INTO reset_codes (user_id, code_hash, created, tries) VALUES (?, ?, ?, 0)",
                         (u["id"], code_hash(code), now))
            db().commit()
            try:
                send_mail(u["email"], f"Your Overtime reset code: {code}",
                          f"Hi {u['username']},\n\nYour code to reset your Overtime password is:\n\n    {code}\n\n"
                          f"It works for {RESET_TTL // 60} minutes. If you didn't ask for it, ignore this email; "
                          "your password stays the same.\n")
            except Exception:
                app.logger.exception("could not send the reset email")
        # same answer whether or not the account exists or has an email, so this page can't be used to probe usernames
        session["reset_name"] = name
        return redirect(url_for("reset"))
    return page("forgot", "Reset your password")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    name = session.get("reset_name")
    if not name:
        return redirect(url_for("forgot"))
    err = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        u = user_by_login(name)
        row = u and db().execute("SELECT * FROM reset_codes WHERE user_id = ?", (u["id"],)).fetchone()
        code = "".join(request.form.get("code", "").split())
        pw = request.form.get("password", "")
        if locked_out(ip):
            err = "Too many attempts. Try again in a few minutes."
        elif row and (time.time() - row["created"] > RESET_TTL or row["tries"] >= RESET_TRIES):
            db().execute("DELETE FROM reset_codes WHERE user_id = ?", (u["id"],))
            db().commit()
            err = "That code has expired. Ask for a new one."
        elif not row or not hmac.compare_digest(code_hash(code), row["code_hash"]):
            if row:
                db().execute("UPDATE reset_codes SET tries = tries + 1 WHERE user_id = ?", (u["id"],))
                db().commit()
            FAILS.setdefault(ip, []).append(time.time())
            time.sleep(1)
            err = "That code isn't right. Check the latest email and try again."
        else:
            err = password_problem(pw, request.form.get("confirm", ""))
            if not err:
                db().execute("DELETE FROM reset_codes WHERE user_id = ?", (u["id"],))
                set_user_password(u["id"], pw)
                session.pop("reset_name", None)
                log_in(user_by_login(name))
                return redirect(url_for("index"))
    return page("reset", "Enter your code", err=err, reset_name=name)


def settings_page(err=None, msg=None):
    conf = smtp_conf()
    conf["has_password"] = bool(conf.pop("smtp_password"))  # never sent back to the browser
    return page("settings", "Settings", err=err, msg=msg, idle=idle_minutes(db()), opts=IDLE_OPTIONS,
                smtp=conf, smtp_ok=smtp_ready(), security=SMTP_SECURITY,
                companies=[dict(r) for r in db().execute(
                    "SELECT id, name FROM companies WHERE user_id = ? ORDER BY name COLLATE NOCASE", (uid(),))])


@app.route("/settings", methods=["GET", "POST"])
def settings():
    err = msg = None
    if request.method == "POST":
        new = request.form.get("new", "")
        if not check_password_hash(g.user["pw_hash"], request.form.get("current", "")):
            err = "Current password is wrong."
        else:
            err = password_problem(new, request.form.get("confirm", ""))
        if not err:
            session["v"] = set_user_password(uid(), new)
            msg = "Password changed. Your other devices were signed out."
    return settings_page(err, msg)


@app.post("/settings/company")
def settings_company():
    name = clean_name(request.form.get("name"))
    try:
        cid = int(request.form.get("company", ""))
    except ValueError:
        cid = -1
    conn = db()
    if not name or not conn.execute("SELECT 1 FROM companies WHERE id = ? AND user_id = ?", (cid, uid())).fetchone():
        return settings_page(err="Pick a company and enter a name.")
    try:
        conn.execute("UPDATE companies SET name = ? WHERE id = ?", (name, cid))
        conn.commit()
    except sqlite3.IntegrityError:
        return settings_page(err="A company with that name already exists.")
    return settings_page(msg="Company renamed.")


@app.post("/settings/idle")
def settings_idle():
    if not g.user["is_admin"]:
        abort(403)
    try:
        v = int(request.form.get("idle", ""))
    except ValueError:
        v = -1
    if v not in dict(IDLE_OPTIONS):
        return settings_page(err="Pick one of the listed options.")
    set_setting(db(), "idle_minutes", str(v))
    return settings_page(msg="Auto sign-out updated.")


def clean_email(raw):
    e = str(raw or "").strip()[:254]
    return e if not e or ("@" in e and " " not in e and "\n" not in e) else None


@app.post("/settings/email")
def settings_email():
    email = clean_email(request.form.get("email"))
    if email is None:
        return settings_page(err="That doesn't look like an email address.")
    if email_taken(email, uid()):
        return settings_page(err="Another account already uses that email.")
    db().execute("UPDATE users SET email = ? WHERE id = ?", (email, uid()))
    db().commit()
    return settings_page(msg="Email saved." if email else "Email removed. You won't be able to reset your password by email.")


@app.post("/settings/smtp")
def admin_smtp():
    f = request.form
    conn = db()
    if f.get("smtp_security") not in dict(SMTP_SECURITY):
        return settings_page(err="Pick one of the listed security options.")
    port = f.get("smtp_port", "").strip()
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        return settings_page(err="The port must be a number like 587.")
    if f.get("smtp_from", "").strip() and not clean_email(f.get("smtp_from")):
        return settings_page(err="The sender must be an email address.")
    for k in ("smtp_host", "smtp_security", "smtp_user", "smtp_from"):
        set_setting(conn, k, f.get(k, "").strip())
    set_setting(conn, "smtp_port", port)
    if f.get("clear_password") == "1":
        set_setting(conn, "smtp_password", "")
    elif f.get("smtp_password"):
        set_setting(conn, "smtp_password", f.get("smtp_password"))  # blank keeps the saved one
    return settings_page(msg="Email settings saved. Send a test email to check them.")


@app.post("/settings/smtp/test")
def admin_smtp_test():
    if not g.user["email"]:
        return settings_page(err="Add your own email address above first; the test goes there.")
    if not smtp_ready():
        return settings_page(err="Fill in at least the server and the sender address.")
    try:
        send_mail(g.user["email"], "Overtime test email", "Email from Overtime works. Password resets by email are on.\n")
    except Exception as e:
        return settings_page(err=f"Sending failed: {type(e).__name__}: {e}")
    return settings_page(msg=f"Test email sent to {g.user['email']}.")


# ---------- user administration (admins only; the gate checks the admin_ prefix) ----------

def users_page(err=None, msg=None):
    rows = db().execute(
        "SELECT u.id, u.username, u.email, u.is_admin, u.disabled, COUNT(e.id) AS entries "
        "FROM users u LEFT JOIN companies c ON c.user_id = u.id LEFT JOIN entries e ON e.company_id = c.id "
        "GROUP BY u.id ORDER BY u.username COLLATE NOCASE"
    ).fetchall()
    return page("users", "Users", err=err, msg=msg, users=[dict(r) for r in rows], smtp_ok=smtp_ready())


def target_user(user_id):
    u = db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not u:
        abort(404)
    return u


def last_admin(u):
    """True when u is the only enabled admin, so demoting or disabling them would lock everyone out."""
    if not u["is_admin"] or u["disabled"]:
        return False
    return db().execute("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled = 0").fetchone()[0] <= 1


@app.get("/admin/users")
def admin_users():
    return users_page()


@app.post("/admin/users")
def admin_user_new():
    name = clean_username(request.form.get("username"))
    pw = request.form.get("password", "")
    email = clean_email(request.form.get("email"))
    err = "Enter a username." if not name else password_problem(pw)
    if "@" in name:
        err = "Usernames can't contain @. Put the email in the Email field."
    if email is None:
        err = "That doesn't look like an email address."
    elif email_taken(email):
        err = "Another account already uses that email."
    if err:
        return users_page(err=err)
    try:
        db().execute("INSERT INTO users (username, email, pw_hash, is_admin, epoch) VALUES (?, ?, ?, ?, ?)",
                     (name, email, generate_password_hash(pw), int(request.form.get("admin") == "1"), new_epoch()))
        db().commit()
    except sqlite3.IntegrityError:
        return users_page(err=f"The username {name} is taken.")
    return users_page(msg=f"Added {name}. Share the password with them; they can change it in Settings.")


@app.post("/admin/users/<int:user_id>/role")
def admin_user_role(user_id):
    u = target_user(user_id)
    make = request.form.get("admin") == "1"
    if not make and last_admin(u):
        return users_page(err="Keep at least one admin. Make someone else an admin first.")
    db().execute("UPDATE users SET is_admin = ? WHERE id = ?", (int(make), user_id))
    db().commit()
    if user_id == uid() and not make:
        return redirect(url_for("settings"))
    return users_page(msg=f"{u['username']} is {'now' if make else 'no longer'} an admin.")


@app.post("/admin/users/<int:user_id>/password")
def admin_user_password(user_id):
    u = target_user(user_id)
    pw = request.form.get("password", "")
    err = password_problem(pw)
    if err:
        return users_page(err=err)
    epoch = set_user_password(user_id, pw)
    if user_id == uid():
        session["v"] = epoch
    return users_page(msg=f"New password set for {u['username']}. They were signed out everywhere.")


@app.post("/admin/users/<int:user_id>/email")
def admin_user_email(user_id):
    u = target_user(user_id)
    email = clean_email(request.form.get("email"))
    if email is None:
        return users_page(err="That doesn't look like an email address.")
    if email_taken(email, user_id):
        return users_page(err="Another account already uses that email.")
    db().execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
    db().commit()
    return users_page(msg=f"Email for {u['username']} {'saved' if email else 'removed'}.")


@app.post("/admin/users/<int:user_id>/disable")
def admin_user_disable(user_id):
    u = target_user(user_id)
    if user_id == uid():
        return users_page(err="You can't disable your own account.")
    if not u["disabled"] and last_admin(u):
        return users_page(err="Keep at least one admin. Make someone else an admin first.")
    db().execute("UPDATE users SET disabled = ?, epoch = ? WHERE id = ?", (int(not u["disabled"]), new_epoch(), user_id))
    db().commit()
    return users_page(msg=f"{u['username']} is {'enabled again' if u['disabled'] else 'disabled and signed out'}.")


@app.post("/admin/users/<int:user_id>/delete")
def admin_user_delete(user_id):
    u = target_user(user_id)
    if user_id == uid():
        return users_page(err="You can't delete your own account.")
    if last_admin(u):
        return users_page(err="Keep at least one admin. Make someone else an admin first.")
    conn = db()
    conn.execute("DELETE FROM entries WHERE company_id IN (SELECT id FROM companies WHERE user_id = ?)", (user_id,))
    conn.execute("DELETE FROM companies WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM reset_codes WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return users_page(msg=f"Deleted {u['username']} and their entries.")


# ---------- API (every query is limited to the signed-in user's companies) ----------

def clean_name(raw):
    return " ".join(str(raw or "").split())[:60]


@app.get("/api/companies")
def list_companies():
    rows = db().execute(
        "SELECT c.id, c.name, COALESCE(SUM(e.hours), 0) AS balance, COUNT(e.id) AS entries "
        "FROM companies c LEFT JOIN entries e ON e.company_id = c.id WHERE c.user_id = ? "
        "GROUP BY c.id ORDER BY c.name COLLATE NOCASE", (uid(),)
    ).fetchall()
    return jsonify(companies=[dict(r) for r in rows])


@app.post("/api/companies")
def add_company():
    name = clean_name((request.get_json(force=True) or {}).get("name"))
    if not name:
        return jsonify(error="name required"), 400
    conn = db()
    try:
        cur = conn.execute("INSERT INTO companies (user_id, name) VALUES (?, ?)", (uid(), name))
        conn.commit()
    except sqlite3.IntegrityError:
        row = conn.execute("SELECT id FROM companies WHERE user_id = ? AND name = ?", (uid(), name)).fetchone()
        return jsonify(error="exists", id=row["id"]), 409
    return jsonify(id=cur.lastrowid, name=name)


@app.delete("/api/companies/<int:cid>")
def delete_company(cid):
    conn = db()
    if not conn.execute("SELECT 1 FROM companies WHERE id = ? AND user_id = ?", (cid, uid())).fetchone():
        return jsonify(error="unknown company"), 404
    conn.execute("DELETE FROM entries WHERE company_id = ?", (cid,))
    conn.execute("DELETE FROM companies WHERE id = ?", (cid,))
    conn.commit()
    return jsonify(ok=True)


@app.get("/api/entries")
def list_entries():
    # the whole bank, or only one company's entries when ?company=<id> is given
    cid = request.args.get("company", type=int)
    where, args = ("AND e.company_id = ?", (uid(), cid)) if cid is not None else ("", (uid(),))
    rows = db().execute(
        "SELECT e.id, e.day, e.hours, e.note, e.company_id, c.name AS company "
        f"FROM entries e JOIN companies c ON c.id = e.company_id WHERE c.user_id = ? {where} "
        "ORDER BY e.day DESC, e.id DESC", args
    ).fetchall()
    return jsonify(balance=sum(r["hours"] for r in rows), entries=[dict(r) for r in rows])


def company_id_for(name):
    """The id of this user's company with this name, creating it the first time it is used."""
    conn = db()
    conn.execute("INSERT OR IGNORE INTO companies (user_id, name) VALUES (?, ?)", (uid(), name))
    return conn.execute("SELECT id FROM companies WHERE user_id = ? AND name = ?", (uid(), name)).fetchone()["id"]


def owns_entry(eid):
    return db().execute(
        "SELECT 1 FROM entries e JOIN companies c ON c.id = e.company_id WHERE e.id = ? AND c.user_id = ?",
        (eid, uid())).fetchone() is not None


def company_balance(cid, exclude_entry_id=None):
    """A company's current banked balance, optionally as if one entry didn't exist yet."""
    if exclude_entry_id is None:
        row = db().execute("SELECT COALESCE(SUM(hours), 0) AS b FROM entries WHERE company_id = ?", (cid,))
    else:
        row = db().execute(
            "SELECT COALESCE(SUM(hours), 0) AS b FROM entries WHERE company_id = ? AND id != ?",
            (cid, exclude_entry_id))
    return row.fetchone()["b"]


def entry_fields(d):
    """Validate an entry sent by the page: (company_id, day, hours, note), or an error string."""
    try:
        hours = float(d["hours"])
        day = str(d["day"])[:10]
    except (KeyError, ValueError, TypeError):
        return "bad input"
    if hours == 0:
        return "hours cannot be 0"
    name = clean_name(d.get("company"))
    if not name:
        return "company required"
    return company_id_for(name), day, hours, str(d.get("note", ""))[:200]


@app.post("/api/entries")
def add_entry():
    f = entry_fields(request.get_json(force=True) or {})
    if isinstance(f, str):
        return jsonify(error=f), 400
    cid, day, hours, note = f
    if company_balance(cid) + hours < 0:
        return jsonify(error="not enough hours banked"), 400
    db().execute("INSERT INTO entries (company_id, day, hours, note) VALUES (?, ?, ?, ?)", f)
    db().commit()
    return jsonify(ok=True)


@app.put("/api/entries/<int:eid>")
def update_entry(eid):
    if not owns_entry(eid):
        return jsonify(error="unknown entry"), 404
    f = entry_fields(request.get_json(force=True) or {})
    if isinstance(f, str):
        return jsonify(error=f), 400
    cid, day, hours, note = f
    if company_balance(cid, exclude_entry_id=eid) + hours < 0:
        return jsonify(error="not enough hours banked"), 400
    db().execute("UPDATE entries SET company_id = ?, day = ?, hours = ?, note = ? WHERE id = ?", (*f, eid))
    drop_empty_companies()
    db().commit()
    return jsonify(ok=True)


def drop_empty_companies():
    # a company only exists through its entries, so forget it once the last one is gone
    db().execute("DELETE FROM companies WHERE user_id = ? AND id NOT IN "
                 "(SELECT company_id FROM entries WHERE company_id IS NOT NULL)", (uid(),))


@app.post("/api/ping")
def ping():
    return jsonify(ok=True)  # the auth gate refreshes the idle clock


@app.delete("/api/entries/<int:eid>")
def delete_entry(eid):
    if owns_entry(eid):
        db().execute("DELETE FROM entries WHERE id = ?", (eid,))
        drop_empty_companies()
        db().commit()
    return jsonify(ok=True)


@app.get("/api/export")
def export_data():
    conn = db()
    companies = [dict(r) for r in conn.execute(
        "SELECT id, name FROM companies WHERE user_id = ? ORDER BY name COLLATE NOCASE", (uid(),))]
    entries = [dict(r) for r in conn.execute(
        "SELECT e.company_id, e.day, e.hours, e.note FROM entries e JOIN companies c ON c.id = e.company_id "
        "WHERE c.user_id = ? ORDER BY e.company_id, e.day, e.id", (uid(),))]
    if request.args.get("format") == "csv":
        cname = {c["id"]: c["name"] for c in companies}
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["company", "day", "hours", "note"])
        for e in entries:
            w.writerow([cname.get(e["company_id"], ""), e["day"], e["hours"], e["note"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                         headers={"Content-Disposition": "attachment; filename=overtime-export.csv"})
    return jsonify(companies=companies, entries=entries)


# ---------- PWA bits ----------

@app.get("/manifest.json")
def manifest():
    return jsonify(
        name="Overtime Bank",
        short_name="Overtime",
        start_url="/",
        display="standalone",
        background_color="#0C1322",
        theme_color="#14213D",
        icons=[{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml"}],
    )


@app.get("/icon.svg")
def icon():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
        '<rect width="100" height="100" rx="22" fill="#14213D"/>'
        '<circle cx="50" cy="50" r="28" fill="none" stroke="#2A3A5E" stroke-width="8"/>'
        '<path d="M50 22a28 28 0 1 1-28 28" fill="none" stroke="#FFC233" stroke-width="8" stroke-linecap="round"/>'
        '<path d="M50 50V35M50 50l10 7" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round"/>'
        "</svg>"
    )
    return Response(svg, mimetype="image/svg+xml")


@app.get("/")
def index():
    html = PAGE.replace("__IDLE__", str(idle_minutes(db()))).replace("__NONCE__", g.csp_nonce)
    return Response(html, mimetype="text/html")


# ---------- pages ----------

# Shared by every page. One full turn of the dial is a 40h work week; long ticks mark 8h workdays.
CSS = """
:root{--bg:#E9EDF2;--surf:#fff;--soft:#F3F5F8;--ink:#14213D;--mut:#5B6577;--line:#D5DCE5;
--amber:#E9A100;--earn:#0F7B5F;--use:#B4234A;--onsem:#fff;--btn:#14213D;--btnfg:#fff;--focus:#2F4BD8;
--r-lg:22px;--r-sm:12px;
--round:ui-rounded,"SF Pro Rounded","Nunito","Varela Round",system-ui,sans-serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#0C1322;--surf:#141E33;--soft:#1A2640;--ink:#E7ECF4;--mut:#8E9AB0;
--line:#24304A;--amber:#FFC233;--earn:#3DD6A3;--use:#FF6B8B;--onsem:#0C1322;--btn:#FFC233;--btnfg:#14213D;
--focus:#FFC233;color-scheme:dark}}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 var(--sans);-webkit-font-smoothing:antialiased}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
@media(prefers-reduced-motion:reduce){*,*::before{animation:none!important;transition:none!important}}

.field{display:block;margin-bottom:12px}
.field>span{display:block;font-size:.82rem;color:var(--mut);margin:0 0 5px 2px}
input,select{width:100%;min-height:48px;padding:11px 14px;border:1px solid var(--line);border-radius:var(--r-sm);
background:var(--soft);font-size:1rem;-webkit-appearance:none;appearance:none}
select{padding-right:38px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%238E9AB0' stroke-width='2.5' stroke-linecap='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
background-repeat:no-repeat;background-position:right 12px center;background-size:18px}
input:focus,select:focus{outline:none;border-color:var(--focus);background-color:var(--surf);
box-shadow:0 0 0 3px color-mix(in srgb,var(--focus) 22%,transparent)}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;min-height:48px;padding:12px 16px;
border:0;border-radius:var(--r-sm);background:var(--btn);color:var(--btnfg);font-weight:650;cursor:pointer;
text-decoration:none;transition:transform .08s,filter .15s}
.btn:hover{filter:brightness(1.12)}
.btn:active{transform:scale(.98)}
.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}
.btn.ghost:hover{background:var(--soft);filter:none}
.btn.danger{background:var(--use);color:var(--onsem)}
.link{background:none;border:0;padding:6px 0;color:var(--mut);cursor:pointer;font-size:.9rem;
text-decoration:underline;text-decoration-color:var(--line);text-underline-offset:3px}
.link:hover{color:var(--ink)}
.msg{border-radius:var(--r-sm);padding:10px 14px;margin:0 0 14px;font-size:.92rem}
.msg.err{color:var(--use);background:color-mix(in srgb,var(--use) 12%,transparent)}
.msg.ok{color:var(--earn);background:color-mix(in srgb,var(--earn) 12%,transparent)}
.panel{background:var(--surf);border-radius:var(--r-lg);padding:20px}

.dial{display:block;width:100%;height:100%;overflow:visible}
.dial .track{fill:none;stroke:var(--line);stroke-width:12}
.dial .arc{fill:none;stroke:var(--amber);stroke-width:12;stroke-linecap:round;stroke-dasharray:628.32;
stroke-dashoffset:628.32;transform:rotate(-90deg);transform-origin:120px 120px;
transition:stroke-dashoffset .9s cubic-bezier(.2,.8,.2,1),stroke .3s}
.dial .arc.neg{stroke:var(--use);transform:scaleX(-1) rotate(-90deg)}
.dial .tick{stroke:var(--mut);stroke-width:1.5;stroke-linecap:round;opacity:.35}
.dial .tick.major{stroke-width:3;opacity:.85}

/* sign-in / setup */
body.auth{min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:28px 16px}
.authbox{width:100%;max-width:360px;text-align:center}
.clock{width:176px;height:176px;margin:0 auto 22px}
.clock .hand{stroke:var(--ink);stroke-linecap:round;transform-origin:120px 120px;
transition:transform 1.3s cubic-bezier(.3,1.25,.5,1)}
.clock .hand.h{stroke-width:7}
.clock .hand.m{stroke-width:4.5}
.clock .pin{fill:var(--amber)}
.authbox h1{font:700 2rem/1.1 var(--round);letter-spacing:-.01em;margin:0}
.authbox .sub{color:var(--mut);margin:6px 0 24px}
.authform{text-align:left;background:var(--surf);border-radius:var(--r-lg);padding:20px}
.authform .link{margin:-4px 0 12px}

/* settings */
.wrap{max-width:520px;margin:0 auto;padding:0 16px calc(36px + env(safe-area-inset-bottom))}
.back{display:inline-flex;align-items:center;gap:4px;padding:16px 0 4px;color:var(--mut);text-decoration:none}
.back:hover{color:var(--ink)}
.back svg{width:18px;height:18px}
.pagetitle{font:700 2rem/1.15 var(--round);letter-spacing:-.01em;margin:6px 0 18px}
.set{margin-bottom:14px}
.set h2{font:650 1.12rem/1.3 var(--round);margin:0 0 2px}
.hint{color:var(--mut);font-size:.9rem;margin:0 0 16px}
.support{color:var(--mut);font-size:.82rem;text-align:center;margin:22px 0 0}
.support a{color:var(--mut);text-decoration:underline;text-decoration-color:var(--line)}
.support a:hover{color:var(--ink)}
.inline{display:flex;gap:10px}
.inline select{flex:1;min-width:0}
.inline .btn{width:auto;flex:none}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.signout{margin-top:22px}
.whoami{color:var(--mut);margin:-10px 0 18px}
.group{font:650 .95rem var(--round);color:var(--mut);margin:28px 4px 10px}
.inline input{flex:1;min-width:0}
.testmail{margin-top:10px}
.tag{display:inline-block;padding:2px 9px;border-radius:999px;background:var(--soft);color:var(--mut);
font:600 .75rem var(--sans);vertical-align:2px}
.tag.on{background:color-mix(in srgb,var(--amber) 24%,transparent);color:var(--ink)}
.tag.off{background:color-mix(in srgb,var(--use) 14%,transparent);color:var(--use)}
.check{display:flex;align-items:center;gap:10px;margin:2px 0 14px;cursor:pointer}
.uact .check{display:inline-flex;margin:0}
input[type=checkbox]{-webkit-appearance:auto;appearance:auto;width:20px;height:20px;min-height:0;padding:0;margin:0;
accent-color:var(--amber);flex:none}
.ulist{padding:4px 20px}
.urow{padding:16px 0;border-top:1px solid var(--line)}
.urow:first-child{border-top:0}
.uname{font-weight:650;font-size:1.05rem}
.ucount{color:var(--mut);font-size:.85rem;margin:2px 0 10px;overflow-wrap:anywhere}
.uact{display:flex;flex-wrap:wrap;align-items:center;gap:6px 20px}
.uact details[open]{flex-basis:100%}
.uact details .inline{margin-top:8px}
summary.link{list-style:none;display:inline-block}
summary.link::-webkit-details-marker{display:none}
.confirm{color:var(--mut);font-size:.88rem;margin:8px 0 10px}
.authlinks{display:flex;justify-content:space-between;gap:12px;margin:-4px 0 12px}
.authlinks .link{margin:0}
.authform .authlinks:last-child{margin:12px 0 0}
.authbox .sub b{color:var(--ink)}
.code{font:650 1.5rem var(--round);letter-spacing:.3em;text-align:center}

/* the bank */
.bar{display:flex;align-items:center;justify-content:space-between;padding:14px 0 10px}
.brand{display:flex;align-items:center;gap:10px;font:700 1.15rem var(--round);color:var(--ink);text-decoration:none}
.brand img{width:30px;height:30px;border-radius:8px}
.gear{display:inline-flex;padding:8px;margin-right:-8px;border-radius:10px;color:var(--mut)}
.gear:hover{color:var(--ink);background:var(--surf)}
.gear svg{width:22px;height:22px}
.chips{display:flex;gap:8px;overflow-x:auto;padding:4px 16px 10px;margin:0 -16px;scrollbar-width:none}
.chips::-webkit-scrollbar{display:none}
.chip{flex:none;display:flex;align-items:baseline;gap:8px;min-height:40px;padding:8px 15px;border-radius:999px;
border:1px solid var(--line);background:var(--surf);cursor:pointer;white-space:nowrap;font-size:.95rem}
.chip b{font-weight:600}
.chip .num{color:var(--mut);font:600 .85rem var(--round);font-variant-numeric:tabular-nums}
.chip[aria-pressed=true]{background:var(--ink);border-color:var(--ink);color:var(--bg)}
.chip[aria-pressed=true] .num{color:inherit;opacity:.75}

.hero{text-align:center;padding:10px 0 18px}
.dialwrap{position:relative;width:min(264px,74vw);aspect-ratio:1;margin:0 auto}
.dialc{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
#bal{font:700 clamp(2.6rem,13vw,3.5rem)/1 var(--round);letter-spacing:-.02em;font-variant-numeric:tabular-nums}
#bal.neg{color:var(--use)}
#bal.long{font-size:clamp(2.1rem,10vw,2.75rem)}
#sub{color:var(--mut);font-size:.88rem;margin-top:8px}
#colabel{margin:12px 0 0;font-weight:600}
.spark{display:block;width:min(220px,60vw);height:34px;margin:8px auto 0;overflow:visible}
.spark .zero{stroke:var(--line);stroke-width:1;stroke-dasharray:3 4;vector-effect:non-scaling-stroke}
.spark .ln{fill:none;stroke:var(--mut);stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round;vector-effect:non-scaling-stroke}

.editing{display:flex;justify-content:space-between;align-items:center;margin:-6px 0 12px;font-weight:600}
.seg{position:relative;display:grid;grid-template-columns:1fr 1fr;padding:4px;margin-bottom:16px;
background:var(--soft);border:1px solid var(--line);border-radius:14px}
.seg::before{content:"";position:absolute;top:4px;bottom:4px;left:4px;width:calc(50% - 4px);border-radius:10px;
background:var(--earn);transition:transform .25s cubic-bezier(.2,.8,.2,1),background-color .25s}
.seg.use::before{transform:translateX(100%);background:var(--use)}
.seg button{position:relative;z-index:1;min-height:40px;border:0;background:none;font-weight:650;cursor:pointer;
color:var(--mut);transition:color .2s}
.seg button[aria-pressed=true]{color:var(--onsem)}
#hrs{font:650 1.6rem var(--round);font-variant-numeric:tabular-nums;min-height:58px}
#hrs::placeholder{font:400 1rem var(--sans);color:var(--mut)}
.quick{display:flex;gap:6px;flex-wrap:wrap;margin:-2px 0 14px}
.quick button{min-height:34px;padding:4px 13px;border:1px solid var(--line);border-radius:999px;background:none;
cursor:pointer;font:600 .88rem var(--round);font-variant-numeric:tabular-nums;color:var(--mut)}
.quick button:hover{color:var(--ink);border-color:var(--mut)}
.two{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.35fr);gap:10px}
@media(max-width:360px){.two{grid-template-columns:1fr}}

.hist{margin-top:14px;padding:6px 0 8px}
.month{display:flex;justify-content:space-between;padding:14px 20px 6px;color:var(--mut);font-size:.85rem;font-weight:600}
.month .num{font-family:var(--round);font-variant-numeric:tabular-nums}
.row{display:grid;grid-template-columns:4px minmax(0,1fr) auto auto auto;align-items:center;gap:12px;
padding:9px 8px 9px 20px;cursor:pointer;transition:background-color .15s}
.row:hover{background:var(--soft)}
.row .stripe{width:4px;height:34px;border-radius:2px;background:var(--earn)}
.row.neg .stripe{background:var(--use)}
.what span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.what small{color:var(--mut);font-size:.8rem}
.what small b{font-weight:600;color:var(--ink);opacity:.75;margin-right:6px}
.amt{font:650 1.02rem var(--round);font-variant-numeric:tabular-nums;color:var(--earn);margin-right:4px}
.row.neg .amt{color:var(--use)}
.icbtn{display:inline-flex;padding:8px;border:0;border-radius:10px;background:none;color:var(--mut);cursor:pointer}
.icbtn svg{width:18px;height:18px}
.icbtn:hover{color:var(--ink);background:var(--bg)}
.icbtn.del:hover{color:var(--use)}
.empty{color:var(--mut);text-align:center;padding:22px 20px;margin:0}
.skel{height:14px;margin:16px 20px;border-radius:7px;background:linear-gradient(90deg,var(--soft),var(--line),var(--soft));
background-size:300% 100%;animation:shimmer 1.4s ease infinite}
.skel.short{width:45%}
@keyframes shimmer{from{background-position:100% 0}to{background-position:0 0}}
.foot{display:flex;justify-content:space-between;gap:12px;padding:16px 4px 0}
.link.danger:hover{color:var(--use)}

.toast{position:fixed;left:50%;bottom:calc(24px + env(safe-area-inset-bottom));transform:translate(-50%,8px);
background:var(--ink);color:var(--bg);padding:10px 18px;border-radius:999px;font-size:.92rem;font-weight:600;
box-shadow:0 10px 30px rgba(12,19,34,.28);opacity:0;transition:opacity .2s,transform .2s;max-width:90vw;text-align:center}
.toast.show{opacity:1;transform:translate(-50%,0)}
.ov{position:fixed;inset:0;display:grid;place-items:center;padding:16px;background:rgba(12,19,34,.5);animation:fade .15s}
.dlg{width:100%;max-width:340px;background:var(--surf);border-radius:var(--r-lg);padding:22px;
box-shadow:0 20px 50px rgba(12,19,34,.35)}
.dlg p{margin:0 0 18px;font-size:1.02rem}
.dlgrow{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@keyframes fade{from{opacity:0}}
"""

HEAD = """<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#E9EDF2" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0C1322" media="(prefers-color-scheme: dark)">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon.svg">
<link rel="apple-touch-icon" href="/icon.svg">"""

# Draws the hour ticks around a dial: n ticks, every `major`-th one long.
TICKS_JS = """function ticks(g,n,major){
  const ns='http://www.w3.org/2000/svg';
  for(let i=0;i<n;i++){
    const a=i/n*2*Math.PI,mj=i%major===0,r1=mj?78:84,r2=90;
    const l=document.createElementNS(ns,'line');
    l.setAttribute('x1',(120+r1*Math.sin(a)).toFixed(2));l.setAttribute('y1',(120-r1*Math.cos(a)).toFixed(2));
    l.setAttribute('x2',(120+r2*Math.sin(a)).toFixed(2));l.setAttribute('y2',(120-r2*Math.cos(a)).toFixed(2));
    l.setAttribute('class','tick'+(mj?' major':''));g.append(l);
  }
}"""

AUTH = """<!doctype html>
<html lang="en"><head>
{{ head|safe }}
<title>{{ title }} - Overtime</title>
<style nonce="{{ nonce }}">{{ css|safe }}</style></head>
{% if mode in ('settings', 'users') %}
<body>
<main class="wrap">
{% if mode == 'settings' %}
<a class="back" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 6-6 6 6 6"/></svg>Hour bank</a>
<h1 class="pagetitle">Settings</h1>
<p class="whoami">Signed in as <b>{{ me.username }}</b>{% if me.is_admin %} <span class="tag on">Admin</span>{% endif %}</p>
{% else %}
<a class="back" href="/settings"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 6-6 6 6 6"/></svg>Settings</a>
<h1 class="pagetitle">Users</h1>
{% endif %}
{% if err %}<p class="msg err" role="alert">{{ err }}</p>{% endif %}
{% if msg %}<p class="msg ok" role="status">{{ msg }}</p>{% endif %}

{% if mode == 'settings' %}
<section class="panel set">
<h2>Password</h2>
<p class="hint">Changing it signs out your other devices.</p>
<form method="post" action="/settings">
<label class="field"><span>Current password</span><input type="password" name="current" data-pw autocomplete="current-password" required></label>
<label class="field"><span>New password (8 characters or more)</span><input type="password" name="new" data-pw autocomplete="new-password" minlength="8" required></label>
<label class="field"><span>Confirm new password</span><input type="password" name="confirm" data-pw autocomplete="new-password" minlength="8" required></label>
<button type="button" class="link showpw">Show passwords</button>
<button type="submit" class="btn">Change password</button>
</form>
</section>
<section class="panel set">
<h2>Email</h2>
<p class="hint">{% if smtp_ok %}Where your password reset codes go.{% else %}Where your password reset codes will go once an admin sets up email.{% endif %}</p>
<form method="post" action="/settings/email" class="inline">
<input type="email" name="email" value="{{ me.email }}" placeholder="you@example.com" autocomplete="email" aria-label="Email">
<button type="submit" class="btn ghost">Save</button>
</form>
</section>
{% if companies %}
<section class="panel set">
<h2>Rename a company</h2>
<p class="hint">Entries stay with the company under its new name.</p>
<form method="post" action="/settings/company">
<label class="field"><span>Company</span><select name="company">{% for c in companies %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}</select></label>
<label class="field"><span>New name</span><input type="text" name="name" maxlength="60" required></label>
<button type="submit" class="btn ghost">Rename company</button>
</form>
</section>
{% endif %}
<section class="panel set">
<h2>Your data</h2>
<p class="hint">Every company and entry of yours, for backups or spreadsheets.</p>
<div class="pair"><a class="btn ghost" href="/api/export?format=csv">Download CSV</a><a class="btn ghost" href="/api/export">Download JSON</a></div>
</section>
{% if me.is_admin %}
<h2 class="group">For everyone</h2>
<section class="panel set">
<h2>Users</h2>
<p class="hint">Add people, reset passwords and choose who is an admin.</p>
<a class="btn ghost" href="/admin/users">Manage users</a>
</section>
<section class="panel set">
<h2>Auto sign-out</h2>
<p class="hint">Sign everyone out after this long without activity.</p>
<form method="post" action="/settings/idle" class="inline">
<select name="idle" aria-label="Idle time">{% for v, l in opts %}<option value="{{ v }}"{% if v == idle %} selected{% endif %}>{{ l }}</option>{% endfor %}</select>
<button type="submit" class="btn ghost">Save</button>
</form>
</section>
<section class="panel set">
<h2>Email server</h2>
<p class="hint">Lets people reset a forgotten password with a one-time code sent to their email.
{% if smtp_ok %}Resets by email are on.{% else %}Resets by email are off until a server and sender are saved.{% endif %}</p>
<form method="post" action="/settings/smtp">
<div class="two">
<label class="field"><span>Server</span><input name="smtp_host" value="{{ smtp.smtp_host }}" placeholder="smtp.example.com" autocomplete="off"></label>
<label class="field"><span>Port</span><input name="smtp_port" value="{{ smtp.smtp_port }}" inputmode="numeric" placeholder="587" autocomplete="off"></label>
</div>
<label class="field"><span>Security</span><select name="smtp_security">{% for v, l in security %}<option value="{{ v }}"{% if v == smtp.smtp_security %} selected{% endif %}>{{ l }}</option>{% endfor %}</select></label>
<label class="field"><span>Username</span><input name="smtp_user" value="{{ smtp.smtp_user }}" autocomplete="off"></label>
<label class="field"><span>Password{% if smtp.has_password %} (saved; leave blank to keep it){% endif %}</span><input type="password" name="smtp_password" data-pw autocomplete="new-password"></label>
{% if smtp.has_password %}<label class="check"><input type="checkbox" name="clear_password" value="1"> Remove the saved password</label>{% endif %}
<label class="field"><span>Send from</span><input type="email" name="smtp_from" value="{{ smtp.smtp_from }}" placeholder="overtime@example.com"></label>
<button type="submit" class="btn">Save email server</button>
</form>
<form method="post" action="/settings/smtp/test" class="testmail">
<button type="submit" class="btn ghost">Send a test email{% if me.email %} to {{ me.email }}{% endif %}</button>
</form>
</section>
{% endif %}
<form method="post" action="/logout" class="signout"><button type="submit" class="btn ghost">Sign out</button></form>

{% else %}
<section class="panel set">
<h2>Add a user</h2>
<p class="hint">They get their own hour bank. Share the password with them; they can change it in Settings.</p>
<form method="post" action="/admin/users">
<div class="two">
<label class="field"><span>Username</span><input name="username" maxlength="32" autocomplete="off" autocapitalize="none" required></label>
<label class="field"><span>Email (for resets)</span><input type="email" name="email" autocomplete="off"></label>
</div>
<label class="field"><span>Password (8 characters or more)</span><input type="password" name="password" data-pw minlength="8" autocomplete="new-password" required></label>
<button type="button" class="link showpw">Show password</button>
<label class="check"><input type="checkbox" name="admin" value="1"> Admin: can manage users and app settings</label>
<button type="submit" class="btn">Add user</button>
</form>
</section>
<section class="panel ulist" aria-label="Users">
{% for u in users %}{% set mine = u.id == me.id %}
<div class="urow">
<div class="uname">{{ u.username }}{% if mine %} <span class="tag">You</span>{% endif %}{% if u.disabled %} <span class="tag off">Disabled</span>{% endif %}</div>
<div class="ucount">{{ u.email or 'No email' }}, {{ u.entries }} entr{{ 'y' if u.entries == 1 else 'ies' }}</div>
<div class="uact">
<form method="post" action="/admin/users/{{ u.id }}/role">
<label class="check"><input type="checkbox" name="admin" value="1" data-autosubmit{% if u.is_admin %} checked{% endif %}> Admin</label>
<noscript><button type="submit" class="link">Save</button></noscript>
</form>
<details><summary class="link">Reset password</summary>
<form method="post" action="/admin/users/{{ u.id }}/password" class="inline">
<input type="password" name="password" minlength="8" autocomplete="new-password" placeholder="New password" aria-label="New password for {{ u.username }}" required>
<button type="submit" class="btn ghost">Set</button>
</form>
<p class="confirm">Signs {{ 'you' if mine else u.username }} out everywhere.{% if smtp_ok and u.email and not mine %} They can also reset it themselves from the sign-in page.{% endif %}</p>
</details>
<details><summary class="link">Email</summary>
<form method="post" action="/admin/users/{{ u.id }}/email" class="inline">
<input type="email" name="email" value="{{ u.email }}" placeholder="name@example.com" aria-label="Email for {{ u.username }}">
<button type="submit" class="btn ghost">Save</button>
</form>
</details>
{% if not mine %}
<form method="post" action="/admin/users/{{ u.id }}/disable"><button type="submit" class="link">{{ 'Enable' if u.disabled else 'Disable' }}</button></form>
<details><summary class="link danger">Delete</summary>
<form method="post" action="/admin/users/{{ u.id }}/delete">
<p class="confirm">Deletes {{ u.username }} and their {{ u.entries }} entr{{ 'y' if u.entries == 1 else 'ies' }}. This cannot be undone.</p>
<button type="submit" class="btn danger">Delete {{ u.username }}</button>
</form>
</details>
{% endif %}
</div>
</div>
{% endfor %}
</section>
{% endif %}
</main>

{% else %}
<body class="auth">
<main class="authbox">
<svg class="dial clock" viewBox="0 0 240 240" aria-hidden="true">
<g id="ticks"></g>
<circle class="track" cx="120" cy="120" r="104"/>
<circle class="arc" id="arc" cx="120" cy="120" r="100"/>
<line class="hand h" id="hh" x1="120" y1="132" x2="120" y2="74"/>
<line class="hand m" id="mh" x1="120" y1="136" x2="120" y2="48"/>
<circle class="pin" cx="120" cy="120" r="7"/>
</svg>
{% if mode == 'login' %}
<h1>Overtime</h1>
<p class="sub">Sign in to your hour bank</p>
{% elif mode == 'setup' %}
<h1>Welcome</h1>
<p class="sub">Create the admin account for this server</p>
{% elif mode == 'forgot' %}
<h1>Forgot your password?</h1>
<p class="sub">We'll email a 6-digit code to the address on your account</p>
{% else %}
<h1>Check your email</h1>
<p class="sub">If <b>{{ reset_name }}</b> has an email address, a 6-digit code is on its way. It works for 10 minutes.</p>
{% endif %}
<form method="post" class="authform">
{% if err %}<p class="msg err" role="alert">{{ err }}</p>{% endif %}
{% if mode == 'login' %}
<label class="field"><span>Username or email</span><input name="username" value="{{ username }}" autocomplete="username" autocapitalize="none" {% if not username %}autofocus {% endif %}required></label>
<label class="field"><span>Password</span><input type="password" name="password" data-pw autocomplete="current-password" {% if username %}autofocus {% endif %}required></label>
<div class="authlinks"><button type="button" class="link showpw">Show password</button>{% if can_reset %}<a class="link" href="/forgot">Forgot password?</a>{% endif %}</div>
<button type="submit" class="btn">Sign in</button>
<p class="support">Want to keep this alive? <a href="https://buymeacoffee.com/ttheroux" target="_blank" rel="noopener">Buy us a coffee</a></p>
{% elif mode == 'setup' %}
<label class="field"><span>Username</span><input name="username" maxlength="32" autocomplete="username" autocapitalize="none" autofocus required></label>
<label class="field"><span>Password (8 characters or more)</span><input type="password" name="password" data-pw autocomplete="new-password" minlength="8" required></label>
<label class="field"><span>Confirm password</span><input type="password" name="confirm" data-pw autocomplete="new-password" minlength="8" required></label>
<button type="button" class="link showpw">Show passwords</button>
<button type="submit" class="btn">Create admin account</button>
{% elif mode == 'forgot' %}
<label class="field"><span>Username or email</span><input name="username" autocomplete="username" autocapitalize="none" autofocus required></label>
<button type="submit" class="btn">Email me a code</button>
<div class="authlinks"><a class="link" href="/login">Back to sign in</a></div>
{% else %}
<label class="field"><span>6-digit code</span><input name="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" pattern="[0-9 ]*" autofocus required></label>
<label class="field"><span>New password (8 characters or more)</span><input type="password" name="password" data-pw autocomplete="new-password" minlength="8" required></label>
<label class="field"><span>Confirm new password</span><input type="password" name="confirm" data-pw autocomplete="new-password" minlength="8" required></label>
<button type="button" class="link showpw">Show passwords</button>
<button type="submit" class="btn">Set new password</button>
<div class="authlinks"><a class="link" href="/forgot">Send a new code</a><a class="link" href="/login">Back to sign in</a></div>
{% endif %}
</form>
</main>
{% endif %}
<script nonce="{{ nonce }}">
document.querySelectorAll('.showpw').forEach(function(b){
  var label=b.textContent;
  b.onclick=function(){
    var pw=b.form.querySelectorAll('[data-pw]');
    var showing=pw.length&&pw[0].type==='text';
    pw.forEach(function(i){i.type=showing?'password':'text'});
    b.textContent=showing?label:label.replace('Show','Hide');
  };
});
document.querySelectorAll('[data-autosubmit]').forEach(function(i){i.onchange=function(){i.form.submit()}});
{{ ticks_js|safe }}
(function(){
  var g=document.getElementById('ticks');if(!g)return;
  ticks(g,60,5);
  var hh=document.getElementById('hh'),mh=document.getElementById('mh'),arc=document.getElementById('arc');
  // the hands sweep from 12 to the current time once, then keep time
  function set(){
    var d=new Date(),m=d.getMinutes()+d.getSeconds()/60;
    hh.style.transform='rotate('+((d.getHours()%12+m/60)*30)+'deg)';
    mh.style.transform='rotate('+(m*6)+'deg)';
    arc.style.strokeDashoffset=628.32*(1-m/60);
  }
  requestAnimationFrame(function(){requestAnimationFrame(set)});
  setInterval(set,20000);
})();
</script>
</body></html>
"""

PAGE = """<!doctype html>
<html lang="en"><head>
__HEAD__
<title>Overtime</title>
<style nonce="__NONCE__">__CSS__</style></head><body>
<main class="wrap">
<header class="bar">
  <a class="brand" href="/"><img src="/icon.svg" alt="">Overtime</a>
  <a class="gear" href="/settings" title="Settings" aria-label="Settings"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></svg></a>
</header>
<nav class="chips" id="chips" aria-label="Show company"></nav>
<section class="hero">
  <div class="dialwrap">
    <svg class="dial" viewBox="0 0 240 240" aria-hidden="true">
      <g id="ticks"></g>
      <circle class="track" cx="120" cy="120" r="104"/>
      <circle class="arc" id="arc" cx="120" cy="120" r="100"/>
    </svg>
    <div class="dialc"><div id="bal">0h00</div><div id="sub"></div></div>
  </div>
  <p id="colabel"></p>
  <svg id="spark" class="spark" viewBox="0 0 300 40" preserveAspectRatio="none" role="img" aria-label="Balance over time"></svg>
</section>
<section class="panel" id="entryCard">
  <div class="editing" id="editing" hidden><span>Editing entry</span><button type="button" class="link" id="cancelEdit">Cancel</button></div>
  <div class="seg" id="seg" role="group" aria-label="Entry type">
    <button id="tAdd" type="button" aria-pressed="true">Earned</button>
    <button id="tUse" type="button" aria-pressed="false">Used</button>
  </div>
  <label class="field"><span>Hours</span><input id="hrs" inputmode="decimal" placeholder="1.5 or 1:30" autocomplete="off"></label>
  <div class="quick" aria-label="Quick hours"><button type="button" data-h="0:30">0h30</button><button type="button" data-h="1">1h</button><button type="button" data-h="2">2h</button><button type="button" data-h="4">4h</button><button type="button" data-h="8">8h</button></div>
  <label class="field"><span>Company</span><select id="cosel"></select></label>
  <label class="field" id="conewwrap" hidden><span>New company name</span><input id="conew" maxlength="60" autocomplete="off" placeholder="Who the hours are with"></label>
  <div class="two">
    <label class="field"><span>Day</span><input id="day" type="date"></label>
    <label class="field"><span>Note</span><input id="note" placeholder="Optional" maxlength="200"></label>
  </div>
  <button id="go" type="button" class="btn">Bank hours</button>
</section>
<section class="panel hist" id="list" aria-label="History"></section>
<div class="foot">
  <button id="coDel" type="button" class="link danger">Delete company</button>
  <form method="post" action="/logout"><button type="submit" class="link">Sign out</button></form>
</div>
<p class="support">Want to keep this alive? <a href="https://buymeacoffee.com/ttheroux" target="_blank" rel="noopener">Buy us a coffee</a></p>
</main>
<script nonce="__NONCE__">
const $=s=>document.querySelector(s);
const WEEK=40,DAY=8,C=628.32;
const PEN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>';
const BIN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>';
__TICKS_JS__
ticks($('#ticks'),WEEK,DAY);
function toast(msg){
  const t=document.createElement('div');t.className='toast';t.setAttribute('role','status');t.textContent=msg;document.body.append(t);
  requestAnimationFrame(()=>t.classList.add('show'));
  setTimeout(()=>{t.classList.remove('show');setTimeout(()=>t.remove(),200)},2400);
}
function ask(msg,yesLabel){
  return new Promise(res=>{
    const ov=document.createElement('div');ov.className='ov';
    const dlg=document.createElement('div');dlg.className='dlg';dlg.setAttribute('role','alertdialog');dlg.setAttribute('aria-modal','true');
    const p=document.createElement('p');p.textContent=msg;
    const row=document.createElement('div');row.className='dlgrow';
    const no=document.createElement('button');no.className='btn ghost';no.type='button';no.textContent='Cancel';
    const yes=document.createElement('button');yes.className='btn danger';yes.type='button';yes.textContent=yesLabel;
    row.append(no,yes);dlg.append(p,row);ov.append(dlg);document.body.append(ov);no.focus();
    const done=v=>{ov.remove();removeEventListener('keydown',esc);res(v)};
    const esc=e=>{if(e.key==='Escape')done(false)};
    addEventListener('keydown',esc);
    ov.onclick=e=>{if(e.target===ov)done(false)};
    no.onclick=()=>done(false);yes.onclick=()=>done(true);
  });
}
function store(k,v){try{localStorage.setItem(k,v)}catch(e){}}
function stored(k){try{return localStorage.getItem(k)}catch(e){return null}}
// cid is the company filter: null shows the whole bank
let sign=1,companies=[],cid=null,editingId=null,balShown=null;
{const f=stored('filter');if(f&&f!=='all')cid=+f}
$('#day').value=new Date().toLocaleDateString('en-CA');
function fmt(h){const s=h<0?'-':'';const m=Math.round(Math.abs(h)*60);return s+Math.floor(m/60)+'h'+String(m%60).padStart(2,'0')}
function parse(v){v=v.trim().replace(',','.');if(v.includes(':')){const[a,b]=v.split(':');return (+a)+(+b)/60}return parseFloat(v)}
async function api(url,opt){const r=await fetch(url,opt);if(r.status===401){location='/login';throw new Error('auth')}return r}
function cname(id){const c=companies.find(c=>c.id===id);return c?c.name:''}
// the Company field starts on the filtered company, else the one used last
function defaultCo(){return cid!==null?cname(cid):(stored('lastco')||(companies.length===1?companies[0].name:''))}
function label(){
  if(editingId!==null){$('#go').textContent='Update entry';return}
  const h=parse($('#hrs').value),amt=h>0?fmt(h):'hours';
  $('#go').textContent=sign>0?'Bank '+amt:'Use '+amt;
}
function tab(s){
  sign=s;$('#seg').classList.toggle('use',s<0);
  $('#tAdd').setAttribute('aria-pressed',String(s>0));$('#tUse').setAttribute('aria-pressed',String(s<0));label();
}
$('#tAdd').onclick=()=>tab(1);$('#tUse').onclick=()=>tab(-1);
$('#hrs').oninput=label;
document.querySelectorAll('[data-h]').forEach(b=>b.onclick=()=>{$('#hrs').value=b.dataset.h;label()});
// How much of the dial to fill for a balance. One full turn is one work week.
function ringFraction(b){return Math.min(Math.abs(b)/WEEK,1)}
function setRing(b){const a=$('#arc');a.style.strokeDashoffset=C*(1-ringFraction(b));a.classList.toggle('neg',b<0)}
function days(b){
  if(!b)return'Nothing banked yet';
  const d=(Math.abs(b)/DAY).toFixed(1);
  return '≈ '+d+' workday'+(d==='1.0'?'':'s')+(b<0?' owed':' off');
}
function animateBal(target){
  const el=$('#bal'),from=balShown===null?target:balShown,start=performance.now();
  balShown=target;
  el.classList.toggle('long',Math.max(fmt(from).length,fmt(target).length)>4);  // keep 10h30 inside the ticks
  function step(t){const p=Math.min(1,(t-start)/400),e=1-Math.pow(1-p,3);el.textContent=fmt(from+(target-from)*e);if(p<1)requestAnimationFrame(step)}
  if(from===target)el.textContent=fmt(target);else requestAnimationFrame(step);
}
function drawSpark(entries){
  const svg=$('#spark');
  if(entries.length<2){svg.innerHTML='';svg.hidden=true;return}
  svg.hidden=false;
  let sum=0;const pts=[0];
  entries.slice().reverse().forEach(e=>{sum+=e.hours;pts.push(sum)});
  const min=Math.min(0,...pts),max=Math.max(0,...pts),span=(max-min)||1,w=300,h=40,pad=3;
  const stepX=(w-2*pad)/(pts.length-1),y=v=>h-pad-((v-min)/span)*(h-2*pad);
  const d=pts.map((v,i)=>(i?'L':'M')+(pad+i*stepX).toFixed(1)+','+y(v).toFixed(1)).join(' ');
  const z=y(0).toFixed(1);
  svg.innerHTML='<line class="zero" x1="'+pad+'" y1="'+z+'" x2="'+(w-pad)+'" y2="'+z+'"/><path class="ln" d="'+d+'"/>';
}
function pick(id){if(id===cid)return;cid=id;store('filter',id===null?'all':String(id));stopEdit();refresh()}
function renderChips(){
  const nav=$('#chips');nav.textContent='';
  nav.hidden=!companies.length;  // need at least one company shown/selectable, even just to delete it
  const chip=(name,bal,id)=>{
    const b=document.createElement('button');b.type='button';b.className='chip';b.setAttribute('aria-pressed',String(id===cid));
    const n=document.createElement('b');n.textContent=name;
    const v=document.createElement('span');v.className='num';v.textContent=fmt(bal);
    b.append(n,v);b.onclick=()=>pick(id);nav.append(b);
  };
  chip('All',companies.reduce((s,c)=>s+c.balance,0),null);
  companies.forEach(c=>chip(c.name,c.balance,c.id));
  const on=nav.querySelector('[aria-pressed=true]');if(on)on.scrollIntoView({block:'nearest',inline:'nearest'});
}
function iconBtn(svg,name,fn){
  const b=document.createElement('button');b.type='button';b.className='icbtn';b.title=name;b.setAttribute('aria-label',name);
  b.innerHTML=svg;b.onclick=ev=>{ev.stopPropagation();fn()};return b;
}
function editEntry(e){
  editingId=e.id;tab(e.hours>0?1:-1);
  $('#day').value=e.day;$('#hrs').value=String(Math.abs(e.hours));$('#note').value=e.note||'';setCo(e.company);
  $('#editing').hidden=false;label();
  $('#entryCard').scrollIntoView({behavior:'smooth',block:'nearest'});
  $('#hrs').focus({preventScroll:true});
}
function stopEdit(){
  editingId=null;$('#editing').hidden=true;$('#hrs').value='';$('#note').value='';setCo(defaultCo());label();
}
function renderList(entries){
  const l=$('#list');l.textContent='';
  if(!entries.length){
    const p=document.createElement('p');p.className='empty';p.textContent='No entries yet. Bank your first overtime above.';l.append(p);return;
  }
  let month=null,net=0,sum=null;
  const flush=()=>{if(sum)sum.textContent=(net>0?'+':'')+fmt(net)};
  entries.forEach(e=>{
    const d=new Date(e.day+'T00:00'),ok=!isNaN(d);
    if(e.day.slice(0,7)!==month){
      flush();month=e.day.slice(0,7);net=0;
      const head=document.createElement('div');head.className='month';
      const t=document.createElement('span');t.textContent=ok?d.toLocaleDateString(undefined,{month:'long',year:'numeric'}):month;
      sum=document.createElement('span');sum.className='num';
      head.append(t,sum);l.append(head);
    }
    net+=e.hours;
    const row=document.createElement('div');row.className='row'+(e.hours<0?' neg':'');
    const stripe=document.createElement('i');stripe.className='stripe';
    const what=document.createElement('div');what.className='what';
    const n=document.createElement('span');n.textContent=e.note||(e.hours>0?'Overtime':'Time off');
    const dd=document.createElement('small');dd.textContent=ok?d.toLocaleDateString(undefined,{weekday:'short',month:'short',day:'numeric'}):e.day;
    if(cid===null&&companies.length>1){const co=document.createElement('b');co.textContent=e.company;dd.prepend(co)}
    what.append(n,dd);
    const a=document.createElement('span');a.className='amt';a.textContent=(e.hours>0?'+':'')+fmt(e.hours);
    const ed=iconBtn(PEN,'Edit entry',()=>editEntry(e));
    const x=iconBtn(BIN,'Delete entry',async()=>{
      if(!await ask('Delete this entry?','Delete'))return;
      await api('/api/entries/'+e.id,{method:'DELETE'});
      if(editingId===e.id)stopEdit();
      toast('Entry deleted');refresh(cid);
    });
    x.classList.add('del');
    row.append(stripe,what,a,ed,x);row.onclick=()=>editEntry(e);
    l.append(row);
  });
  flush();
}
// Company picker: a real <select> of this user's companies, plus "+ New company…" which opens a name field
function getCo(){
  const v=$('#cosel').value;
  return (v==='__new__'?$('#conew').value:v).trim().replace(/\\s+/g,' ');
}
function showNewCo(on){$('#conewwrap').hidden=!on}
function setCo(name){
  const known=companies.find(c=>c.name.toLowerCase()===String(name||'').toLowerCase());
  if(known){$('#cosel').value=known.name;$('#conew').value='';showNewCo(false)}
  else{$('#cosel').value='__new__';$('#conew').value=name||'';showNewCo(true)}
}
function fillCo(){
  const keep=$('#cosel').options.length?getCo():(editingId===null?defaultCo():'');
  const sel=$('#cosel');sel.textContent='';
  companies.forEach(c=>{const o=document.createElement('option');o.value=c.name;o.textContent=c.name;sel.append(o)});
  const n=document.createElement('option');n.value='__new__';n.textContent='+ New company…';sel.append(n);
  setCo(keep||defaultCo());
}
$('#cosel').onchange=()=>{const on=$('#cosel').value==='__new__';showNewCo(on);if(on)$('#conew').focus()};
async function loadCompanies(){
  const r=await(await api('/api/companies')).json();
  companies=r.companies;
  if(cid!==null&&!companies.some(c=>c.id===cid))cid=null;
  renderChips();
  fillCo();
  $('#coDel').hidden=cid===null;
  if(cid!==null)$('#coDel').textContent='Delete '+cname(cid);
}
async function load(){
  $('#colabel').textContent=cid!==null?cname(cid):
    companies.length>1?'All companies':companies.length?companies[0].name:'Bank your first hours below';
  const l=$('#list');
  if(!l.children.length)l.innerHTML='<div class="skel"></div><div class="skel short"></div>';
  const r=await(await api('/api/entries'+(cid===null?'':'?company='+cid))).json();
  animateBal(r.balance);setRing(r.balance);
  $('#bal').classList.toggle('neg',r.balance<0);
  $('#sub').textContent=days(r.balance);
  drawSpark(r.entries);renderList(r.entries);
}
async function refresh(){await loadCompanies();await load()}
$('#cancelEdit').onclick=stopEdit;
$('#coDel').onclick=async()=>{
  const c=companies.find(c=>c.id===cid);if(!c)return;
  const n=c.entries||0;
  if(!await ask('Delete "'+c.name+'" and its '+n+' entr'+(n===1?'y':'ies')+'? This cannot be undone.','Delete'))return;
  await api('/api/companies/'+cid,{method:'DELETE'});
  toast('Deleted '+c.name);
  if(stored('lastco')===c.name)store('lastco','');
  cid=null;store('filter','all');setCo('');
  await refresh();
};
$('#go').onclick=async()=>{
  const h=parse($('#hrs').value);
  if(!h||h<=0){toast('Enter hours, like 1.5 or 1:30');$('#hrs').focus();return}
  const co=getCo();
  if(!co){toast('Pick a company or add a new one');($('#conewwrap').hidden?$('#cosel'):$('#conew')).focus();return}
  const body={company:co,day:$('#day').value,hours:sign*h,note:$('#note').value};
  const r=editingId!==null
    ?await api('/api/entries/'+editingId,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    :await api('/api/entries',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok){
    const j=await r.json().catch(()=>({}));
    toast(j.error==='not enough hours banked'?"Not enough hours banked, can't go negative":'Could not save. Check the day and hours.');
    return;
  }
  store('lastco',co);
  toast(editingId!==null?'Entry updated':(sign>0?'Banked '+fmt(h)+' with ':'Used '+fmt(h)+' from ')+co);
  stopEdit();refresh();
};
['#hrs','#note','#conew'].forEach(s=>$(s).onkeydown=e=>{if(e.key==='Enter')$('#go').click()});
const IDLE=__IDLE__*60000;
let last=Date.now(),pinged=Date.now();
async function bye(){try{await fetch('/logout',{method:'POST'})}catch(e){}location='/login'}
function act(){last=Date.now();if(IDLE&&Date.now()-pinged>60000){pinged=Date.now();fetch('/api/ping',{method:'POST'})}}
['pointerdown','keydown','touchstart','scroll','input'].forEach(ev=>addEventListener(ev,act,{passive:true}));
function check(){if(IDLE&&Date.now()-last>IDLE)bye()}
setInterval(check,15000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)check()});
refresh();
</script></body></html>
""".replace("__HEAD__", HEAD).replace("__CSS__", CSS).replace("__TICKS_JS__", TICKS_JS)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setpw":
        # Reset a forgotten password from the server console: python app.py setpw <username>
        # (also re-enables the account and makes it an admin, so a locked-out server can always be recovered)
        if len(sys.argv) != 3:
            sys.exit("Usage: python app.py setpw <username>")
        c = sqlite3.connect(DB)
        if not c.execute("SELECT 1 FROM users WHERE username = ?", (sys.argv[2],)).fetchone():
            names = ", ".join(r[0] for r in c.execute("SELECT username FROM users ORDER BY username"))
            sys.exit(f"No user named {sys.argv[2]}. Users: {names or 'none yet'}")
        pw = getpass.getpass("New password: ")
        if len(pw) < MIN_PW or pw != getpass.getpass("Confirm: "):
            sys.exit(f"Passwords must match and be at least {MIN_PW} characters.")
        c.execute("UPDATE users SET pw_hash = ?, epoch = ?, disabled = 0, is_admin = 1 WHERE username = ?",
                  (generate_password_hash(pw), new_epoch(), sys.argv[2]))
        c.commit()
        c.close()
        print(f"Password updated for {sys.argv[2]}, who is now an enabled admin. Their devices were signed out.")
        sys.exit(0)
    app.run(host="0.0.0.0", port=8080)
