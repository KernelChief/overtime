import sqlite3

from conftest import make_admin, raw_db


def test_init_db_creates_core_tables(app_module):
    conn = raw_db(app_module)
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"entries", "settings", "users", "reset_codes", "companies"} <= names
    conn.close()


def test_migration_promotes_existing_password_to_admin_user(tmp_path, monkeypatch):
    import importlib
    db_path = tmp_path / "legacy.db"
    monkeypatch.setenv("DB_PATH", str(db_path))

    import app as mod
    importlib.reload(mod)  # first import: creates an empty fresh-style DB

    # Simulate a pre-accounts install: wipe the fresh DB and recreate it the old, single-password way.
    db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.executescript(
        "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, day TEXT NOT NULL, "
        "hours REAL NOT NULL, note TEXT DEFAULT '');"
        "CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT NOT NULL UNIQUE COLLATE NOCASE);"
    )
    conn.execute("INSERT INTO settings (key, value) VALUES ('pw_hash', 'pbkdf2:sha256:FAKE')")
    conn.execute("INSERT INTO settings (key, value) VALUES ('pw_epoch', 'old-epoch')")
    conn.execute("INSERT INTO companies (name) VALUES ('Acme Co')")
    conn.execute("INSERT INTO entries (day, hours) VALUES ('2026-01-01', 8)")
    conn.commit()
    conn.close()

    importlib.reload(mod)  # re-import: must run the migration against the legacy-shaped DB

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    assert admin is not None
    assert admin["pw_hash"] == "pbkdf2:sha256:FAKE"
    assert admin["is_admin"] == 1
    assert admin["disabled"] == 0
    assert conn.execute("SELECT value FROM settings WHERE key = 'pw_hash'").fetchone() is None
    # the pre-existing company is reassigned to the new admin, not left ownerless
    company = conn.execute("SELECT * FROM companies WHERE name = 'Acme Co'").fetchone()
    assert company["user_id"] == admin["id"]
    # the entry predates companies entirely, so it's parked under an auto-created "Unassigned" one
    unassigned = conn.execute("SELECT * FROM companies WHERE name = 'Unassigned'").fetchone()
    assert unassigned["user_id"] == admin["id"]
    entry = conn.execute("SELECT * FROM entries").fetchone()
    assert entry["company_id"] == unassigned["id"]
    conn.close()


def test_setup_creates_admin_and_signs_in(app_module, client):
    resp = client.post("/setup", data={"username": "boss", "password": "longenough1", "confirm": "longenough1"})
    assert resp.status_code == 302
    u = raw_db(app_module).execute("SELECT * FROM users WHERE username = 'boss'").fetchone()
    assert u["is_admin"] == 1
    # already signed in, no redirect to /login needed
    assert client.get("/").status_code == 200


def test_setup_rejects_short_password(app_module, client):
    resp = client.post("/setup", data={"username": "boss", "password": "short", "confirm": "short"})
    assert resp.status_code == 200
    assert raw_db(app_module).execute("SELECT 1 FROM users").fetchone() is None


def test_login_wrong_password_fails_and_counts_toward_lockout(app_module, client):
    make_admin(app_module, "boss", "longenough1")
    for _ in range(app_module.MAX_FAILS):
        resp = client.post("/login", data={"username": "boss", "password": "nope"})
        assert resp.status_code == 200
    resp = client.post("/login", data={"username": "boss", "password": "longenough1"})
    assert b"Too many attempts" in resp.data


def test_login_succeeds_with_right_password(app_module, client):
    make_admin(app_module, "boss", "longenough1")
    resp = client.post("/login", data={"username": "boss", "password": "longenough1"})
    assert resp.status_code == 302
    assert client.get("/").status_code == 200


def test_login_rejects_disabled_account(app_module, client):
    make_admin(app_module, "boss", "longenough1")
    with app_module.app.test_client() as admin_c:
        admin_c.post("/login", data={"username": "boss", "password": "longenough1"})
        admin_c.post("/admin/users", data={"username": "second", "password": "longenough2", "admin": "1"})
        uid = raw_db(app_module).execute("SELECT id FROM users WHERE username = 'second'").fetchone()[0]
        admin_c.post(f"/admin/users/{uid}/disable")
    resp = client.post("/login", data={"username": "second", "password": "longenough2"})
    assert b"disabled" in resp.data


def test_cannot_demote_the_only_admin(app_module):
    make_admin(app_module, "boss", "longenough1")
    with app_module.app.test_client() as c:
        c.post("/login", data={"username": "boss", "password": "longenough1"})
        uid = raw_db(app_module).execute("SELECT id FROM users WHERE username = 'boss'").fetchone()[0]
        resp = c.post(f"/admin/users/{uid}/role", data={"admin": "0"})
        assert b"Keep at least one admin" in resp.data


def test_cannot_disable_own_account(app_module):
    make_admin(app_module, "boss", "longenough1")
    with app_module.app.test_client() as c:
        c.post("/login", data={"username": "boss", "password": "longenough1"})
        uid = raw_db(app_module).execute("SELECT id FROM users WHERE username = 'boss'").fetchone()[0]
        resp = c.post(f"/admin/users/{uid}/disable")
        assert b"can&#39;t disable your own account" in resp.data or b"can't disable your own account" in resp.data


def test_admin_can_add_and_remove_a_user(app_module):
    make_admin(app_module, "boss", "longenough1")
    with app_module.app.test_client() as c:
        c.post("/login", data={"username": "boss", "password": "longenough1"})
        c.post("/admin/users", data={"username": "worker", "password": "longenough2"})
        row = raw_db(app_module).execute("SELECT id, is_admin FROM users WHERE username = 'worker'").fetchone()
        assert row is not None and row["is_admin"] == 0
        c.post(f"/admin/users/{row['id']}/delete")
        assert raw_db(app_module).execute("SELECT 1 FROM users WHERE username = 'worker'").fetchone() is None


def test_non_admin_cannot_reach_admin_routes(app_module):
    make_admin(app_module, "boss", "longenough1")
    with app_module.app.test_client() as c:
        c.post("/login", data={"username": "boss", "password": "longenough1"})
        c.post("/admin/users", data={"username": "worker", "password": "longenough2"})
    with app_module.app.test_client() as worker_c:
        worker_c.post("/login", data={"username": "worker", "password": "longenough2"})
        resp = worker_c.get("/admin/users")
        assert resp.status_code == 403


def test_password_change_signs_out_other_sessions(app_module):
    make_admin(app_module, "boss", "longenough1")
    c1 = app_module.app.test_client()
    c2 = app_module.app.test_client()
    c1.post("/login", data={"username": "boss", "password": "longenough1"})
    c2.post("/login", data={"username": "boss", "password": "longenough1"})
    c1.post("/settings", data={"current": "longenough1", "new": "longenough9", "confirm": "longenough9"})
    # c2's session cookie is now stale; the auth gate should bounce it to /login
    resp = c2.get("/admin/users")
    assert resp.status_code in (302, 401)
