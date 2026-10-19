import json

from conftest import make_admin, raw_db


def signed_in_client(app_module, username="boss", password="longenough1"):
    make_admin(app_module, username, password)
    c = app_module.app.test_client()
    c.post("/login", data={"username": username, "password": password})
    return c


def post_entry(c, company, day, hours, note=""):
    return c.post("/api/entries", data=json.dumps({"company": company, "day": day, "hours": hours, "note": note}),
                  content_type="application/json")


def test_banking_hours_creates_company_and_entry(app_module):
    c = signed_in_client(app_module)
    resp = post_entry(c, "Acme Co", "2026-01-01", 8)
    assert resp.status_code == 200
    rows = c.get("/api/companies").get_json()["companies"]
    assert rows[0]["name"] == "Acme Co"
    assert rows[0]["balance"] == 8


def test_cannot_use_more_hours_than_banked(app_module):
    c = signed_in_client(app_module)
    post_entry(c, "Acme Co", "2026-01-01", 5)
    resp = post_entry(c, "Acme Co", "2026-01-02", -6)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "not enough hours banked"
    # the balance is untouched by the rejected use
    balance = c.get("/api/companies").get_json()["companies"][0]["balance"]
    assert balance == 5


def test_using_exactly_the_banked_balance_is_allowed(app_module):
    c = signed_in_client(app_module)
    post_entry(c, "Acme Co", "2026-01-01", 5)
    resp = post_entry(c, "Acme Co", "2026-01-02", -5)
    assert resp.status_code == 200
    balance = c.get("/api/companies").get_json()["companies"][0]["balance"]
    assert balance == 0


def test_zero_hours_is_rejected(app_module):
    c = signed_in_client(app_module)
    resp = post_entry(c, "Acme Co", "2026-01-01", 0)
    assert resp.status_code == 400


def test_each_user_has_their_own_bank(app_module):
    boss = signed_in_client(app_module, "boss", "longenough1")
    boss.post("/admin/users", data={"username": "worker", "password": "longenough2"})
    worker = app_module.app.test_client()
    worker.post("/login", data={"username": "worker", "password": "longenough2"})

    post_entry(boss, "Acme Co", "2026-01-01", 8)
    post_entry(worker, "Acme Co", "2026-01-01", 3)

    boss_balance = boss.get("/api/companies").get_json()["companies"][0]["balance"]
    worker_balance = worker.get("/api/companies").get_json()["companies"][0]["balance"]
    assert boss_balance == 8
    assert worker_balance == 3


def test_updating_an_entry_still_enforces_the_balance_guard(app_module):
    c = signed_in_client(app_module)
    post_entry(c, "Acme Co", "2026-01-01", 5)
    eid = raw_db(app_module).execute("SELECT id FROM entries").fetchone()[0]
    resp = c.put(f"/api/entries/{eid}", data=json.dumps({"company": "Acme Co", "day": "2026-01-01", "hours": -1}),
                 content_type="application/json")
    assert resp.status_code == 400


def test_deleting_the_last_entry_drops_the_company(app_module):
    c = signed_in_client(app_module)
    post_entry(c, "Acme Co", "2026-01-01", 5)
    eid = raw_db(app_module).execute("SELECT id FROM entries").fetchone()[0]
    c.delete(f"/api/entries/{eid}")
    assert raw_db(app_module).execute("SELECT 1 FROM companies").fetchone() is None


def test_user_cannot_touch_another_users_entry(app_module):
    boss = signed_in_client(app_module, "boss", "longenough1")
    boss.post("/admin/users", data={"username": "worker", "password": "longenough2"})
    post_entry(boss, "Acme Co", "2026-01-01", 8)
    eid = raw_db(app_module).execute("SELECT id FROM entries").fetchone()[0]

    worker = app_module.app.test_client()
    worker.post("/login", data={"username": "worker", "password": "longenough2"})
    resp = worker.delete(f"/api/entries/{eid}")
    assert resp.status_code == 200  # silently a no-op, not an error that leaks existence
    assert raw_db(app_module).execute("SELECT 1 FROM entries WHERE id = ?", (eid,)).fetchone() is not None


def test_csv_export_contains_the_entry(app_module):
    c = signed_in_client(app_module)
    post_entry(c, "Acme Co", "2026-01-01", 8, "first shift")
    resp = c.get("/api/export?format=csv")
    assert resp.status_code == 200
    assert b"Acme Co" in resp.data
    assert b"first shift" in resp.data
