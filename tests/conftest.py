import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def app_module(tmp_path, monkeypatch):
    """A freshly-imported app module backed by an empty temp-file SQLite DB."""
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    import app as mod
    importlib.reload(mod)
    mod.app.config["TESTING"] = True
    return mod


@pytest.fixture
def client(app_module):
    with app_module.app.test_client() as c:
        yield c


def raw_db(app_module):
    """A second, independent sqlite3 connection to the same temp DB, for setup/assertions
    outside of a request (the app's own `g.db` only exists inside a request context)."""
    import sqlite3
    conn = sqlite3.connect(app_module.DB)
    conn.row_factory = sqlite3.Row
    return conn


def make_admin(app_module, username="admin", password="adminpass1"):
    """Create the first (admin) account through the real /setup flow."""
    with app_module.app.test_client() as c:
        c.post("/setup", data={"username": username, "password": password, "confirm": password})
    return username, password


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})
