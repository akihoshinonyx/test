# -*- coding: utf-8 -*-
"""SQLite storage for the AmneziaWG panel."""
import os
import sqlite3
import time
import hashlib
import secrets

DB_PATH = os.environ.get("AWG_DB", "/var/lib/amnezia-panel/panel.db")


def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',      -- admin | user
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_login INTEGER
);
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    owner_id INTEGER,                       -- NULL for admin-created keys
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    preshared_key TEXT NOT NULL,
    ip4 TEXT,
    ip6 TEXT,
    endpoint_ip TEXT,
    endpoint_port INTEGER NOT NULL DEFAULT 443,
    dns TEXT DEFAULT '8.8.8.8, 8.8.4.4',
    mtu INTEGER DEFAULT 1420,
    enable_pfs INTEGER DEFAULT 1,
    tg_port INTEGER DEFAULT 443,
    enable_amnezia INTEGER DEFAULT 1,
    junk_min_size INTEGER DEFAULT 50,
    junk_max_size INTEGER DEFAULT 90,
    junk_count INTEGER DEFAULT 3,
    packets_per_junk INTEGER DEFAULT 3,
    init_packet_junk_size INTEGER DEFAULT 857,
    response_packet_junk_size INTEGER DEFAULT 1271,
    counter INTEGER DEFAULT 0,
    transport TEXT DEFAULT 'wg-amnezia',   -- wg | wg-amnezia | shadowsocks
    ss_cipher TEXT DEFAULT 'aes-256-gcm',
    ss_password TEXT,
    ss_port INTEGER,
    status TEXT NOT NULL DEFAULT 'active',  -- active | disabled | expired
    expires_at INTEGER,
    quota_bytes INTEGER,                    -- NULL = unlimited
    used_bytes INTEGER DEFAULT 0,
    allowed_ips TEXT DEFAULT '0.0.0.0/0, ::/0',
    note TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    last_seen INTEGER,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
"""


def pw_hash(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
    return h.hex(), salt


ADMIN_CRED_PATH = "/etc/amnezia-panel/admin.json"


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = conn()
    c.executescript(SCHEMA)
    # default admin
    row = c.execute("SELECT COUNT(*) n FROM users WHERE role='admin'").fetchone()
    if row["n"] == 0:
        import json
        try:
            with open(ADMIN_CRED_PATH) as f:
                a = json.load(f)
            uname, pwd = a["username"], a["password"]
        except Exception:
            uname = "admin"
            pwd = secrets.token_urlsafe(12)
            _write_admin(uname, pwd)
        h, s = pw_hash(pwd)
        c.execute(
            "INSERT INTO users(username,pass_hash,salt,role,created_at) VALUES(?,?,?,?,?)",
            (uname, h, s, "admin", int(time.time())),
        )
    c.commit()
    c.close()


def sync_admin_login():
    """Keep the DB admin account in sync with /etc/amnezia-panel/admin.json.

    The installer writes admin.json on every re-run; if the login was renamed
    afterwards we must rename it in the DB too — otherwise the admin would be
    locked out after reinstalling. Password changes happen only via the panel
    API (/api/password), which also updates admin.json.

    Exception: a *fresh* install (empty keys/users activity) may legitimately
    reset the admin password via admin.json — apply it then, so that an
    interrupted first install never leaves a stale unusable hash in the DB.
    """
    import json
    try:
        with open(ADMIN_CRED_PATH) as f:
            a = json.load(f)
        want_user = str(a.get("username") or "").strip().lower()
        want_pass = str(a.get("password") or "")
    except Exception:
        return
    c = conn()
    try:
        r = c.execute("SELECT id, username FROM users WHERE role='admin' "
                      "ORDER BY id LIMIT 1").fetchone()
        if not r:
            return
        if r["username"].lower() != want_user:
            clash = c.execute("SELECT id FROM users WHERE username=? AND id<>?",
                              (want_user, r["id"])).fetchone()
            if not clash:
                c.execute("UPDATE users SET username=? WHERE id=?",
                          (want_user, r["id"]))
        nkeys = c.execute("SELECT COUNT(*) n FROM keys").fetchone()["n"]
        nuser = c.execute("SELECT COUNT(*) n FROM users WHERE role<>'admin'"
                          ).fetchone()["n"]
        if want_pass and nkeys == 0 and nuser == 0:
            h, s = pw_hash(want_pass)
            c.execute("UPDATE users SET pass_hash=?, salt=? WHERE id=?",
                      (h, s, r["id"]))
        c.commit()
    finally:
        c.close()


def _write_admin(u, p):
    import json
    os.makedirs("/etc/amnezia-panel", exist_ok=True)
    with open("/etc/amnezia-panel/admin.json", "w") as f:
        json.dump({"username": u, "password": p}, f)
    os.chmod("/etc/amnezia-panel/admin.json", 0o600)


def get_user_by_login(username, password):
    c = conn()
    r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    c.close()
    if not r or not r["enabled"]:
        return None
    h, _ = pw_hash(password, r["salt"])
    if secrets.compare_digest(h, r["pass_hash"]):
        return dict(r)
    return None


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    c = conn()
    c.execute(
        "INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        (token, user_id, now, now + 7 * 86400),
    )
    c.execute("UPDATE users SET last_login=? WHERE id=?", (now, user_id))
    c.commit()
    c.close()
    return token


def session_user(token):
    if not token:
        return None
    c = conn()
    r = c.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token=? AND s.expires_at>?",
        (token, int(time.time())),
    ).fetchone()
    c.close()
    return dict(r) if r else None


def drop_session(token):
    c = conn()
    c.execute("DELETE FROM sessions WHERE token=?", (token,))
    c.commit()
    c.close()


def get_setting(key, default=None):
    c = conn()
    r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    c.close()
    return r["value"] if r else default


def set_setting(key, value):
    c = conn()
    c.execute(
        "INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )
    c.commit()
    c.close()
