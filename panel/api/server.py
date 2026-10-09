#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AmneziaWG 3.0 control panel — stdlib-only HTTP API + static web UI."""
import json
import mimetypes
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db
import wg

WEB_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
PORT = int(os.environ.get("AWG_PORT", "8777"))

db.init_db()


# ---------------- helpers ----------------

def key_public_view(r, st=None):
    now = int(time.time())
    live = None
    if st and r["public_key"] in st:
        ls = st[r["public_key"]].get("last_seen") or 0
        live = (now - ls) < 120 if ls else False
    expired = bool(r["expires_at"] and r["expires_at"] < now)
    return {
        "id": r["id"], "name": r["name"], "owner_id": r["owner_id"],
        "public_key": r["public_key"], "ip4": r["ip4"], "ip6": r["ip6"],
        "endpoint_ip": r["endpoint_ip"], "endpoint_port": r["endpoint_port"],
        "dns": r["dns"], "mtu": r["mtu"], "counter": r["counter"],
        "transport": r["transport"], "ss_cipher": r["ss_cipher"],
        "ss_password": r["ss_password"], "ss_port": r["ss_port"],
        "enable_pfs": bool(r["enable_pfs"]), "tg_port": r["tg_port"],
        "enable_amnezia": bool(r["enable_amnezia"]),
        "junk_min_size": r["junk_min_size"], "junk_max_size": r["junk_max_size"],
        "junk_count": r["junk_count"], "packets_per_junk": r["packets_per_junk"],
        "init_packet_junk_size": r["init_packet_junk_size"],
        "response_packet_junk_size": r["response_packet_junk_size"],
        "status": "expired" if expired else r["status"],
        "expires_at": r["expires_at"], "quota_bytes": r["quota_bytes"],
        "used_bytes": r["used_bytes"], "allowed_ips": r["allowed_ips"],
        "note": r["note"], "created_at": r["created_at"],
        "last_seen": r["last_seen"], "online": bool(live),
    }


SETTINGS_KEYS = [
    "endpoint_host", "port", "subnet", "server_ip", "server_ipv6",
    "pfs", "amnezia_enabled", "jc", "jmin", "jmax", "s1", "s2", "st",
    "default_dns", "default_mtu", "site_name",
]


class Handler(BaseHTTPRequestHandler):
    server_version = "AmneziaPanel/3.0"

    def log_message(self, fmt, *args):
        pass

    # ---------- plumbing ----------

    def _send(self, code, body=b"", ctype="application/json; charset=utf-8",
              extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json_out(self, obj, code=200, extra_headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   extra_headers=extra_headers)

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}

    def current_user(self):
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        tok = ck["awg_session"].value if "awg_session" in ck else None
        u = db.session_user(tok)
        if not u:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                u = db.session_user(auth[7:].strip())
        return u

    # ---------- routing ----------

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_PUT(self):
        self.dispatch("PUT")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def dispatch(self, method):
        path = urlparse(self.path).path
        try:
            for regex, mth, fn in ROUTES:
                if mth != method:
                    continue
                mo = regex.match(path)
                if mo:
                    return fn(self, *(mo.groups()))
            if method == "GET":
                return self.serve_static(path)
            self.json_out({"error": "not found"}, 404)
        except PermissionError as e:
            self.json_out({"error": str(e)}, 403)
        except ValueError as e:
            self.json_out({"error": str(e)}, 400)
        except Exception as e:
            self.json_out({"error": "internal: %s" % e}, 500)

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        full = os.path.normpath(os.path.join(WEB_ROOT, path.lstrip("/")))
        if not full.startswith(WEB_ROOT) or not os.path.isfile(full):
            full = os.path.join(WEB_ROOT, "index.html")
            if not os.path.isfile(full):
                return self._send(404, "not found", "text/plain")
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype)

    # ---------- auth ----------

    def require(self, admin=False):
        u = self.current_user()
        if not u:
            raise PermissionError("unauthorized")
        if admin and u["role"] != "admin":
            raise PermissionError("admin only")
        return u

    def api_login(self):
        d = self.read_body()
        u = db.get_user_by_login(d.get("username", "").strip(), d.get("password", ""))
        if not u:
            time.sleep(0.4)
            return self.json_out({"error": "Неверный логин или пароль"}, 401)
        tok = db.create_session(u["id"])
        self.json_out({"ok": True, "user": sanitize_user(u)}, extra_headers={
            "Set-Cookie": "awg_session=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800" % tok,
        })

    def api_logout(self):
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        if "awg_session" in ck:
            db.drop_session(ck["awg_session"].value)
        self.json_out({"ok": True}, extra_headers={
            "Set-Cookie": "awg_session=; HttpOnly; Path=/; Max-Age=0"})

    def api_me(self):
        u = self.require()
        self.json_out({"user": sanitize_user(u)})

    # ---------- keys ----------

    def api_keys_list(self):
        u = self.require()
        c = db.conn()
        if u["role"] == "admin":
            rows = c.execute("SELECT * FROM keys ORDER BY id DESC").fetchall()
        else:
            rows = c.execute("SELECT * FROM keys WHERE owner_id=? ORDER BY id DESC",
                             (u["id"],)).fetchall()
        st = wg.peer_status()
        out = [key_public_view(r, st) for r in rows]
        c.close()
        self.json_out(out)

    def api_key_get(self, kid):
        u = self.require()
        c = db.conn()
        r = c.execute("SELECT * FROM keys WHERE id=?", (int(kid),)).fetchone()
        c.close()
        if not r:
            return self.json_out({"error": "not found"}, 404)
        if u["role"] != "admin" and r["owner_id"] != u["id"]:
            raise PermissionError("forbidden")
        v = key_public_view(r, wg.peer_status())
        v["private_key"] = r["private_key"]
        v["preshared_key"] = r["preshared_key"]
        self.json_out(v)

    def api_key_create(self):
        u = self.require()
        d = self.read_body()
        name = (d.get("name") or "").strip() or "key-%d" % int(time.time())
        owner = u["id"]
        if u["role"] == "admin" and d.get("owner_id"):
            owner = int(d["owner_id"])
        if u["role"] != "admin":
            cnt = db.conn().execute(
                "SELECT COUNT(*) n FROM keys WHERE owner_id=?", (u["id"],)
            ).fetchone()["n"]
            limit = int(db.get_setting("user_key_limit", "10"))
            if cnt >= limit:
                raise ValueError("Достигнут лимит ключей (%d)" % limit)
        priv = wg.gen_privkey()
        pub = wg.pubkey(priv)
        psk = wg.gen_psk()
        days = d.get("expires_days")
        expires = int(time.time()) + int(days) * 86400 if days else None
        quota_mb = d.get("quota_mb")
        transport = d.get("transport") or db.get_setting("default_transport", "wg-amnezia")
        ss_pass = secrets.token_urlsafe(16) if transport == "shadowsocks" else None
        c = db.conn()
        ip4 = wg.next_ip(c)
        counter = wg.gen_counter()
        v6 = db.get_setting("server_ipv6")
        ip6 = None
        if v6:
            base = v6.split("/")[0].rsplit("::", 1)[0]  # e.g. fdaa:bd4c:1234
            ip6 = "%s::%x" % (base, counter)
        c.execute(
            """INSERT INTO keys(name,owner_id,private_key,public_key,preshared_key,
               ip4,ip6,endpoint_ip,endpoint_port,dns,mtu,enable_pfs,tg_port,
               enable_amnezia,junk_min_size,junk_max_size,junk_count,packets_per_junk,
               init_packet_junk_size,response_packet_junk_size,counter,transport,
               ss_cipher,ss_password,ss_port,status,expires_at,quota_bytes,allowed_ips,
               note,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (name, owner, priv, pub, psk, ip4, ip6,
             d.get("endpoint_ip") or db.get_setting("endpoint_host", ""),
             int(d.get("endpoint_port") or db.get_setting("port", "443")),
             d.get("dns") or db.get_setting("default_dns", "8.8.8.8, 8.8.4.4"),
             int(d.get("mtu") or db.get_setting("default_mtu", "1420")),
             1 if d.get("enable_pfs", True) else 0,
             int(d.get("tg_port") or 443),
             1 if d.get("enable_amnezia", True) else 0,
             int(d.get("junk_min_size") or 50), int(d.get("junk_max_size") or 90),
             int(d.get("junk_count") or 3), int(d.get("packets_per_junk") or 3),
             int(d.get("init_packet_junk_size") or 857),
             int(d.get("response_packet_junk_size") or 1271),
             counter, transport,
             d.get("ss_cipher") or "aes-256-gcm", ss_pass,
             int(d.get("ss_port") or db.get_setting("port", "443")),
             "active", expires,
             int(float(quota_mb) * 1024 * 1024) if quota_mb else None,
             d.get("allowed_ips") or "0.0.0.0/0, ::/0",
             d.get("note") or "", int(time.time())),
        )
        c.commit()
        kid = c.execute("SELECT last_insert_rowid() i").fetchone()["i"]
        row = c.execute("SELECT * FROM keys WHERE id=?", (kid,)).fetchone()
        c.close()
        ok, err = wg.apply_config()
        res = key_public_view(row, {})
        res["private_key"] = priv
        res["applied"] = ok
        if not ok:
            res["apply_error"] = err
        self.json_out(res, 201)

    def api_key_update(self, kid):
        u = self.require()
        d = self.read_body()
        c = db.conn()
        r = c.execute("SELECT * FROM keys WHERE id=?", (int(kid),)).fetchone()
        if not r:
            c.close()
            return self.json_out({"error": "not found"}, 404)
        if u["role"] != "admin" and r["owner_id"] != u["id"]:
            c.close()
            raise PermissionError("forbidden")
        fields = []
        vals = []
        simple = ["name", "dns", "note", "allowed_ips", "endpoint_ip"]
        ints = ["endpoint_port", "mtu", "tg_port", "junk_min_size", "junk_max_size",
                "junk_count", "packets_per_junk", "init_packet_junk_size",
                "response_packet_junk_size", "ss_port"]
        bools = ["enable_pfs", "enable_amnezia"]
        for f in simple:
            if f in d:
                fields.append("%s=?" % f); vals.append(d[f])
        for f in ints:
            if f in d and d[f] not in (None, ""):
                fields.append("%s=?" % f); vals.append(int(d[f]))
        for f in bools:
            if f in d:
                fields.append("%s=?" % f); vals.append(1 if d[f] else 0)
        if "status" in d and u["role"] == "admin":
            fields.append("status=?"); vals.append(d["status"])
        if "expires_days" in d:
            if d["expires_days"] in (None, "", 0):
                fields.append("expires_at=NULL")
            else:
                fields.append("expires_at=?")
                vals.append(int(time.time()) + int(d["expires_days"]) * 86400)
        if "quota_mb" in d:
            q = d["quota_mb"]
            fields.append("quota_bytes=?")
            vals.append(int(float(q) * 1024 * 1024) if q else None)
        if "transport" in d:
            fields.append("transport=?"); vals.append(d["transport"])
        if "ss_password" in d:
            fields.append("ss_password=?"); vals.append(d["ss_password"])
        if "ss_cipher" in d:
            fields.append("ss_cipher=?"); vals.append(d["ss_cipher"])
        if fields:
            vals.append(int(kid))
            c.execute("UPDATE keys SET %s WHERE id=?" % ",".join(fields), vals)
            c.commit()
        row = c.execute("SELECT * FROM keys WHERE id=?", (int(kid),)).fetchone()
        c.close()
        ok, err = wg.apply_config()
        res = key_public_view(row, {})
        res["applied"] = ok
        self.json_out(res)

    def api_key_delete(self, kid):
        u = self.require()
        c = db.conn()
        r = c.execute("SELECT * FROM keys WHERE id=?", (int(kid),)).fetchone()
        if not r:
            c.close()
            return self.json_out({"error": "not found"}, 404)
        if u["role"] != "admin" and r["owner_id"] != u["id"]:
            c.close()
            raise PermissionError("forbidden")
        c.execute("DELETE FROM keys WHERE id=?", (int(kid),))
        c.commit()
        c.close()
        try:
            os.unlink("/var/lib/amnezia-panel/psk_%s.pem" % kid)
        except OSError:
            pass
        wg.apply_config()
        self.json_out({"ok": True})

    def api_key_rotate(self, kid):
        self.require(admin=True)
        c = db.conn()
        r = c.execute("SELECT * FROM keys WHERE id=?", (int(kid),)).fetchone()
        if not r:
            c.close()
            return self.json_out({"error": "not found"}, 404)
        priv = wg.gen_privkey()
        pub = wg.pubkey(priv)
        psk = wg.gen_psk()
        c.execute("UPDATE keys SET private_key=?, public_key=?, preshared_key=? WHERE id=?",
                  (priv, pub, psk, int(kid)))
        c.commit()
        row = c.execute("SELECT * FROM keys WHERE id=?", (int(kid),)).fetchone()
        c.close()
        wg.apply_config()
        res = key_public_view(row, {})
        res["private_key"] = priv
        self.json_out(res)

    def _key_or_404(self, kid, u):
        c = db.conn()
        r = c.execute("SELECT * FROM keys WHERE id=?", (int(kid),)).fetchone()
        c.close()
        if not r:
            raise ValueError("key not found")
        if u["role"] != "admin" and r["owner_id"] != u["id"]:
            raise PermissionError("forbidden")
        return r

    def api_key_ini(self, kid):
        u = self.require()
        r = self._key_or_404(kid, u)
        ini = wg.key_ini(r, amnezia=bool(r["enable_amnezia"]))
        safe = re.sub(r"[^\w\-]", "_", r["name"])
        self._send(200, ini, "text/plain; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="%s.conf"' % safe})

    def api_key_json(self, kid):
        u = self.require()
        r = self._key_or_404(kid, u)
        self._send(200, wg.key_native_json(r), "application/json",
                   {"Content-Disposition": 'attachment; filename="%s.json"' %
                    re.sub(r"[^\w\-]", "_", r["name"])})

    def api_key_qr(self, kid):
        u = self.require()
        r = self._key_or_404(kid, u)
        png = wg.qr_png_bytes(wg.key_ini(r, amnezia=bool(r["enable_amnezia"])))
        if not png:
            return self.json_out({"error": "qrcode lib missing"}, 500)
        self._send(200, png, "image/png")

    # ---------- users (admin) ----------

    def api_users_list(self):
        self.require(admin=True)
        c = db.conn()
        rows = c.execute("SELECT id,username,role,enabled,created_at,last_login FROM users ORDER BY id").fetchall()
        counts = {r["owner_id"]: r["n"] for r in c.execute(
            "SELECT owner_id, COUNT(*) n FROM keys GROUP BY owner_id")}
        c.close()
        out = []
        for r in rows:
            d = dict(r)
            d["keys_count"] = counts.get(r["id"], 0)
            out.append(d)
        self.json_out(out)

    def api_user_create(self):
        self.require(admin=True)
        d = self.read_body()
        username = (d.get("username") or "").strip()
        password = d.get("password") or ""
        role = d.get("role", "user")
        if not re.match(r"^[a-zA-Z0-9_.@-]{3,32}$", username):
            raise ValueError("Некорректное имя пользователя")
        if len(password) < 6:
            raise ValueError("Пароль слишком короткий (мин. 6)")
        h, s = db.pw_hash(password)
        c = db.conn()
        try:
            c.execute("INSERT INTO users(username,pass_hash,salt,role,created_at) VALUES(?,?,?,?,?)",
                      (username, h, s, role, int(time.time())))
            c.commit()
        except db.sqlite3.IntegrityError:
            c.close()
            raise ValueError("Пользователь уже существует")
        uid = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        c.close()
        self.json_out({"id": uid, "username": username, "role": role}, 201)

    def api_user_update(self, uid):
        self.require(admin=True)
        d = self.read_body()
        c = db.conn()
        if "password" in d and d["password"]:
            if len(d["password"]) < 6:
                c.close()
                raise ValueError("Пароль слишком короткий")
            h, s = db.pw_hash(d["password"])
            c.execute("UPDATE users SET pass_hash=?, salt=? WHERE id=?", (h, s, int(uid)))
        if "role" in d:
            c.execute("UPDATE users SET role=? WHERE id=?", (d["role"], int(uid)))
        if "enabled" in d:
            c.execute("UPDATE users SET enabled=? WHERE id=?", (1 if d["enabled"] else 0, int(uid)))
        c.commit()
        c.close()
        self.json_out({"ok": True})

    def api_user_delete(self, uid):
        self.require(admin=True)
        me = self.current_user()
        if int(uid) == me["id"]:
            raise ValueError("Нельзя удалить себя")
        c = db.conn()
        c.execute("DELETE FROM users WHERE id=?", (int(uid),))
        c.execute("UPDATE keys SET owner_id=NULL WHERE owner_id=?", (int(uid),))
        c.commit()
        c.close()
        self.json_out({"ok": True})

    def api_my_password(self):
        u = self.require()
        d = self.read_body()
        cur = db.get_user_by_login(u["username"], d.get("old_password", ""))
        if not cur:
            raise ValueError("Текущий пароль неверен")
        if len(d.get("new_password", "")) < 6:
            raise ValueError("Новый пароль слишком короткий")
        h, s = db.pw_hash(d["new_password"])
        c = db.conn()
        c.execute("UPDATE users SET pass_hash=?, salt=? WHERE id=?", (h, s, u["id"]))
        c.commit()
        c.close()
        self.json_out({"ok": True})

    # ---------- settings / stats ----------

    def api_settings_get(self):
        self.require(admin=True)
        out = {}
        for k in SETTINGS_KEYS:
            out[k] = db.get_setting(k, "")
        self.json_out(out)

    def api_settings_put(self):
        self.require(admin=True)
        d = self.read_body()
        for k in SETTINGS_KEYS:
            if k in d:
                db.set_setting(k, d[k])
        for k in ("user_key_limit", "default_transport"):
            if k in d:
                db.set_setting(k, d[k])
        ok, err = wg.apply_config()
        self.json_out({"ok": True, "applied": ok, "apply_error": err if not ok else None})

    def api_stats(self):
        u = self.require()
        c = db.conn()
        if u["role"] == "admin":
            total = c.execute("SELECT COUNT(*) n FROM keys").fetchone()["n"]
            online = 0
            active = c.execute("SELECT COUNT(*) n FROM keys WHERE status='active'").fetchone()["n"]
            users = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
            traffic = c.execute("SELECT COALESCE(SUM(used_bytes),0) t FROM keys").fetchone()["t"]
        else:
            total = c.execute("SELECT COUNT(*) n FROM keys WHERE owner_id=?", (u["id"],)).fetchone()["n"]
            active = total
            users = 1
            traffic = c.execute(
                "SELECT COALESCE(SUM(used_bytes),0) t FROM keys WHERE owner_id=?",
                (u["id"],)).fetchone()["t"]
        c.close()
        st = wg.peer_status()
        if u["role"] == "admin":
            online = sum(1 for v in st.values() if v.get("last_seen") and
                         int(time.time()) - v["last_seen"] < 120)
        load = os.getloadavg()
        uptime = 0
        try:
            with open("/proc/uptime") as f:
                uptime = int(float(f.read().split()[0]))
        except Exception:
            pass
        self.json_out({
            "keys_total": total, "keys_active": active, "keys_online": online,
            "users": users, "traffic_bytes": traffic,
            "load": list(load), "uptime": uptime,
            "server_pubkey": wg.server_pubkey(),
            "endpoint": db.get_setting("endpoint_host", ""),
            "port": db.get_setting("port", "443"),
        })

    def api_reload(self):
        self.require(admin=True)
        ok, err = wg.apply_config()
        self.json_out({"ok": ok, "error": err if not ok else None})


def sanitize_user(u):
    return {"id": u["id"], "username": u["username"], "role": u["role"]}


R = lambda p: re.compile(p)
ROUTES = [
    (R(r"^/api/login$"), "POST", Handler.api_login),
    (R(r"^/api/logout$"), "POST", Handler.api_logout),
    (R(r"^/api/me$"), "GET", Handler.api_me),
    (R(r"^/api/stats$"), "GET", Handler.api_stats),
    (R(r"^/api/keys$"), "GET", Handler.api_keys_list),
    (R(r"^/api/keys$"), "POST", Handler.api_key_create),
    (R(r"^/api/keys/(\d+)/ini$"), "GET", Handler.api_key_ini),
    (R(r"^/api/keys/(\d+)/json$"), "GET", Handler.api_key_json),
    (R(r"^/api/keys/(\d+)/qr$"), "GET", Handler.api_key_qr),
    (R(r"^/api/keys/(\d+)/rotate$"), "POST", Handler.api_key_rotate),
    (R(r"^/api/keys/(\d+)$"), "GET", Handler.api_key_get),
    (R(r"^/api/keys/(\d+)$"), "PUT", Handler.api_key_update),
    (R(r"^/api/keys/(\d+)$"), "DELETE", Handler.api_key_delete),
    (R(r"^/api/users$"), "GET", Handler.api_users_list),
    (R(r"^/api/users$"), "POST", Handler.api_user_create),
    (R(r"^/api/users/(\d+)$"), "PUT", Handler.api_user_update),
    (R(r"^/api/users/(\d+)$"), "DELETE", Handler.api_user_delete),
    (R(r"^/api/password$"), "POST", Handler.api_my_password),
    (R(r"^/api/settings$"), "GET", Handler.api_settings_get),
    (R(r"^/api/settings$"), "PUT", Handler.api_settings_put),
    (R(r"^/api/reload$"), "POST", Handler.api_reload),
]


def background_loop():
    while True:
        try:
            wg.sync_stats()
        except Exception:
            pass
        time.sleep(30)


def main():
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("AmneziaWG panel listening on 127.0.0.1:%d" % PORT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
