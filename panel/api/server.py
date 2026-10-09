#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AmneziaWG 3.0 control panel — stdlib-only HTTP API + static web UI."""
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import socket
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


def _log(msg):
    line = "[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    sys.stderr.write(line)
    try:
        with open("/var/log/amnezia-panel.log", "a") as f:
            f.write(line)
    except OSError:
        pass


def _fatal(msg):
    """Print a loud diagnostic to stderr/journal and exit non-zero."""
    _log("[FATAL] %s" % msg)
    sys.exit(1)


try:
    db.init_db()
    db.sync_admin_login()
except Exception as e:
    # never crash at import: the HTTP server must come up so nginx doesn't
    # return 502; login will report the problem instead.
    _log("[warn] init_db/sync failed: %r" % (e,))


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

AUTO_NET_KEYS = ["endpoint_host", "port", "subnet", "server_ip",
                 "server_ipv6", "default_dns", "default_mtu"]


# ---------- automatic network detection (settings are auto-filled from the server) ----------

def _read_file(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def detect_public_ip():
    """Public IPv4 of this server (UDP-socket trick — no traffic leaves unless sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass


def detect_default_iface():
    out = _run_shell("ip route show default 2>/dev/null | awk '/default/{print $5; exit}'")
    return out.strip()


def detect_netmask(iface):
    """IPv4 netmask of an interface in CIDR bits (e.g. '24')."""
    if not iface:
        return "24"
    try:
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mask = struct.unpack(
            "!I", fcntl.ioctl(s.fileno(), 0x891b,
                              struct.pack("256s", iface[:15].encode()))[20:24])[0]
        s.close()
        bits = bin(mask).count("1")
        return str(bits if 0 < bits <= 32 else 24)
    except Exception:
        return "24"


def detect_ipv6_address(iface):
    """Global (non-link-local, non-loopback) IPv6 address of the server, or ''."""
    try:
        for line in _read_file("/proc/net/if_inet6").splitlines():
            p = line.split()
            if len(p) >= 6 and p[4] != "lo":
                raw = p[0]
                if raw == "0" * 32 or raw.startswith("fe80"):
                    continue  # skip ::1 and link-local addresses
                return socket.inet_ntop(socket.AF_INET6, bytes.fromhex(raw))
    except Exception:
        pass
    return ""


def detect_dns_servers():
    servers = []
    for line in _read_file("/etc/resolv.conf").splitlines():
        if line.strip().startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1]
                # skip local resolv stubs (127.0.x.x / ::1) — useless for clients
                if ip.startswith("127.") or ip == "::1":
                    continue
                servers.append(ip)
    if not servers:
        servers = ["1.1.1.1", "8.8.8.8"]
    return ", ".join(servers[:2])


def detect_mtu(iface):
    if not iface:
        return 1420
    try:
        mtu = int(_read_file("/sys/class/net/%s/mtu" % iface).strip() or 0)
    except ValueError:
        mtu = 0
    if mtu <= 0:
        return 1420
    return max(1280, min(mtu - 80, 1420))


def _run_shell(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""


def _v4_in_network(addr, cidr):
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


def _pick_tunnel_v4(detected_ip):
    """Keep a manually configured tunnel subnet if it is still set & valid."""
    cur_subnet = db.get_setting("subnet", "") or ""
    cur_srv = db.get_setting("server_ip", "") or ""
    if cur_subnet and cur_srv:
        try:
            net = ipaddress.ip_network(cur_subnet, strict=False)
            srv_ip = cur_srv.split("/")[0]
            if (net.version == 4 and str(net.network_address) != detected_ip
                    and _v4_in_network(srv_ip, str(net))):
                return cur_subnet, cur_srv
        except Exception:
            pass
    # pick a /24 that does not clash with any directly connected network
    used = []
    for line in _run_shell("ip -o -4 addr show scope global 2>/dev/null").splitlines():
        for tok in line.split():
            if "/" in tok:
                try:
                    used.append(ipaddress.ip_network(tok, strict=False))
                except Exception:
                    pass
    for n in range(66, 254):
        cand_net = ipaddress.ip_network("10.%d.%d.0/24" % (n, (n * 7) % 254))
        if not any(cand_net.overlaps(u) for u in used):
            return str(cand_net), "%s/24" % list(cand_net.hosts())[0]
    return "10.66.66.0/24", "10.66.66.1/24"


def detect_network_settings():
    """Auto-detect all network settings from the current server state."""
    pub = detect_public_ip()
    iface = detect_default_iface()
    subnet, server_ip = _pick_tunnel_v4(pub)
    v6_pub = detect_ipv6_address(iface)
    v6_cur = db.get_setting("server_ipv6", "") or ""
    if v6_pub:
        server_ipv6 = v6_pub
    elif v6_cur and ":" in v6_cur and not v6_cur.startswith("::1"):
        server_ipv6 = v6_cur
    else:
        server_ipv6 = ""
    port_raw = db.get_setting("port", "") or ""
    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        port = 443
    return {
        "iface": iface,
        "public_ip": pub,
        "netmask_bits": detect_netmask(iface),
        "endpoint_host": db.get_setting("endpoint_host", "") or pub,
        "port": str(port),
        "subnet": subnet,
        "server_ip": server_ip,
        "server_ipv6": server_ipv6,
        "default_dns": detect_dns_servers(),
        "default_mtu": str(detect_mtu(iface)),
    }


def apply_detected_network(persist=True):
    """Write auto-detected network values into settings (skips manual overrides)."""
    det = detect_network_settings()
    saved = {}
    for k in AUTO_NET_KEYS:
        if db.get_setting("auto_" + k, "1") != "0" and det.get(k):
            if persist:
                db.set_setting(k, det[k])
            saved[k] = det[k]
    return det, saved


def certbot_available():
    """Path to the certbot binary if it is installed on this system."""
    for p in ("/usr/bin/certbot", "/usr/local/bin/certbot"):
        if os.path.exists(p):
            return p
    return None


# ---------- startup self-healing ----------

def _derive_server_pubkey():
    """Ensure server private key + noise key exist and cache the public key.

    Runs at boot: without a valid 'server_pubkey' setting every API call that
    touches wg status (dashboard/keys) used to crash with NameError, which on
    systemd-restart loops looked like a dead panel -> nginx 502 Bad Gateway.
    """
    try:
        priv = wg.ensure_server_keys()
        pub = wg.pubkey(priv)
        db.set_setting("server_pubkey", pub)
    except Exception as e:
        sys.stderr.write("[warn] server_pubkey derivation failed: %s\n" % e)


def _ensure_noise_key():
    """Create /var/lib/amnezia-panel/noise.pem if missing (wg.conf references it)."""
    path = "/var/lib/amnezia-panel/noise.pem"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(wg.gen_psk() + "\n")
            os.chmod(path, 0o600)
    except Exception as e:
        sys.stderr.write("[warn] noise key init failed: %s\n" % e)


def _iface_conf_ok(path):
    """Validate a wg0.conf-style file: [Interface] + PrivateKey + ListenPort."""
    try:
        with open(path) as f:
            t = f.read()
        return ("[interface]" in t.lower() and "privatekey" in t.lower()
                and "listenport" in t.lower())
    except OSError:
        return False


def _ensure_wg_conf_file():
    """Make sure /etc/wireguard/wg0.conf exists and is valid.

    wg-quick@wg0.service reads exactly that path; if it was deleted by an
    uninstall run, replaced by a broken symlink or overwritten with garbage,
    the unit shows 'failed' in the maintenance page forever.
    """
    panel_conf = "/etc/amnezia-panel/wg.conf"
    if not _iface_conf_ok(panel_conf):
        try:
            ok, err = wg.apply_config()  # renders a full valid config there
            if not ok:
                _log("[warn] apply_config while fixing wg.conf: %s" % err)
        except Exception as e:
            _log("[warn] cannot render wg.conf: %r" % (e,))
    target = "/etc/wireguard/wg0.conf"
    try:
        os.makedirs("/etc/wireguard", exist_ok=True)
        need = True
        if os.path.islink(target) and os.path.realpath(target) == os.path.realpath(panel_conf):
            need = False
        elif os.path.isfile(target) and _iface_conf_ok(target):
            need = False
        if need:
            tmp = target + ".new"
            with open(panel_conf) as src, open(tmp, "w") as dst:
                dst.write(src.read())
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
            _log("recreated /etc/wireguard/wg0.conf from panel settings")
    except Exception as e:
        _log("[warn] cannot fix /etc/wireguard/wg0.conf: %r" % (e,))


def _systemd_set_iface(iface):
    """Point wg-quick@.service at our own config file via a drop-in override."""
    d = "/etc/systemd/system/wg-quick@.service.d"
    try:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "amnezia-panel.conf"), "w") as f:
            f.write("[Service]\nEnvironment=WG_QUICK_IFACE=%s\n" % iface)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=20)
    except Exception as e:
        _log("[warn] systemd drop-in for wg-quick failed: %r" % (e,))


def _bring_up_directly(conf):
    """Fallback: bring wg0 up with `ip` + `wg` when wg-quick is unavailable/fails."""
    try:
        subprocess.run(["ip", "link", "del", "wg0"], capture_output=True, timeout=10)
        priv = None
        addr = port = None
        with open(conf) as f:
            for line in f:
                parts = line.split("=", 1)
                if len(parts) != 2:
                    continue
                k, v = parts[0].strip().lower(), parts[1].strip()
                if k == "privatekey":
                    priv = v
                elif k == "address" and addr is None:
                    addr = v
                elif k == "listenport":
                    port = v
        if not priv or not addr:
            return False
        cmds = [
            ["ip", "link", "add", "wg0", "type", "wireguard",
             "private-key", priv, "listen-port", port or "443"],
            ["ip", "addr", "add", addr, "dev", "wg0"],
            ["ip", "link", "set", "wg0", "up"],
        ]
        for c in cmds:
            r = subprocess.run(c, capture_output=True, timeout=15)
            if r.returncode != 0:
                return False
        # add active peers straight from the rendered config
        section = None
        peer = {}
        with open(conf) as f:
            lines = f.read().splitlines() + [""]
        for line in lines:
            s = line.strip()
            if s.startswith("["):
                if section == "peer" and peer.get("publickey"):
                    args = ["wg", "set", "wg0", "peer", peer["publickey"],
                            "allowed-ips", peer.get("allowedips", "0.0.0.0/0")]
                    if peer.get("presharedkeyfile"):
                        args += ["preshared-key", peer["presharedkeyfile"]]
                    subprocess.run(args, capture_output=True, timeout=15)
                section = "interface" if "interface" in s.lower() else \
                          ("peer" if "peer" in s.lower() else None)
                peer = {}
            elif "=" in s and section == "peer":
                k, v = [x.strip() for x in s.split("=", 1)]
                peer[k.lower()] = v
        r = subprocess.run(["wg", "show"], capture_output=True, text=True, timeout=10)
        return "wg0" in (r.stdout or "")
    except Exception as e:
        _log("[warn] direct wg0 bring-up failed: %r" % (e,))
        return False


def _ensure_wg_interface_up():
    """Bring wg0 up if it is down (idempotent; safe to call on every start)."""
    try:
        r = subprocess.run(["ip", "-o", "link", "show", "wg0"],
                           capture_output=True, text=True, timeout=10)
        state = (r.stdout or "")
        if r.returncode == 0 and "state UP" in state:
            return True
    except Exception:
        pass
    _ensure_wg_conf_file()
    _systemd_set_iface("wg0")
    conf = "/etc/wireguard/wg0.conf"
    try:
        subprocess.run(["wg-quick", "down", "wg0"], capture_output=True, timeout=30)
        r = subprocess.run(["wg-quick", "up", "wg0"], capture_output=True,
                           text=True, timeout=30)
        ok = r.returncode == 0
        if not ok:
            _log("[warn] wg-quick up failed: %s — trying direct ip/wg bring-up"
                 % ((r.stderr or r.stdout or "").strip()[:200]))
            ok = _bring_up_directly(conf)
        if ok:
            subprocess.run(["systemctl", "reset-failed", "wg-quick@wg0.service"],
                           capture_output=True, timeout=15)
            subprocess.run(["systemctl", "restart", "wg-quick@wg0.service"],
                           capture_output=True, timeout=30)
        chk = subprocess.run(["ip", "-o", "link", "show", "wg0"],
                             capture_output=True, text=True, timeout=10)
        return "state UP" in (chk.stdout or "")
    except Exception as e:
        _log("[warn] ensure wg0 up failed: %r" % (e,))
        return False


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

    def do_HEAD(self):
        # nginx probes / curl -I compatibility: serve headers only
        self.dispatch("GET", head=True)

    def dispatch(self, method, head=False):
        path = urlparse(self.path).path
        try:
            for regex, mth, fn in ROUTES:
                if mth != method:
                    continue
                mo = regex.match(path)
                if mo:
                    return fn(self, *(mo.groups()))
            if method == "GET":
                return self.serve_static(path, head=head)
            self.json_out({"error": "not found"}, 404)
        except PermissionError as e:
            self.json_out({"error": str(e)}, 403)
        except ValueError as e:
            self.json_out({"error": str(e)}, 400)
        except Exception as e:
            self.json_out({"error": "internal: %s" % e}, 500)

    def serve_static(self, path, head=False):
        if path == "/":
            path = "/index.html"
        full = os.path.normpath(os.path.join(WEB_ROOT, path.lstrip("/")))
        if not full.startswith(WEB_ROOT) or not os.path.isfile(full):
            # unknown API paths -> JSON 404 instead of the SPA shell
            if path.startswith("/api/"):
                return self.json_out({"error": "not found"}, 404)
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
        try:
            u = db.get_user_by_login(d.get("username", "").strip(), d.get("password", ""))
        except Exception as e:
            _log("[error] login: DB failure: %r" % (e,))
            return self.json_out({
                "error": "Ошибка базы данных панели: %s. Выполните на сервере: "
                         "journalctl -u amnezia-panel -n 50" % e}, 500)
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
        if u["role"] == "admin":
            # keep admin.json in sync so installer re-runs don't restore the old password
            try:
                with open(db.ADMIN_CRED_PATH, "w") as f:
                    json.dump({"username": u["username"], "password": d["new_password"]}, f)
                os.chmod(db.ADMIN_CRED_PATH, 0o600)
            except OSError:
                pass
        self.json_out({"ok": True})

    # ---------- settings / stats ----------

    def api_settings_get(self):
        self.require(admin=True)
        out = {}
        for k in SETTINGS_KEYS:
            out[k] = db.get_setting(k, "")
        for k in AUTO_NET_KEYS:
            out["auto_" + k] = "0" if db.get_setting("auto_" + k, "1") == "0" else "1"
        try:
            out["detected"] = detect_network_settings()
        except Exception as e:
            out["detected"] = {"error": str(e)}
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
        for k in AUTO_NET_KEYS:
            flag = "auto_" + k
            if flag in d:
                db.set_setting(flag, "0" if str(d[flag]) in ("0", "false", "off") else "1")
        ok, err = wg.apply_config()
        self.json_out({"ok": True, "applied": ok, "apply_error": err if not ok else None})

    def api_net_detect(self):
        """Preview what auto-detection would set (no writes)."""
        self.require(admin=True)
        try:
            det = detect_network_settings()
        except Exception as e:
            raise ValueError("Ошибка автообнаружения сети: %s" % e)
        cur = {k: db.get_setting(k, "") for k in AUTO_NET_KEYS}
        changed = {k: v for k, v in det.items()
                   if k in AUTO_NET_KEYS and cur.get(k) != v}
        self.json_out({"detected": det, "current": cur, "changed": changed})

    def api_net_apply(self):
        """Re-detect network settings from the server and persist them."""
        self.require(admin=True)
        det, saved = apply_detected_network(persist=True)
        try:
            ok, err = wg.apply_config()
        except Exception as e:
            ok, err = False, repr(e)
        self.json_out({"ok": True, "detected": det, "applied_keys": sorted(saved),
                       "wg_applied": ok, "apply_error": (str(err)[:300]) if not ok else None})

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

    # ---------- maintenance / uninstall (admin) ----------

    PANEL_PATHS = [
        "/opt/amnezia-panel",
        "/etc/amnezia-panel",
        "/var/lib/amnezia-panel",
        "/var/log/amnezia-install.log",
        "/etc/systemd/system/amnezia-panel.service",
        "/etc/systemd/system/awg-stats.service",
        "/etc/systemd/system/awg-stats.timer",
        "/etc/nginx/sites-available/amnezia-panel",
        "/etc/nginx/sites-enabled/amnezia-panel",
        "/etc/wireguard/wg0.conf",
        "/etc/sysctl.d/60-amnezia-panel.conf",
    ]

    def _run(self, cmd, timeout=30):
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
            return (p.stdout + p.stderr).strip()
        except Exception as e:
            return "error: %s" % e

    def _service_exists(self, name):
        return os.path.exists("/etc/systemd/system/%s" % name)

    def api_maintenance_status(self):
        self.require(admin=True)
        domain = db.get_setting("endpoint_host", "")
        cert_ok = bool(domain) and os.path.isfile(
            "/etc/letsencrypt/live/%s/fullchain.pem" % domain)
        out = []
        for p in self.PANEL_PATHS:
            if os.path.isdir(p):
                out.append({"path": p, "type": "dir", "exists": True})
            elif os.path.islink(p):
                out.append({"path": p, "type": "symlink", "exists": True})
            elif os.path.exists(p):
                out.append({"path": p, "type": "file", "exists": True})
            else:
                out.append({"path": p, "type": "none", "exists": False})
        services = {}
        for svc in ("amnezia-panel.service", "awg-stats.service",
                    "awg-stats.timer", "wg-quick@wg0.service"):
            services[svc] = self._run(
                "systemctl is-active %s 2>/dev/null" % svc, 10) or "unknown"
        self.json_out({
            "paths": out,
            "services": services,
            "certbot": certbot_available(),
            "letsencrypt_cert": cert_ok,
            "domain": domain,
            "db_path": db.DB_PATH,
            "db_size_bytes": (os.path.getsize(db.DB_PATH)
                              if os.path.exists(db.DB_PATH) else 0),
            "panel_log_tail": self._log_tail("/var/log/amnezia-panel.log", 30),
        })

    @staticmethod
    def _log_tail(path, n):
        try:
            with open(path, "r", errors="replace") as f:
                return "".join(f.readlines()[-n:])
        except OSError:
            return ""

    def api_uninstall_preview(self):
        self.require(admin=True)
        self.json_out({"remove": self.PANEL_PATHS,
                       "keep": ["/etc/letsencrypt (сертификаты)",
                                "wg-quick (интерфейс wg0 — будет остановлен)",
                                "Nginx / fail2ban (системные пакеты)"]})

    def api_uninstall_run(self):
        u = self.require(admin=True)
        d = self.read_body()
        if str(d.get("confirm", "")) != "DELETE-PANEL":
            raise ValueError("Введите DELETE-PANEL для подтверждения удаления")
        if int(d.get("user_id", -1)) != int(u["id"]):
            raise PermissionError("Только текущий администратор может удалить панель")
        # response first — the service will be stopped right after
        self.json_out({"ok": True, "message":
                       "Файлы панели удаляются. Сервис будет остановлен."})

        script = r"""#!/bin/bash
set +e
LOG=/tmp/amnezia-uninstall.log
exec >>"$LOG" 2>&1
echo "=== AmneziaWG panel uninstall $(date) ==="
# stop & disable panel services (this script itself runs under amnezia-panel.service)
systemctl stop awg-stats.timer awg-stats.service 2>/dev/null
systemctl disable --now amnezia-panel 2>/dev/null
# drop the VPN interface but keep wireguard-tools installed
wg-quick down wg0 2>/dev/null
ip link set wg0 down 2>/dev/null; ip link del wg0 2>/dev/null
# remove panel files
rm -rf /opt/amnezia-panel /etc/amnezia-panel /var/lib/amnezia-panel
rm -f /var/log/amnezia-install.log \
      /etc/systemd/system/amnezia-panel.service \
      /etc/systemd/system/awg-stats.service \
      /etc/systemd/system/awg-stats.timer \
      /etc/nginx/sites-available/amnezia-panel \
      /etc/nginx/sites-enabled/amnezia-panel \
      /etc/wireguard/wg0.conf \
      /etc/sysctl.d/60-amnezia-panel.conf
# revoke Let's Encrypt certificate for the panel domain (if any)
DOM=$(grep -h '^server_name' /etc/nginx/conf.d/*.conf /etc/nginx/sites-available/* 2>/dev/null | awk '/[^ ]/{print $2; exit}')
if command -v certbot >/dev/null 2>&1; then
  for c in $(certbot certificates 2>/dev/null | awk '/Certificate Name:/{print $3}'); do
    certbot delete --non-interactive --cert-name "$c" >/dev/null 2>&1
  done
fi
systemctl daemon-reload
systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null
# clean up our crontab entry if present
crontab -l 2>/dev/null | grep -v 'certbot renew --quiet --deploy-hook' | crontab - 2>/dev/null
sync
sleep 2
rm -f /usr/local/sbin/amnezia-panel-uninstall.sh
echo "uninstall finished"
"""
        path = "/usr/local/sbin/amnezia-panel-uninstall.sh"
        try:
            with open(path, "w") as f:
                f.write(script)
            os.chmod(path, 0o755)
        except OSError as e:
            return self.json_out({"ok": False, "error": str(e)}, 500)
        subprocess.Popen(["setsid", "bash", path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)


def sanitize_user(u):
    return {"id": u["id"], "username": u["username"], "role": u["role"]}


R = lambda p: re.compile(p)


def api_ping(self):
    # lightweight health report: helps diagnose 502 / half-installed states
    pub = db.get_setting("server_pubkey") or ""
    wg_up = False
    try:
        r = subprocess.run(["wg", "show"], capture_output=True, text=True, timeout=5)
        wg_up = "wg0" in (r.stdout or "")
    except Exception:
        pass
    index_ok = os.path.isfile(os.path.join(WEB_ROOT, "index.html"))
    self._send(200, json.dumps({
        "ok": True, "app": "amnezia-panel",
        "wg0": wg_up,
        "pubkey_ready": bool(pub),
        "web_root": WEB_ROOT,
        "web_files_ok": index_ok,
    }).encode())


ROUTES = [
    (R(r"^/api/ping$"), "GET", api_ping),
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
    (R(r"^/api/network/detect$"), "GET", Handler.api_net_detect),
    (R(r"^/api/network/apply$"), "POST", Handler.api_net_apply),
    (R(r"^/api/reload$"), "POST", Handler.api_reload),
    (R(r"^/api/maintenance$"), "GET", Handler.api_maintenance_status),
    (R(r"^/api/uninstall/preview$"), "GET", Handler.api_uninstall_preview),
    (R(r"^/api/uninstall$"), "POST", Handler.api_uninstall_run),
]


def background_loop():
    while True:
        try:
            wg.sync_stats()
        except Exception:
            pass
        time.sleep(30)


def main():
    # fail loudly (journal + /var/log/amnezia-panel.log) if the install is broken
    if not os.path.isfile(os.path.join(WEB_ROOT, "index.html")):
        _fatal("web UI missing: %s/index.html not found — панель не была установлена "
               "полностью. Перезапустите установку: bash install.sh" % WEB_ROOT)
    try:
        socket.getaddrinfo("127.0.0.1", PORT)
    except Exception as e:
        _fatal("bad AWG_PORT %r: %s" % (PORT, e))

    # self-heal critical state before serving (pubkey cache, noise key, wg0)
    _ensure_noise_key()
    _derive_server_pubkey()
    # auto-configure network settings from the actual server state
    try:
        det, saved = apply_detected_network(persist=True)
        if saved:
            _log("network settings auto-configured: %s" % ", ".join(sorted(saved)))
    except Exception as e:
        _log("[warn] network auto-detect failed: %r" % (e,))
    threading.Thread(target=_ensure_wg_interface_up, daemon=True).start()

    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as e:
        _fatal("cannot bind 127.0.0.1:%d (%s) — возможно порт занят другим процессом; "
               "проверьте: ss -ltnp | grep %d" % (PORT, e, PORT))
    print("AmneziaWG panel listening on 127.0.0.1:%d" % PORT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
