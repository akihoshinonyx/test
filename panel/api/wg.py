# -*- coding: utf-8 -*-
"""AmneziaWG key management: wg tooling, INI & native config generation."""
import base64
import ipaddress
import os
import re
import secrets
import subprocess
import time

from db import conn, get_setting

CONF = "/etc/amnezia-panel/wg.conf"


def gen_privkey():
    return base64.b64encode(secrets.token_bytes(32)).decode()


def pubkey(priv):
    out = subprocess.run(
        ["wg", "pubkey", "/dev/stdin"],
        input=priv.encode(), capture_output=True, check=True,
    )
    return out.stdout.decode().strip()


def gen_psk():
    return base64.b64encode(secrets.token_bytes(32)).decode()


def server_pubkey():
    """Server public key (derived from stored private key, cached in settings)."""
    k = get_setting("server_pubkey")
    if k:
        return k
    try:
        priv = ensure_server_keys()
        pub = pubkey(priv)
        set_setting("server_pubkey", pub)
        return pub
    except Exception:
        return ""


def next_ip(c):
    used = {r["ip4"] for r in c.execute("SELECT ip4 FROM keys WHERE ip4 IS NOT NULL")}
    net = ipaddress.ip_network(get_setting("subnet", "10.66.66.0/24"))
    hostnet = ipaddress.ip_network(str(net), strict=False)
    for i, h in enumerate(hostnet.hosts()):
        s = str(h)
        if i < 5:
            continue  # first addresses reserved
        if s not in used:
            return s
    raise RuntimeError("Subnet exhausted")


def ensure_server_keys():
    path = "/etc/amnezia-panel/server_private.key"
    if not os.path.exists(path):
        priv = gen_privkey()
        os.makedirs("/etc/amnezia-panel", exist_ok=True)
        with open(path, "w") as f:
            f.write(priv + "\n")
        os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()


# ---------- wg.conf rendering & apply ----------

def interface_block(srv_priv):
    out = [
        "[Interface]",
        "PrivateKey = %s" % srv_priv,
        "Address = %s" % get_setting("server_ip", "10.66.66.1/24"),
        "ListenPort = %s" % get_setting("port", "443"),
    ]
    v6 = get_setting("server_ipv6")
    if v6:
        out.insert(3, "Address = %s" % v6)
    if int(get_setting("pfs", "1")):
        out.append("PresharedKeyFile = /var/lib/amnezia-panel/noise.pem")
    if int(get_setting("amnezia_enabled", "1")):
        out += [
            "Jc = %s" % get_setting("jc", "3"),
            "Jmin = %s" % get_setting("jmin", "50"),
            "Jmax = %s" % get_setting("jmax", "90"),
            "S1 = %s" % get_setting("s1", "857"),
            "S2 = %s" % get_setting("s2", "1271"),
            "H1 = %s" % get_setting("h1", ""),
            "H2 = %s" % get_setting("h2", ""),
            "H3 = %s" % get_setting("h3", ""),
            "H4 = %s" % get_setting("h4", ""),
            "St = %s" % get_setting("st", "0"),
        ]
    return out


def render_conf():
    c = conn()
    srv_priv = ensure_server_keys()
    out = interface_block(srv_priv)
    now = int(time.time())
    for r in c.execute("SELECT * FROM keys ORDER BY id"):
        if r["expires_at"] and r["expires_at"] < now:
            continue
        if r["status"] != "active":
            continue
        psk_path = "/var/lib/amnezia-panel/psk_%d.pem" % r["id"]
        try:
            with open(psk_path, "w") as f:
                f.write(r["preshared_key"] + "\n")
            os.chmod(psk_path, 0o600)
        except OSError:
            pass
        out += [
            "",
            "[Peer]",
            "# name: %s" % r["name"],
            "PublicKey = %s" % r["public_key"],
            "PresharedKeyFile = %s" % psk_path,
            "AllowedIPs = %s" % (r["allowed_ips"] or "0.0.0.0/0, ::/0"),
        ]
    c.close()
    return "\n".join(out) + "\n"


def apply_config():
    conf = render_conf()
    with open(CONF, "w") as f:
        f.write(conf)
    os.chmod(CONF, 0o600)
    subprocess.run(["wg-quick", "down", "wg0"], capture_output=True)
    r = subprocess.run(["wg-quick", "up", "wg0"], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout)


def peer_status():
    """Return {public_key: {'last_seen': ts, 'endpoint': str, 'rx': int, 'tx': int}}"""
    res = {}
    try:
        out = subprocess.run(["wg", "show", "wg0", "latest-handshakes"],
                             capture_output=True, text=True).stdout
        for line in out.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                res[parts[0]] = {"last_seen": int(float(parts[1]))}
        dump = subprocess.run(["wg", "show", "wg0", "dump"],
                              capture_output=True, text=True).stdout
        for line in dump.strip().splitlines():
            cols = line.split("\t")
            if len(cols) >= 5 and cols[0] in res:
                res[cols[0]].update({"rx": int(cols[2]), "tx": int(cols[3]),
                                     "endpoint": cols[4]})
    except Exception:
        pass
    return res


def sync_stats():
    """Periodic: update last_seen & used_bytes, expire keys."""
    st = peer_status()
    c = conn()
    now = int(time.time())
    for r in c.execute("SELECT id, public_key, used_bytes FROM keys"):
        info = st.get(r["public_key"])
        if info:
            c.execute(
                "UPDATE keys SET last_seen=?, used_bytes=? WHERE id=?",
                (info.get("last_seen") or None, info.get("rx", r["used_bytes"]), r["id"]),
            )
    c.execute("UPDATE keys SET status='expired' WHERE expires_at IS NOT NULL AND expires_at<?", (now,))
    c.commit()
    c.close()


# ---------- client config generation ----------

def endpoint_for_key(r):
    host = r["endpoint_ip"] or get_setting("endpoint_host", "")
    port = r["endpoint_port"] or int(get_setting("port", "443"))
    return host, port


def gen_counter():
    c = conn()
    n = c.execute("SELECT COALESCE(MAX(counter),0)+1 n FROM keys").fetchone()["n"]
    c.close()
    return n


def key_ini(r, amnezia=True):
    """WireGuard INI for the client."""
    host, port = endpoint_for_key(r)
    lines = [
        "[Interface]",
        "PrivateKey = %s" % r["private_key"],
        "Address = %s/32%s" % (r["ip4"], (",%s/128" % r["ip6"]) if r["ip6"] else ""),
        "DNS = %s" % r["dns"],
    ]
    if int(r["mtu"] or 1420):
        lines.append("MTU = %s" % r["mtu"])
    if amnezia and int(r["enable_amnezia"] or 0):
        lines += [
            "Jc = %s" % r["junk_count"],
            "Jmin = %s" % r["junk_min_size"],
            "Jmax = %s" % r["junk_max_size"],
            "S1 = %s" % r["init_packet_junk_size"],
            "S2 = %s" % r["response_packet_junk_size"],
            "H1 = ", "H2 = ", "H3 = ", "H4 = ",
            "St = 0",
        ]
    lines += [
        "",
        "[Peer]",
        "PublicKey = %s" % server_pubkey(),
        "PresharedKey = %s" % r["preshared_key"],
        "Endpoint = %s:%s" % (host, port),
        "AllowedIPs = %s" % (r["allowed_ips"] or "0.0.0.0/0, ::/0"),
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


def key_native_json(r):
    """AmneziaWG / AmneziaVPN native connection-settings JSON."""
    host, port = endpoint_for_key(r)
    transport = r["transport"] or "wg-amnezia"
    proto = {
        "wg": "AmneziaWG",
        "wg-amnezia": "AmneziaWG",
        "shadowsocks": "ShadowsocksWg",
    }.get(transport, "AmneziaWG")
    d = {
        "aps": ["0.0.0.0/0, ::/0"],
        "cf": [1, 2],
        "dns": r["dns"],
        "hk": [],
        "ht": [],
        "hw": [],
        "jc": str(r["junk_count"]),
        "jk": [],
        "jm": str(r["junk_min_size"]),
        "jx": str(r["junk_max_size"]),
        "kt": 25,
        "mtu": str(r["mtu"]),
        "pk": r["public_key"],
        "pp": str(port),
        "psk": r["preshared_key"],
        "protocol": proto,
        "proxy_url": "",
        "pt": "udp",
        "pubkey": server_pubkey(),
        "s1": str(r["init_packet_junk_size"]),
        "s2": str(r["response_packet_junk_size"]),
        "api_endpoint": "https://%s:443" % host if host else "",
        "hostname": host,
        "username": "",
        "password": "",
        "client_private_key": r["private_key"],
        "client_public_key": r["public_key"],
        "server_public_key": server_pubkey(),
        "preshared_key": r["preshared_key"],
        "container_name": "amnezia-awg",
        "isThirdPartyServer": True,
        "replaceAllowedIps": False,
        "time_added": int(time.time()),
        "backup_added": 0,
        "country_code": "",
        "isDefaultContainer": True,
        "name_container": "AwgContainer2",
        "name_service": "AmneziaVpnService",
        "last_connected": None,
        "disconnectedNotification": False,
        "installPostHookScript": "",
        "uninstallPreHookScript": "",
        "postDownScript": "",
        "prepareForConnectScript": "",
        "connectScript": "",
        "disconnectScript": "",
        "connectedNotification": False,
        "timeout": "30",
        "autoStartOnBoot": False,
        "subscriptions": {},
        "bucket": "",
        "region": "",
        "description": "",
        "syncKey": "",
        "remoteSyncId": "",
        "localRemoteSyncId": "",
        "reverseMigrationProcessStarted": False,
        "dpd": 0,
        "ignore_ifaces": "",
        "mssfix": 0,
        "persistent_keepalive": 25,
    }
    if transport == "shadowsocks":
        d.update({
            "protocol": "ShadowsocksWg",
            "ss_password": r["ss_password"] or "",
            "ss_cipher": r["ss_cipher"] or "aes-256-gcm",
            "ss_port": str(r["ss_port"] or port),
            "transport_proto": "tcp",
        })
    import json as _json
    return _json.dumps(d, indent=4)


def qr_png_bytes(text):
    import io
    try:
        import qrcode
        img = qrcode.make(text)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        return b""
