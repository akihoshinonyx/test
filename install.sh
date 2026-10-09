#!/usr/bin/env bash
# =====================================================================
#  AmneziaWG 3.0 + Web Control Panel — one-click installer for Ubuntu 20.04+
#
#  Usage:
#    sudo bash install.sh                    # interactive
#    DOMAIN=vpn.example.com ADMIN_PASS=xxx sudo -E bash install.sh   # non-interactive
#
#  What it does:
#    1. Asks for panel domain (A record must point to this server)
#    2. Installs AmneziaWG kernel module + wg tools (v3.0)
#    3. Sets up NAT/forwarding, fail2ban (UFW is NOT touched — stays as-is)
#    4. Installs the web panel (Python, systemd) + Nginx
#    5. Issues a Let's Encrypt certificate for the domain automatically
#    6. Prints admin credentials and client connection info
# =====================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo bash install.sh"; exit 1; fi

export DEBIAN_FRONTEND=noninteractive
LOG=/var/log/amnezia-install.log
exec > >(tee -a "$LOG") 2> >(tee -a "$LOG" >&2)

C_G='\033[0;32m'; C_Y='\033[1;33m'; C_R='\033[0;31m'; C_B='\033[1;34m'; C_0='\033[0m'
say()  { echo -e "${C_G}==>${C_0} $*"; }
warn() { echo -e "${C_Y}!! ${C_0}$*"; }
die()  { echo -e "${C_R}XX $*${C_0}"; exit 1; }

echo -e "${C_B}"
cat << 'ASCII'
    _                        _        __        _____  _
   / \   _ __ ___   ___   __| | ___   \ \      / /__ \| |
  / _ \ | '_ ` _ \ / _ \ / _` |/ _ \   \ \ /\ / /   / / | |
 / ___ \| | | | | | (_) | (_| |  __/    \ V  V /  _|_/|_|
/_/   \_\_| |_| |_|\___/ \__,_|\___|     \_/\_/ |___/
   AmneziaWG 3.0  +  Web Control Panel installer
ASCII
echo -e "${C_0}"

[[ "$(lsb_release -si 2>/dev/null || echo Unknown)" =~ Ubuntu|Debian ]] || die "This installer supports Ubuntu/Debian only."
UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo 22.04)

# ---------------------------------------------------------------- 1. questions
if [[ -z "${DOMAIN:-}" ]]; then
  echo
  read -rp "$(echo -e "${C_B}Домен панели (A-запись должна указывать на этот сервер), напр. vpn.example.com: ${C_0}")" DOMAIN
fi
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ && "$DOMAIN" == *.* ]] || die "Некорректный домен: '$DOMAIN'"

PUB_IP=$(curl -fsS4 --max-time 10 https://ifconfig.me || curl -fsS4 --max-time 10 https://api.ipify.org || true)
[[ -n "$PUB_IP" ]] || die "Не удалось определить публичный IP сервера."
RESOLVED=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)
[[ -n "$RESOLVED" ]] || RESOLVED=$(dig +short A "$DOMAIN" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)
if [[ -n "$RESOLVED" && "$RESOLVED" != "$PUB_IP" ]]; then
  warn "Домен $DOMAIN резолвится на $RESOLVED, а сервер — $PUB_IP."
  warn "Let's Encrypt не выдаст сертификат, пока DNS не настроен. Продолжить? [y/N]"
  read -r ANS; [[ "$ANS" == y || "$ANS" == Y ]] || die "Настройте A-запись $DOMAIN -> $PUB_IP и повторите."
fi

# ---------------------------------------------------------------- preflight checks
# Проверки ДО каких-либо изменений системы: если что-то не так — выходим сразу,
# не оставив «полуюстановку» (юниты/файлы есть, панель не работает).
say "Предпроверка окружения..."
[[ -f /proc/net/ip_tables_names || -e /sys/module/nf_nat ]] \
  || warn "Модули iptables/nat недоступны — VPN-маршрутизация может не работать."
for _bin in systemctl nginx curl openssl python3 wg apt-get; do
  command -v "$_bin" >/dev/null 2>&1 || { say "Устанавливаю недостающий компонент: $_bin"; break; }
done
apt-get update -qq >>"$LOG" 2>&1 || true
apt-get install -y -qq wireguard-tools qrencode nginx python3 openssl haveged \
  dnsutils ca-certificates gnupg curl >>"$LOG" 2>&1 \
  || apt-get install -y wireguard-tools qrencode nginx python3 openssl >>"$LOG" 2>&1 \
  || die "Не удалось установить базовые пакеты (nginx, wireguard-tools, python3)."
command -v wg >/dev/null 2>&1 || die "Утилита 'wg' не установлена — установите wireguard-tools вручную."
command -v nginx >/dev/null 2>&1 || die "nginx не установлен."
mkdir -p /etc/amnezia-panel /var/lib/amnezia-panel /opt/amnezia-panel /var/log
touch /var/log/amnezia-panel.log

read -rp "$(echo -e "${C_B}Порт WireGuard/AmneziaWG (по умолчанию 443): ${C_0}")" WG_PORT
WG_PORT=${WG_PORT:-443}
ADMIN_USER=${ADMIN_USER:-admin}
if [[ -z "${ADMIN_PASS:-}" && -f /etc/amnezia-panel/admin.json ]]; then
  # re-install: keep previously generated credentials and WG keys
  ADMIN_USER=$(python3 -c "import json;print(json.load(open('/etc/amnezia-panel/admin.json'))['username'])" 2>/dev/null || echo admin)
  ADMIN_PASS=$(python3 -c "import json;print(json.load(open('/etc/amnezia-panel/admin.json'))['password'])" 2>/dev/null || true)
  [[ -n "$ADMIN_PASS" ]] && warn "Повторная установка — сохранены прежние логин/пароль администратора ($ADMIN_USER)."
fi
if [[ -z "${ADMIN_PASS:-}" ]]; then
  ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 14)
  warn "Сгенерирован пароль администратора: ${C_Y}$ADMIN_PASS${C_0} (сохраните его!)"
fi

say "Домен: $DOMAIN | IP: $PUB_IP | WG-порт: $WG_PORT | Админ: $ADMIN_USER"

# ---------------------------------------------------------------- 2. base packages
say "Обновление списков пакетов и установка зависимостей..."
apt-get update -qq || warn "apt update завершился с предупреждениями (некоторые репозитории недоступны) — продолжаем."
apt-get install -y -qq apt-transport-https ca-certificates curl gnupg \
  wireguard-tools qrencode nginx python3 python3-pip openssl haveged unattended-upgrades \
  dnsutils >/dev/null 2>&1 || apt-get install -y wireguard-tools qrencode nginx python3 openssl

# ---------------------------------------------------------------- 3. AmneziaWG repo & kernel module
say "Подключение репозитория AmneziaWG и установка модуля ядра..."
AWG_CODENAME=$(grep -s Poison= /etc/os-release >/dev/null 2>&1; . /etc/os-release; echo "${VERSION_CODENAME:-focal}")
case "$AWG_CODENAME" in focal|jammy|noble|bookworm|bullseye) REPO="$AWG_CODENAME";; *) REPO="jammy";; esac
curl -fsSL "https://amnezia.info/apt.key" | gpg --dearmor -o /usr/share/keyrings/amnezia.gpg 2>/dev/null || true
echo "deb [signed-by=/usr/share/keyrings/amnezia.gpg] https://repo.amnezia.org/deb ${REPO} main" \
  > /etc/apt/sources.list.d/amnezia.list
if ! apt-get update -qq 2>/dev/null; then
  warn "Репозиторий Amnezia недоступен для '$REPO', ставим стандартный wireguard."
  echo "deb http://deb.debian.org/debian ${REPO} main" > /etc/apt/sources.list.d/amnezia.list 2>/dev/null || true
  apt-get update -qq || true
fi
apt-get install -y amnezia-wg 2>/dev/null || apt-get install -y wireguard-dkms wireguard-tools 2>/dev/null \
  || warn "Модуль AmneziaWG через apt не установлен — используется встроенный в ядро wireguard."
if ! curl -fsS --max-time 8 -o /dev/null https://repo.amnezia.org/deb/dists/${REPO}/InRelease 2>/dev/null; then
  rm -f /etc/apt/sources.list.d/amnezia.list
  warn "Репозиторий repo.amnezia.org недоступен с этого сервера — отключён из apt (VPN работает на модуле ядра wireguard)."
fi

# make sure the module loads
modprobe wireguard 2>/dev/null || modprobe amneziawg 2>/dev/null || true
grep -qs wireguard /proc/modules || echo "wireguard" > /etc/modules-load.d/wireguard.conf

# ---------------------------------------------------------------- 4. sysctl / forwarding
say "Включаем IP-форвардинг и NAT (masquerade)..."
cat > /etc/sysctl.d/60-amnezia-panel.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/60-amnezia-panel.conf

# ---------------------------------------------------------------- 5. panel files
say "Установка файлов панели в /opt/amnezia-panel..."
rm -rf /opt/amnezia-panel
mkdir -p /opt/amnezia-panel /var/lib/amnezia-panel /etc/amnezia-panel
[[ -f /etc/amnezia-panel/server_private.key ]] && cp -n /etc/amnezia-panel/server_private.key /tmp/.awg_keep_priv 2>/dev/null || true
[[ -f /var/lib/amnezia-panel/noise.pem ]] && cp -n /var/lib/amnezia-panel/noise.pem /tmp/.awg_keep_noise 2>/dev/null || true
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Locate panel sources: local repo layout (./panel) or fetch from GitHub if install.sh run standalone
fetch_src() {
  local dest="$1" url="$2"
  curl -fsSL --max-time 30 "$url" -o "$dest"     || curl -fsSL --max-time 30 "${url/raw.githubusercontent.com/fastly.jsdelivr.net/gh}" -o "$dest"     || die "Не удалось скачать $url"
}
if [[ -d "$SCRIPT_DIR/panel/api" && -d "$SCRIPT_DIR/panel/web" ]]; then
  SRC="$SCRIPT_DIR/panel"
elif [[ -d "$SCRIPT_DIR/api" && -d "$SCRIPT_DIR/web" ]]; then
  SRC="$SCRIPT_DIR"
else
  say "Файлы панели не найдены рядом со скриптом — скачиваю с GitHub..."
  mkdir -p /tmp/amnezia-panel-src/api /tmp/amnezia-panel-src/web /tmp/amnezia-panel-src/scripts
  BASE="https://raw.githubusercontent.com/akihoshinonyx/test/main"
  for f in server.py db.py wg.py; do fetch_src "/tmp/amnezia-panel-src/api/$f" "$BASE/panel/api/$f"; done
  for f in index.html app.js style.css; do fetch_src "/tmp/amnezia-panel-src/web/$f" "$BASE/panel/web/$f"; done
  for f in nginx.conf.template amnezia-panel.service awg-stats.service awg-stats.timer; do
    curl -fsSL --max-time 30 "$BASE/panel/scripts/$f" -o "/tmp/amnezia-panel-src/scripts/$f" || true
  done
  SRC="/tmp/amnezia-panel-src"
fi
cp -r "$SRC/api" "$SRC/web" /opt/amnezia-panel/
[[ -d "$SRC/scripts" ]] && cp -r "$SRC/scripts" /opt/amnezia-panel/ || true
rm -rf /tmp/amnezia-panel-src
pip3 install --quiet qrcode pillow 2>/dev/null || pip3 install --break-system-packages --quiet qrcode pillow 2>/dev/null || warn "qrcode/pillow не установлены (QR будет недоступен)."

# noise key for PFS (server-level preshared file used by wg-easy style configs)
if [[ -s /tmp/.awg_keep_priv ]]; then
  mv /tmp/.awg_keep_priv /etc/amnezia-panel/server_private.key
  wg pubkey < /etc/amnezia-panel/server_private.key > /etc/amnezia-panel/server_public.key
else
  wg genkey | tee /etc/amnezia-panel/server_private.key | wg pubkey > /etc/amnezia-panel/server_public.key
fi
chmod 600 /etc/amnezia-panel/server_private.key
if [[ -s /tmp/.awg_keep_noise ]]; then
  mv /tmp/.awg_keep_noise /var/lib/amnezia-panel/noise.pem
else
  head -c 32 /dev/urandom | base64 > /var/lib/amnezia-panel/noise.pem
fi
chmod 600 /var/lib/amnezia-panel/noise.pem

# admin credentials consumed by db.init_db()
if [[ -f /etc/amnezia-panel/admin.json ]]; then
  OLD_ADMIN_USER=$(python3 -c "import json;print(json.load(open('/etc/amnezia-panel/admin.json'))['username'])" 2>/dev/null || echo "$ADMIN_USER")
  OLD_ADMIN_PASS=$(python3 -c "import json;print(json.load(open('/etc/amnezia-panel/admin.json'))['password'])" 2>/dev/null || true)
  if [[ -n "$OLD_ADMIN_PASS" && "$OLD_ADMIN_PASS" != "$ADMIN_PASS" ]]; then
    # панель уже работала и пароль мог быть сменён через веб-интерфейс —
    # сохраняем существующий, чтобы повторный запуск не «вернул» старый
    ADMIN_USER="$OLD_ADMIN_USER"; ADMIN_PASS="$OLD_ADMIN_PASS"
    say "Используются сохранённые учётные данные администратора ($ADMIN_USER)."
  fi
fi
printf '{"username": "%s", "password": "%s"}' "$ADMIN_USER" "$ADMIN_PASS" > /etc/amnezia-panel/admin.json
chmod 600 /etc/amnezia-panel/admin.json

# если БД уже есть (повторная установка) — применяем актуальный логин сразу,
# чтобы даже упавший сервис пускал вас по данным из админской консоли
if [[ -f /var/lib/amnezia-panel/panel.db ]]; then
  python3 - <<'PYEOF' || true
import sys
sys.path.insert(0, "/opt/amnezia-panel/api")
try:
    import db
    db.sync_admin_login()
except Exception as e:
    print("[warn] sync_admin_login:", e)
PYEOF
fi

# --- надёжная инициализация БД напрямую (не зависит от кода панели):
# создаём схему, сверяем логин админа и ВСЕГДА применяем пароль из admin.json.
# Именно этот шаг раньше молча пропускался при прерванных установках,
# и панель не пускала внутрь («Неверный логин или пароль» / 502).
python3 - <<'PYEOF' || warn "Не удалось инициализировать БД напрямую (панель сделает это сама при старте)."
import json, os, sqlite3, hashlib, secrets, time
DB = "/var/lib/amnezia-panel/panel.db"
try:
    with open("/etc/amnezia-panel/admin.json") as f:
        a = json.load(f)
    uname, pwd = str(a["username"]).strip().lower(), str(a["password"])
except Exception as e:
    raise SystemExit("[warn] admin.json недоступен: %s" % e)
os.makedirs(os.path.dirname(DB), exist_ok=True)
con = sqlite3.connect(DB)
con.execute("PRAGMA journal_mode=WAL")
con.executescript("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_login INTEGER);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
""")
row = con.execute("SELECT id, username FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
# тот же алгоритм хэширования, что и в panel/api/db.py (scrypt)
salt = secrets.token_hex(16)
h = hashlib.scrypt(pwd.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
if not row:
    con.execute("INSERT INTO users(username,pass_hash,salt,role,enabled,created_at) VALUES(?,?,?,?,1,?)",
                (uname, h, salt, "admin", int(time.time())))
    print("Создан администратор '%s' с паролем из admin.json." % uname)
else:
    if row[1].lower() != uname:
        clash = con.execute("SELECT id FROM users WHERE username=? AND id<>?", (uname, row[0])).fetchone()
        if not clash:
            con.execute("UPDATE users SET username=? WHERE id=?", (uname, row[0]))
    con.execute("UPDATE users SET pass_hash=?, salt=?, enabled=1 WHERE id=?", (h, salt, row[0]))
    print("Пароль администратора в БД синхронизирован с admin.json.")
con.commit(); con.close()
PYEOF

# ---------------------------------------------------------------- 6. initial wg0 config
say "Создание интерфейса wg0 (AmneziaWG, порт $WG_PORT)..."
SUBNET_V4=10.66.66.0; SERVER_V4=10.66.66.1
cat > /etc/amnezia-panel/wg.conf <<EOF
[Interface]
PrivateKey = $(cat /etc/amnezia-panel/server_private.key)
Address = ${SERVER_V4}/24
ListenPort = ${WG_PORT}
PresharedKeyFile = /var/lib/amnezia-panel/noise.pem
Jc = 3
Jmin = 50
Jmax = 90
S1 = 857
S2 = 1271
H1 = 
H2 = 
H3 = 
H4 = 
St = 0
EOF
chmod 600 /etc/amnezia-panel/wg.conf
ln -sf /etc/amnezia-panel/wg.conf /etc/wireguard/wg0.conf

# iptables persistence + masquerade
apt-get install -y -qq iptables-persistent netfilter-persistent >/dev/null 2>&1 || true
IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
iptables -t nat -A POSTROUTING -s ${SUBNET_V4}.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null || true
ip6tables -t nat -A POSTROUTING -s fdaa:bd4c:1234::/64 -o "$IFACE" -j MASQUERADE 2>/dev/null || true
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

systemctl reset-failed wg-quick@wg0.service >/dev/null 2>&1 || true
systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || systemctl restart wg-quick@wg0 >/dev/null 2>&1 || true

# If systemd unit still cannot bring wg0 up (broken unit / failed state),
# start the interface directly with ip+wg — the panel watchdog will keep it alive.
if ! ip -o link show wg0 >/dev/null 2>&1; then
  say "wg-quick не поднял wg0 — включаю интерфейс напрямую..."
  wg-quick down wg0 >/dev/null 2>&1 || true
  ip link add wg0 type wireguard 2>/dev/null || true
  # apply the FULL rendered config (port, noise key, peers) if possible
  if wg set-conf wg0 /etc/wireguard/wg0.conf >/dev/null 2>&1; then
    :
  else
    wg set wg0 private-key <(cat /etc/amnezia-panel/server_private.key) listen-port "$WG_PORT" 2>/dev/null || true
  fi
  ip addr add ${SERVER_V4}/24 dev wg0 2>/dev/null || true
  ip -6 addr add fdaa:bd4c:1234::1/64 dev wg0 2>/dev/null || true
  ip link set wg0 up 2>/dev/null || true
fi

# ---------------------------------------------------------------- 7. firewall
# UFW намеренно НЕ настраивается и НЕ включается этим установщиком:
# если файрвол выключен — он остаётся выключенным, правила не трогаются.
# При необходимости откройте порты вручную: 22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp

# fail2ban
apt-get install -y -qq fail2ban >/dev/null 2>&1 && systemctl enable --now fail2ban >/dev/null 2>&1 || true

# ---------------------------------------------------------------- 8. nginx config + TLS (before services start)
say "Устанавливаем nginx-конфиг и получаем TLS-сертификат..."
apt-get install -y -qq certbot python3-certbot-nginx >/dev/null 2>&1 || apt-get install -y certbot python3-certbot-nginx || true

NGINX_CONF=/etc/nginx/sites-available/amnezia-panel
TLS_DIR=/etc/nginx/tls
CERTDIR=/etc/letsencrypt/live/$DOMAIN
ACME_DIR=/var/www/letsencrypt
mkdir -p "$TLS_DIR" "$ACME_DIR"

# Конфиг ВСЕГДА генерируется инлайновым шаблоном (надёжнее внешнего файла):
#  • listen ... default_server — панель отдаётся даже при запросе по IP или
#    другому server_name (раньше такой запрос уходил в дефолтный сайт nginx);
#  • /.well-known/acme-challenge/ отдаётся с диска ДО редиректа на HTTPS —
#    именно из-за отсутствия этого location Let's Encrypt не мог пройти
#    HTTP-01 членж и сертификат никогда не выдавался.
cat > "$NGINX_CONF" <<EOF
# AmneziaWG Panel — generated by install.sh ($(date -u +%F\ %T\ UTC))
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN _;

    location /.well-known/acme-challenge/ {
        root $ACME_DIR;
        default_type "text/plain";
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name $DOMAIN _;

    ssl_certificate     $TLS_DIR/self-signed.pem;
    ssl_certificate_key $TLS_DIR/self-signed.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:8777;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 90s;
    }
}
EOF

# temporary self-signed cert so nginx starts even if certbot fails later
if [[ ! -f "$TLS_DIR/self-signed.key" ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "$TLS_DIR/self-signed.key" -out "$TLS_DIR/self-signed.pem" \
    -subj "/CN=$DOMAIN" >/dev/null 2>&1
  chmod 600 "$TLS_DIR/self-signed.key"
fi

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/amnezia-panel
rm -f /etc/nginx/sites-enabled/default
# если где-то остался дефолтный конфиг с «default_server» — убираем дубли,
# иначе nginx -t падает с "duplicate default server"
if grep -RqsE '^\s*listen\s+.*default_server' /etc/nginx/conf.d/ 2>/dev/null; then
  for f in /etc/nginx/conf.d/*.conf; do
    [[ -f "$f" ]] && ! grep -q amnezia-panel "$f" \
      && sed -i.bak -E 's/^(\s*listen\s+[^;]*\s)default_server/\1/' "$f" || true
  done
fi
if nginx -t >>"$LOG" 2>&1; then
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
else
  warn "Проверка nginx завершилась с ошибкой — показываю вывод:"
  cat "$NGINX_CONF" >&2
  nginx -t || true
  die "Некорректный nginx-конфиг. Исправьте /etc/nginx/sites-available/amnezia-panel и перезапустите установку."
fi

# панель должна отвечать ещё до выпуска сертификата — иначе certbot увидит 502,
# а пользователь получит «голый nginx». Поднимаем её прямо сейчас.
ensure_panel_up() {
  systemctl is-active --quiet wg-quick@wg0 || { systemctl reset-failed wg-quick@wg0.service >/dev/null 2>&1 || true; systemctl restart wg-quick@wg0 >/dev/null 2>&1 || true; }
  systemctl restart amnezia-panel || true
  local i
  for i in $(seq 1 10); do
    sleep 2
    curl -fsS --max-time 5 http://127.0.0.1:8777/api/ping >/dev/null 2>&1 && return 0
  done
  return 1
}
systemctl daemon-reload
if ! curl -fsS --max-time 3 http://127.0.0.1:8777/api/ping >/dev/null 2>&1; then
  say "Запускаю сервис панели..."
  ensure_panel_up || warn "Панель не отвечает на 127.0.0.1:8777 — попробую разобраться в логах ниже."
fi

# ------------------------------------------------------------------ TLS helper
# Выпуск/обновление Let's Encrypt + подмена путей в конфиге (с откатом).
issue_letsencrypt() {
  command -v certbot >/dev/null 2>&1 || return 1
  echo "test" > "$ACME_DIR/.acme-check" 2>/dev/null || true
  local _attempt
  for _attempt in 1 2; do
    if certbot certonly --webroot -w "$ACME_DIR" -d "$DOMAIN" \
         --non-interactive --agree-tos -m "admin@$DOMAIN" \
         --keep-until-expiring --preferred-challenges http >>"$LOG" 2>&1; then
      break
    fi
    sleep 3
  done
  [[ -f "$CERTDIR/fullchain.pem" ]] || return 1
  sed -i "s|$TLS_DIR/self-signed.pem|$CERTDIR/fullchain.pem|; s|$TLS_DIR/self-signed.key|$CERTDIR/privkey.pem|" "$NGINX_CONF"
  if nginx -t >>"$LOG" 2>&1; then
    systemctl reload nginx
    return 0
  fi
  warn "nginx не принял LE-пути к сертификату — оставляю самоподписанный."
  sed -i "s|$CERTDIR/fullchain.pem|$TLS_DIR/self-signed.pem|; s|$CERTDIR/privkey.pem|$TLS_DIR/self-signed.key|" "$NGINX_CONF"
  nginx -t >>"$LOG" 2>&1 && systemctl reload nginx
  return 1
}

# issue a real Let's Encrypt certificate (HTTP-01 via webroot — no ALPN needed)
say "Выпуск сертификата Let's Encrypt для $DOMAIN..."
CERT_OK=0
if [[ -f "$CERTDIR/fullchain.pem" ]]; then
  say "Сертификат Let's Encrypt уже существует — обновляю привязку конфига."
  issue_letsencrypt && CERT_OK=1
elif issue_letsencrypt; then
  say "Сертификат Let's Encrypt выдан успешно ✔"
  CERT_OK=1
else
  warn "certbot не смог получить сертификат (проверьте A-запись $DOMAIN -> $PUB_IP и доступность порта 80 извне)."
  warn "Панель работает на временном самоподписанном сертификате."
  warn "Когда DNS/порты заработают, выполните (или просто запустите install.sh заново):"
  echo "  certbot certonly --webroot -w $ACME_DIR -d $DOMAIN --agree-tos -m admin@$DOMAIN --keep-until-expiring"
  echo "  # затем замените пути сертификатов в $NGINX_CONF и: systemctl reload nginx"
fi
if [[ $CERT_OK == 1 ]] && systemctl enable certbot.timer >/dev/null 2>&1; then
  :
else
  (crontab -l 2>/dev/null | grep -v certbot; \
   echo "0 3 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'") | crontab -
fi

# ---------------------------------------------------------------- 9. systemd services
say "Регистрация systemd-сервисов панели..."
cat > /etc/systemd/system/amnezia-panel.service <<EOF
[Unit]
Description=AmneziaWG Control Panel
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/amnezia-panel/api/server.py
Restart=always
RestartSec=3
Environment=AWG_PORT=8777
Environment=AWG_DB=/var/lib/amnezia-panel/panel.db
StandardOutput=append:/var/log/amnezia-panel.log
StandardError=append:/var/log/amnezia-panel.log

[Install]
WantedBy=multi-user.target
EOF
if [[ -f "$SRC/scripts/awg-stats.service" && -f "$SRC/scripts/awg-stats.timer" ]]; then
  cp "$SRC/scripts/awg-stats.service" "$SRC/scripts/awg-stats.timer" /etc/systemd/system/
else
  cat > /etc/systemd/system/awg-stats.service <<EOF
[Unit]
Description=AmneziaWG panel traffic stats collector

[Service]
Type=oneshot
Environment=AWG_DB=/var/lib/amnezia-panel/panel.db
ExecStart=/usr/bin/python3 /opt/amnezia-panel/api/wg.py --collect
EOF
  cat > /etc/systemd/system/awg-stats.timer <<EOF
[Unit]
Description=Collect AmneziaWG traffic stats every minute

[Timer]
OnBootDelaySec=30
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
EOF
fi
systemctl daemon-reload

# seed panel settings into DB (direct sqlite writes — server not running yet)
python3 - <<PYEOF
import json, sqlite3
cfg = {
 "endpoint_host":"$DOMAIN","port":"$WG_PORT","subnet":"$SUBNET_V4.0/24",
 "server_ip":"$SERVER_V4/24","server_ipv6":"fdaa:bd4c:1234::1/64",
 "pfs":"1","amnezia_enabled":"1","jc":"3","jmin":"50","jmax":"90",
 "s1":"857","s2":"1271","st":"0","default_dns":"1.1.1.1, 8.8.8.8",
 "default_mtu":"1420","site_name":"AmneziaWG Panel",
}
con = sqlite3.connect('/var/lib/amnezia-panel/panel.db')
con.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)')
con.executemany('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', list(cfg.items()))
con.commit(); con.close()
PYEOF

# ensure DB dir exists (panel service writes WAL files there)
mkdir -p /var/lib/amnezia-panel

systemctl enable amnezia-panel awg-stats.timer >/dev/null 2>&1
systemctl restart amnezia-panel || true
sleep 2

# self-heal loop: if the panel keeps crashing, show the real traceback and retry
PANEL_OK=0
for _i in 1 2 3 4 5 6; do
  if curl -fsS --max-time 5 http://127.0.0.1:8777/api/ping >/dev/null 2>&1; then
    PANEL_OK=1
    break
  fi
  sleep 2
done
if [[ $PANEL_OK == 0 ]]; then
  warn "Панель не отвечает на http://127.0.0.1:8777/api/ping."
  warn "Диагностика (последние ошибки сервиса):"
  journalctl -u amnezia-panel -n 40 --no-pager 2>/dev/null | sed 's/^/   /' || true
  tail -n 40 /var/log/amnezia-panel.log 2>/dev/null | sed 's/^/   /' || true
  # try to surface a Python traceback directly
  TRC=$(timeout 10 /usr/bin/python3 /opt/amnezia-panel/api/server.py 2>&1 | grep -A 12 "Traceback" | head -n 25 || true)
  [[ -n "$TRC" ]] && printf '%s\n' "$TRC" | sed 's/^/   /'
  warn "Пробую запустить сервис ещё раз..."
  systemctl restart amnezia-panel || true
  for _i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 2
    if curl -fsS --max-time 5 http://127.0.0.1:8777/api/ping >/dev/null 2>&1; then
      PANEL_OK=1
      break
    fi
  done
fi
if [[ $PANEL_OK == 1 ]]; then
  say "API панели отвечает на 127.0.0.1:8777 ✔"
else
  warn "!! ВНИМАНИЕ: панель не поднялась (nginx будет отдавать 502 Bad Gateway)."
  warn "Строки выше содержат точную причину падения — исправьте её и выполните:"
  echo "   systemctl restart amnezia-panel && journalctl -u amnezia-panel -f"
fi

# ---------------------------------------------------------------- end-to-end check
# Финальная проверка «как видит браузер»: запрос через nginx, а не напрямую в API.
# Именно этот шаг раньше молча пропускался — пользователь получал «голый nginx»
# или 502, а установщик рапортовал об успехе.
say "Проверяю доступность панели через nginx..."
NGINX_CHECK=""
for _i in 1 2 3; do
  NGINX_CHECK=$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1/ 2>/dev/null || true)
  [[ "$NGINX_CHECK" == "200" ]] && break
  sleep 2
done
if [[ "$NGINX_CHECK" == "200" ]]; then
  say "Панель отдаётся через nginx (HTTPS с localhost → 200 OK) ✔"
elif [[ "$NGINX_CHECK" == "502" || "$NGINX_CHECK" == "504" ]]; then
  warn "nginx вернул $NGINX_CHECK — прокси до панели не работает. Диагностика:"
  ss -ltnp 2>/dev/null | grep -E ':(80|443|8777)' | sed 's/^/   /' || true
  tail -n 30 /var/log/amnezia-panel.log 2>/dev/null | sed 's/^/   /' || true
  warn "Чиню автоматически: перезапуск сервиса панели..."
  ensure_panel_up \
    && curl -k -s -o /dev/null -w '' --max-time 8 https://127.0.0.1/ >/dev/null 2>&1 \
    && say "После перезапуска панель отвечает через nginx ✔" \
    || warn "Панель по-прежнему недоступна через nginx — смотрите /var/log/amnezia-panel.log"
else
  warn "Неожиданный ответ от nginx: '${NGINX_CHECK:-нет соединения}'. Проверьте: systemctl status nginx"
fi

# --- финальная проверка логина напрямую в БД (scrypt-хэш = пароль из admin.json).
# Если не совпадает — чиним хэш на месте, чтобы «Неверный логин или пароль»
# больше никогда не появился после установки.
if [[ -f /var/lib/amnezia-panel/panel.db ]]; then
  python3 - <<'PYEOF' || true
import json, sqlite3, hashlib, secrets
try:
    with open("/etc/amnezia-panel/admin.json") as f:
        a = json.load(f)
    uname, pwd = str(a["username"]).strip().lower(), str(a["password"])
    con = sqlite3.connect("/var/lib/amnezia-panel/panel.db")
    con.row_factory = sqlite3.Row
    r = con.execute("SELECT id, username, pass_hash, salt FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
    if not r:
        print("[warn] в БД нет администратора — создаём...")
        salt = secrets.token_hex(16)
        h = hashlib.scrypt(pwd.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
        import time as _t
        con.execute("INSERT INTO users(username,pass_hash,salt,role,enabled,created_at) VALUES(?,?,?,?,1,?)",
                    (uname, h, salt, "admin", int(_t.time())))
        con.commit(); con.close()
        print("OK: администратор создан.")
    else:
        want = hashlib.scrypt(pwd.encode(), salt=r["salt"].encode(), n=16384, r=8, p=1).hex()
        if want != r["pass_hash"]:
            print("Хэш пароля админа в БД расходится с admin.json — синхронизирую...")
            salt = secrets.token_hex(16)
            h = hashlib.scrypt(pwd.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
            con.execute("UPDATE users SET username=?, pass_hash=?, salt=?, enabled=1 WHERE id=?",
                        (uname, h, salt, r["id"]))
            con.commit()
        # параллельно проверяем целостность схемы (остальные таблицы)
        tables = {x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing = {"users","keys","sessions","settings"} - tables
        if missing:
            print("[warn] в БД отсутствуют таблицы:", ", ".join(sorted(missing)))
        con.close()
        print("OK: вход '%s' / пароль из admin.json проверен и готов." % uname)
except Exception as e:
    print("[warn] проверка логина: %r" % (e,))
PYEOF
fi

# --- emergency admin access: if the panel is down, recover login/password from DB
if [[ $PANEL_OK == 0 && -f /var/lib/amnezia-panel/panel.db ]]; then
  say "Пробую восстановить доступ к панели напрямую через базу данных..."
  python3 - <<'PYEOF' || true
import json, os, sys
sys.path.insert(0, "/opt/amnezia-panel/api")
try:
    import db
    c = db.conn()
    r = c.execute("SELECT id, username FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
    if not r:
        print("[warn] в БД нет администратора")
        sys.exit(0)
    new_pass = os.environ.get("ADMIN_PASS_RECOVER") or ""
    if not new_pass:
        import secrets as _s
        new_pass = _s.token_urlsafe(12)[:14]
    h, s = db.pw_hash(new_pass)
    c.execute("UPDATE users SET pass_hash=?, salt=?, enabled=1 WHERE id=?", (h, s, r["id"]))
    c.commit(); c.close()
    with open(db.ADMIN_CRED_PATH, "w") as f:
        json.dump({"username": r["username"], "password": new_pass}, f)
    os.chmod(db.ADMIN_CRED_PATH, 0o600)
    print("Логин восстановлен напрямую в БД: %s / %s" % (r["username"], new_pass))
except Exception as e:
    print("[warn] восстановление логина не удалось:", e)
PYEOF
fi

# ---------------------------------------------------------------- 10. done
URL="https://$DOMAIN"
clear 2>/dev/null || true
echo -e "${C_G}"
cat <<EOF

  ✅  Установка завершена!

  🌐 Панель управления : $URL
  👤 Логин             : $ADMIN_USER
  🔑 Пароль            : $ADMIN_PASS

  📡 AmneziaWG endpoint: $DOMAIN:$WG_PORT (UDP)
  🔒 Серверный pubkey  : $(cat /etc/amnezia-panel/server_public.key)
  $( [[ $CERT_OK == 1 ]] && echo "🛂 TLS: Let's Encrypt — автоматическое продление включено" \
     || echo "🛂 TLS: самоподписанный — браузер предупредит о сертификате, можно продолжить; после починки DNS/портов запустите install.sh заново для выпуска Let's Encrypt" )
  $( [[ $NGINX_CHECK == "200" ]] && echo "🟢 Проверка через nginx: панель отдаётся (HTTP 200)" \
     || echo "🟡 Проверка через nginx: HTTP ${NGINX_CHECK:-нет соединения} — если не 200, смотрите systemctl status nginx и /var/log/amnezia-panel.log" )

  Полезные команды:
    systemctl status amnezia-panel   — статус панели
    systemctl status nginx           — статус веб-сервера
    wg show                          — активные пиры
    systemctl status fail2ban        — защита от брутфорса
    tail -f /var/log/amnezia-install.log — лог установки
    tail -f /var/log/amnezia-panel.log   — лог самой панели

  ⚠️  Смените пароль администратора после первого входа!

EOF
echo -e "${C_0}"
