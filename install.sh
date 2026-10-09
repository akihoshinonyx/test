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
printf '{"username": "%s", "password": "%s"}' "$ADMIN_USER" "$ADMIN_PASS" > /etc/amnezia-panel/admin.json
chmod 600 /etc/amnezia-panel/admin.json

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

systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || systemctl restart wg-quick@wg0

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
mkdir -p "$TLS_DIR"

if [[ -f "$SRC/scripts/nginx.conf.template" ]]; then
  sed "s|__DOMAIN__|$DOMAIN|g" "$SRC/scripts/nginx.conf.template" > "$NGINX_CONF"
else
  cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate     $TLS_DIR/self-signed.pem;
    ssl_certificate_key $TLS_DIR/self-signed.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location / {
        proxy_pass http://127.0.0.1:8777;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
fi

# temporary self-signed cert so nginx starts even if certbot fails later
if [[ ! -f "$TLS_DIR/self-signed.key" ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "$TLS_DIR/self-signed.key" -out "$TLS_DIR/self-signed.pem" \
    -subj "/CN=$DOMAIN" >/dev/null 2>&1
  chmod 600 "$TLS_DIR/self-signed.key"
fi

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/amnezia-panel
rm -f /etc/nginx/sites-enabled/default
if nginx -t >/dev/null 2>&1; then
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
else
  warn "Проверка nginx завершилась с ошибкой — показываю конфиг:"
  cat "$NGINX_CONF" >&2
  nginx -t || true
  die "Некорректный nginx-конфиг. Исправьте /etc/nginx/sites-available/amnezia-panel и перезапустите установку."
fi

# issue a real Let's Encrypt certificate (HTTP-01 via webroot — no ALPN needed)
say "Выпуск сертификата Let's Encrypt для $DOMAIN..."
mkdir -p /var/www/html
CERT_OK=0
if command -v certbot >/dev/null 2>&1; then
  for _attempt in 1 2; do
    if certbot certonly --webroot -w /var/www/html -d "$DOMAIN" \
         --non-interactive --agree-tos -m "admin@$DOMAIN" \
         --keep-until-expiring --preferred-challenges http >/dev/null 2>&1; then
      CERT_OK=1; break
    fi
    sleep 3
  done
fi
if [[ $CERT_OK == 1 ]]; then
  say "Сертификат Let's Encrypt выдан успешно ✔"
  sed -i "s|$TLS_DIR/self-signed.pem|$CERTDIR/fullchain.pem|; s|$TLS_DIR/self-signed.key|$CERTDIR/privkey.pem|" "$NGINX_CONF"
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
  else
    warn "nginx не принял LE-пути к сертификату — оставляю самоподписанный."
    sed -i "s|$CERTDIR/fullchain.pem|$TLS_DIR/self-signed.pem|; s|$CERTDIR/privkey.pem|$TLS_DIR/self-signed.key|" "$NGINX_CONF"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx
    CERT_OK=0
  fi
else
  warn "certbot не смог получить сертификат (проверьте A-запись $DOMAIN -> $PUB_IP и доступность портов 80/443 извне)."
  warn "Панель работает на временном самоподписанном сертификате."
  warn "После исправления DNS выполните:"
  echo "  certbot certonly --webroot -w /var/www/html -d $DOMAIN --agree-tos -m admin@$DOMAIN --keep-until-expiring"
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
  journalctl -u amnezia-panel -n 40 --no-pager 2>/dev/null | sed 's/^/   /'
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
     || echo "🛂 TLS: самоподписанный — исправьте DNS и выполните: certbot certonly --webroot -w /var/www/html -d $DOMAIN" )

  Полезные команды:
    systemctl status amnezia-panel   — статус панели
    systemctl status nginx           — статус веб-сервера
    wg show                          — активные пиры
    systemctl status fail2ban        — защита от брутфорса
    tail -f /var/log/amnezia-install.log — лог установки

  ⚠️  Смените пароль администратора после первого входа!

EOF
echo -e "${C_0}"
