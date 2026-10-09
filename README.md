# 🛡️ AmneziaWG 3.0 — Web Control Panel

Полноценная веб-панель управления VPN-сервером на базе **AmneziaWG 3.0** (WireGuard с шумовыми пакетами, устойчивый к DPI-блокировкам) + **однострочный установщик для VPS (Ubuntu/Debian)** с автоматической выдачей сертификатов Let's Encrypt.

## ✨ Возможности

### Веб-панель
- 📊 **Дашборд** — онлайн-пиры, трафик, нагрузка сервера, быстрые действия
- 🔑 **Управление ключами VPN**
  - Создание / редактирование / удаление / ротация ключей
  - Индивидуальные настройки каждого ключа: IP в туннеле, DNS, MTU, AllowedIPs
  - Срок действия ключа и лимит трафика (quota) с автоотключением
  - Транспорт на выбор: чистый WireGuard, AmneziaWG (junk packets) или Shadowsocks + AmneziaWG
  - Per-Key Preshared Keys (PFS), Counter/Tick для SS-транспорта
  - Экспорт: `.conf` (wg-quick), JSON (ConfigLink/AmneziaWG app), QR-код
  - Поиск, статусы «онлайн / истёк / выключен», заметки, счётчик использованного трафика
- 👥 **Система пользователей**
  - Роли: `admin` (полный доступ) и `user` (только свои ключи)
  - Лимит ключей для обычных пользователей
  - Включение/отключение аккаунтов, смена пароля, последний вход
- ⚙️ **Настройки сервера** — endpoint, порт, подсеть, DNS/MTU по умолчанию, параметры анти-DPI (Jc/Jmin/Jmax/S1/S2)
- 🧰 **Обслуживание** — статус сервисов, TLS-сертификат, список файлов панели и **полное удаление веб-панели с сервера прямо из консоли** (с двойным подтверждением)
- 🌗 Тёмная/светлая тема, адаптивный дизайн, без внешних CDN и фреймворков (vanilla JS)

### Установщик `install.sh`
1. Спрашивает **домен панели** (проверяет A-запись относительно публичного IP)
2. Ставит все зависимости автоматически: wireguard-tools, nginx, python3, certbot, ufw, fail2ban, qrencode…
3. Подключает репозиторий Amnezia и ставит модуль **AmneziaWG** (fallback на wireguard-dkms)
4. Настраивает IP-форвардинг, NAT (MASQUERADE), iptables-persistent, UFW, fail2ban
5. Создаёт интерфейс `wg0`, systemd-сервисы панели и сбора статистики
6. Автоматически выпускает **сертификат Let's Encrypt** для домена + автопродление
7. Генерирует пароль администратора и печатает готовую сводку доступа

## 🚀 Установка на VPS (Ubuntu 20.04 / 22.04 / 24.04, Debian 11/12)

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/install.sh -o install.sh && sudo bash install.sh
```

> Замените `OWNER/REPO` на ваш GitHub-репозиторий. Если клонируете руками:
> ```bash
> git clone https://github.com/OWNER/REPO.git && cd REPO && sudo bash install.sh
> ```

### Непараметрическая (non-interactive) установка
```bash
DOMAIN=vpn.example.com WG_PORT=443 ADMIN_USER=admin ADMIN_PASS='Свой_пароль' \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/install.sh)"
```
*(в таком виде используйте `sudo -E` для передачи переменных окружения)*

После установки панель доступна по адресу **https://ваш-домен/**, логин/пароль — из вывода инсталлятора.

## 📂 Структура проекта

```
├── install.sh                 # однострочный установщик для VPS
├── panel/
│   ├── api/                   # HTTP API + статика (Python, только stdlib + qrcode/pillow опц.)
│   │   ├── server.py          # маршруты /api/*, авторизация по cookie-сессиям
│   │   ├── db.py              # SQLite: users, keys, sessions, settings
│   │   └── wg.py              # генерация конфигов wg/amnezia/ss, применение wg-quick
│   ├── web/                   # SPA-фронтенд (vanilla JS)
│   └── scripts/               # systemd-юниты и шаблон nginx
```

## 🔒 Безопасность

- Пароли — pbkdf2_hmac + соль; сессии — HttpOnly SameSite=Lax cookie
- API слушает только `127.0.0.1`, наружу отдаётся через Nginx с TLS (Let's Encrypt)
- RBAC: обычные пользователи видят только свои ключи
- Приватные ключи сервера хранятся с chmod 600, конфиг `/etc/amnezia-panel/wg.conf` закрыт
- Fail2ban + UFW включаются автоматически

## 🧹 Удаление панели

Из веб-консоли: **Обслуживание → ☠️ Удаление веб-панели** (нужно ввести `DELETE-PANEL`).
Или вручную на сервере:

```bash
systemctl disable --now amnezia-panel awg-stats.timer
rm -rf /opt/amnezia-panel /etc/amnezia-panel /var/lib/amnezia-panel \
  /etc/systemd/system/{amnezia-panel.service,awg-stats.*} \
  /etc/nginx/sites-{available,enabled}/amnezia-panel /etc/wireguard/wg0.conf
wg-quick down wg0; systemctl daemon-reload; systemctl reload nginx
```

## ❓ Частые проблемы

| Проблема | Решение |
|---|---|
| Certbot не выдал сертификат | Проверьте A-запись домена → IP сервера и открытые порты 80/443, затем: `certbot --nginx -d ваш-домен` |
| Клиент не подключается | `wg show`, `ufw status` — порт UDP должен быть разрешён; проверьте `Jc/Jmin/Jmax` совпадают ли на клиенте |
| Забыт пароль админа | `sqlite3 /var/lib/amnezia-panel/panel.db "UPDATE users SET pass_hash='',salt='' WHERE username='admin'"` + перезапуск сервиса (или переустановка панели) |

## 📄 Лицензия

MIT
