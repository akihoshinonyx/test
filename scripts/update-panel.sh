#!/bin/bash
# Скрипт для запуска на VPS: подтягивает свежие файлы панели + install.sh и применяет их
set -e
echo "==> Скачиваю архив с GitHub..."
curl -fsSL https://github.com/akihoshinonyx/test/archive/refs/heads/main.tar.gz -o /tmp/p.tar.gz
tar -xzf /tmp/p.tar.gz -C /tmp
rm -rf /tmp/test-main/panel/api/__pycache__
echo "==> Обновляю файлы панели..."
cp -r /tmp/test-main/panel/api/* /opt/amnezia-panel/api/
cp -r /tmp/test-main/panel/web/* /opt/amnezia-panel/web/ 2>/dev/null || true
cp /tmp/test-main/install.sh /root/install.sh
echo "==> Перезапускаю панель (watchdog сам поднимет wg0)..."
systemctl restart amnezia-panel
sleep 3
echo "==> Проверка API:"; curl -s http://127.0.0.1:8777/api/ping; echo
echo "==> Жду watchdog (~35 сек), затем проверка wg0:"
sleep 35
ip -o link show wg0 && wg show | head -8 || echo "!! wg0 всё ещё отсутствует — смотрите вывод ниже"
journalctl -u amnezia-panel -n 15 --no-pager || true
