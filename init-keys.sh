#!/usr/bin/env bash
set -euo pipefail

CONFIG="./config.json"

if [ ! -f "$CONFIG" ]; then
  echo "Файл $CONFIG не найден" >&2
  exit 1
fi

# 1) UUID
echo "==> Генерация UUID..."
UUID_RAW="$(docker run --rm --entrypoint xray ghcr.io/xtls/xray-core:latest uuid | tr -d '\r')"
UUID="$(echo "$UUID_RAW" | sed -nE 's/.*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}).*/\1/p' | head -n1)"
if [ -z "${UUID:-}" ]; then
  UUID="$(cat /proc/sys/kernel/random/uuid)"
fi

# 2) x25519
echo "==> Генерация x25519 (Reality keypair)..."
KEYPAIR="$(docker run --rm --entrypoint xray ghcr.io/xtls/xray-core:latest x25519 | tr -d '\r')"
echo "$KEYPAIR"

PRIVATE_KEY="$(echo "$KEYPAIR" | awk -F': ' '/Private key|PrivateKey/ {print $2; exit}')"
PUBLIC_KEY="$(echo "$KEYPAIR" | awk -F': ' '/Public key|PublicKey/ {print $2; exit}')"

if [ -z "${PRIVATE_KEY:-}" ] || [ -z "${PUBLIC_KEY:-}" ]; then
  echo "Ошибка: не удалось распарсить ключи из вывода xray x25519" >&2
  exit 1
fi

# 3) short id
echo "==> Генерация Short ID..."
SHORT_ID="$(openssl rand -hex 8)"

# 4) Проверка плейсхолдеров в config.json
if ! grep -q 'YOUR_UUID\|YOUR_PRIVATE_KEY\|YOUR_SHORT_ID' "$CONFIG"; then
  echo "В $CONFIG уже нет плейсхолдеров YOUR_* (возможно, скрипт уже запускали)." >&2
  echo "Либо восстанови шаблон config.json, либо подставь значения вручную." >&2
  exit 1
fi

# 5) Подстановка
echo "==> Подстановка значений в config.json..."
sed -i \
  -e "s|YOUR_UUID|$UUID|g" \
  -e "s|YOUR_PRIVATE_KEY|$PRIVATE_KEY|g" \
  -e "s|YOUR_SHORT_ID|$SHORT_ID|g" \
  "$CONFIG"

cat <<EOF

===== СГЕНЕРИРОВАННЫЕ ДАННЫЕ (сохрани!) =====
UUID:        $UUID
Private key: $PRIVATE_KEY
Public key:  $PUBLIC_KEY
Short ID:    $SHORT_ID
EOF