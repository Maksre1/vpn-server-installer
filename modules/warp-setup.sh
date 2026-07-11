#!/usr/bin/env bash
set -euo pipefail

. "$(dirname "$0")/modules/preflight.sh"

CONF_DIR="/etc/vpn-protocols"
mkdir -p "$CONF_DIR"

WARP_MODE="${WARP_MODE:-1}" # 1 = Global, 2 = Selective, 3 = Disabled
WARP_CREDS="${CONF_DIR}/warp-credentials.json"

if [ "$WARP_MODE" = "3" ]; then
    log_info "WARP отключен пользователем. Пропуск регистрации."
    rm -f "$WARP_CREDS"
    exit 0
fi

# 1. Download wgcf binary
WGCF_PATH="/usr/local/bin/wgcf"
if [ ! -f "$WGCF_PATH" ]; then
    log_info "Загрузка wgcf для регистрации аккаунта WARP..."
    # Get latest version from API
    LATEST_VER=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    if [ -z "$LATEST_VER" ]; then
        LATEST_VER="2.2.31"
    fi
    DOWNLOAD_URL="https://github.com/ViRb3/wgcf/releases/download/v${LATEST_VER}/wgcf_${LATEST_VER}_linux_${ARCH_TYPE}"
    curl -L -o "$WGCF_PATH" "$DOWNLOAD_URL"
    chmod +x "$WGCF_PATH"
fi

# 2. Register account with exponential backoff for 429 rate limits
OLD_PWD="$PWD"
cd /tmp
rm -f wgcf-account.toml wgcf-profile.conf

log_info "Регистрация аккаунта Cloudflare WARP..."
RETRIES=0
MAX_RETRIES=5
DELAY=3

until "$WGCF_PATH" register --accept-tos >/dev/null 2>&1; do
    RETRIES=$((RETRIES + 1))
    if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
        log_err "Не удалось зарегистрировать аккаунт WARP после $MAX_RETRIES попыток."
        exit 1
    fi
    log_warn "Регистрация WARP ограничена лимитом запросов (429). Повтор через $DELAY сек..."
    sleep "$DELAY"
    DELAY=$((DELAY * 2))
done

# 3. Generate WireGuard profile
log_info "Генерация профиля WireGuard..."
"$WGCF_PATH" generate >/dev/null 2>&1

if [ ! -f wgcf-profile.conf ]; then
    log_err "Файл wgcf-profile.conf не сгенерирован."
    exit 1
fi

# 4. Parse credentials for sing-box native WireGuard client
log_info "Извлечение параметров WireGuard..."
PRIV_KEY=$(grep -i "PrivateKey" wgcf-profile.conf | awk '{print $3}')
ADDR_V4=$(grep "Address" wgcf-profile.conf | sed -E 's/.*=[[:space:]]*([^,]*),.*/\1/' | tr -d ' ')
ADDR_V6=$(grep "Address" wgcf-profile.conf | sed -E 's/.*,[[:space:]]*(.*)/\1/' | tr -d ' ')

# Extract reserved bytes (format: # Reserved = [x, y, z])
RESERVED_RAW=$(grep -i "reserved" wgcf-profile.conf | sed -E 's/.*reserved[[:space:]]*=[[:space:]]*([^#]*).*/\1/' | tr -d ' ' || echo "")
if [ -z "$RESERVED_RAW" ]; then
    RESERVED_RAW="[0,0,0]"
fi

log_info "Запись учетных данных WARP..."
# Write warp-credentials.json
cat <<EOF > "$WARP_CREDS"
{
  "private_key": "$PRIV_KEY",
  "local_address_v4": "$ADDR_V4",
  "local_address_v6": "$ADDR_V6",
  "reserved": $RESERVED_RAW
}
EOF

# Clean up /tmp
rm -f wgcf-account.toml wgcf-profile.conf
cd "$OLD_PWD"
log_info "WARP успешно настроен в пользовательском режиме (userspace via sing-box)."
