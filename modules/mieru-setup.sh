#!/usr/bin/env bash
set -euo pipefail

. "$(dirname "$0")/modules/preflight.sh"

CONF_DIR="/etc/vpn-protocols"
mkdir -p "$CONF_DIR"

PORT="${MIERU_PORT:-}"
USERNAME="${MIERU_USER:-}"
PASSWORD="${MIERU_PASSWORD:-}"

if [ -f "${CONF_DIR}/mita.json" ]; then
    [ -z "$PORT" ] && PORT=$(jq -r '.portBindings[0].port' "${CONF_DIR}/mita.json" 2>/dev/null || echo "")
    [ -z "$USERNAME" ] && USERNAME=$(jq -r '.users[0].name' "${CONF_DIR}/mita.json" 2>/dev/null || echo "")
    [ -z "$PASSWORD" ] && PASSWORD=$(jq -r '.users[0].password' "${CONF_DIR}/mita.json" 2>/dev/null || echo "")
fi

# 1. Download Mieru (mita) binary
BINARY_PATH="/usr/local/bin/mita"
if [ ! -f "$BINARY_PATH" ]; then
    log_info "Загрузка Mieru (mita) бинарного файла..."
    # Get latest version from API
    LATEST_VER=$(curl -s https://api.github.com/repos/enfein/mieru/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    if [ -z "$LATEST_VER" ]; then
        LATEST_VER="3.34.1" # Fallback version
    fi
    DOWNLOAD_URL="https://github.com/enfein/mieru/releases/download/v${LATEST_VER}/mita_${LATEST_VER}_linux_${ARCH_TYPE}.tar.gz"
    
    # Download and extract
    curl -L -o /tmp/mita.tar.gz "$DOWNLOAD_URL"
    tar -xf /tmp/mita.tar.gz -C /tmp
    mv /tmp/mita "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
fi

# 2. Select free port
if [ -z "$PORT" ]; then
    while true; do
        RAND_PORT=$(shuf -i 20000-65000 -n 1)
        if ! ss -tlnp | grep -q ":${RAND_PORT} " && ! ss -ulnp | grep -q ":${RAND_PORT} "; then
            PORT=$RAND_PORT
            break
        fi
    done
fi

# 3. Generate credentials
if [ -z "$USERNAME" ]; then
    USERNAME=$(openssl rand -hex 8)
fi
if [ -z "$PASSWORD" ]; then
    PASSWORD=$(openssl rand -hex 16)
fi

# Create system user 'mita' if it doesn't exist
if ! id "mita" >/dev/null 2>&1; then
    log_info "Создание системного пользователя mita..."
    useradd -r -s /usr/sbin/nologin mita || adduser --system --no-create-home --group mita || true
fi

# Create required configuration and library directories
mkdir -p /etc/mita /var/lib/mita
chown -R mita:mita /etc/mita /var/lib/mita || true

log_info "Настройка Mieru (mita) на порту $PORT (TCP/UDP)..."

# 4. Create Systemd Service
cat <<EOF > /etc/systemd/system/mita.service
[Unit]
Description=Mieru Proxy Server (mita)
After=network.target

[Service]
Type=simple
RuntimeDirectory=mita
ExecStart=$BINARY_PATH run
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# 5. Start Service to open control socket
systemctl daemon-reload
systemctl enable --now mita

# Wait for socket to become available
log_info "Ожидание инициализации сокета управления mita..."
for i in {1..20}; do
    if [ -S /var/run/mita/mita.sock ] || [ -S /var/run/mita.sock ] || [ -S /run/mita/mita.sock ]; then
        break
    fi
    sleep 0.5
done

# 6. Apply configuration dynamically
CONFIG_JSON="${CONF_DIR}/mita.json"
cat <<EOF > "$CONFIG_JSON"
{
  "portBindings": [
    {
      "port": $PORT,
      "protocol": "TCP"
    },
    {
      "port": $PORT,
      "protocol": "UDP"
    }
  ],
  "users": [
    {
      "name": "$USERNAME",
      "password": "$PASSWORD",
      "allowPrivateIP": true,
      "allowLoopbackIP": true
    }
  ],
  "loggingLevel": "INFO",
  "mtu": 1400
}
EOF

# Apply config
$BINARY_PATH apply config "$CONFIG_JSON"
systemctl restart mita || true
log_info "Конфигурация Mieru (mita) успешно применена."

# Export variables for panel
export MIERU_PORT="$PORT"
export MIERU_USER="$USERNAME"
export MIERU_PASSWORD="$PASSWORD"
