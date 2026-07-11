#!/usr/bin/env bash
set -euo pipefail

. "$(dirname "$0")/preflight.sh"

CONF_DIR="/etc/vpn-protocols"
mkdir -p "$CONF_DIR"

# Parameters
PORT="${HYSTERIA_PORT:-}"
PASSWORD="${HYSTERIA_PASSWORD:-}"
CERT_PATH="${CERT_PATH:-/etc/vpn-protocols/certs/cert.pem}"
KEY_PATH="${KEY_PATH:-/etc/vpn-protocols/certs/key.pem}"

# 1. Download Hysteria 2 binary
BINARY_PATH="/usr/local/bin/hysteria"
if [ ! -f "$BINARY_PATH" ]; then
    log_info "Загрузка Hysteria 2 бинарного файла..."
    DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${ARCH_TYPE}"
    curl -L -o "$BINARY_PATH" "$DOWNLOAD_URL"
    chmod +x "$BINARY_PATH"
fi

# 2. Select free port
if [ -z "$PORT" ]; then
    while true; do
        RAND_PORT=$(shuf -i 20000-65000 -n 1)
        if ! ss -uln | grep -q ":${RAND_PORT} "; then
            PORT=$RAND_PORT
            break
        fi
    done
fi

# 3. Generate password
if [ -z "$PASSWORD" ]; then
    PASSWORD=$(openssl rand -hex 16)
fi

log_info "Настройка Hysteria 2 на порту $PORT (UDP)..."

# 4. Write Configuration
cat <<EOF > "${CONF_DIR}/hysteria2.yaml"
listen: :$PORT
tls:
  cert: $CERT_PATH
  key: $KEY_PATH
auth:
  type: password
  password:
    - "$PASSWORD"
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
EOF

# 5. Create Systemd Service
cat <<EOF > /etc/systemd/system/hysteria2.service
[Unit]
Description=Hysteria 2 VPN Server
After=network.target

[Service]
Type=simple
ExecStart=$BINARY_PATH server --config ${CONF_DIR}/hysteria2.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# 6. Reload and start
systemctl daemon-reload
systemctl enable --now hysteria2
log_info "Hysteria 2 запущен и добавлен в автозагрузку."

# Export variables for panel
export HYSTERIA_PORT="$PORT"
export HYSTERIA_PASSWORD="$PASSWORD"
EOF
