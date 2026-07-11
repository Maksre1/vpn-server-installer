#!/usr/bin/env bash
set -euo pipefail

. "$(dirname "$0")/preflight.sh"

CONF_DIR="/etc/vpn-protocols"
mkdir -p "$CONF_DIR"

PORT="${ANYTLS_PORT:-}"
PASSWORD="${ANYTLS_PASSWORD:-}"

# 1. Download AnyTLS binary
BINARY_PATH="/usr/local/bin/anytls-server"
if [ ! -f "$BINARY_PATH" ]; then
    log_info "Загрузка AnyTLS бинарного файла..."
    # Get latest version from API
    LATEST_VER=$(curl -s https://api.github.com/repos/anytls/anytls-go/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    if [ -z "$LATEST_VER" ]; then
        LATEST_VER="0.0.13"
    fi
    DOWNLOAD_URL="https://github.com/anytls/anytls-go/releases/download/v${LATEST_VER}/anytls_${LATEST_VER}_linux_${ARCH_TYPE}.zip"
    
    # Download and unzip
    pkg_install unzip || true
    curl -L -o /tmp/anytls.zip "$DOWNLOAD_URL"
    unzip -o /tmp/anytls.zip -d /tmp/anytls_bin
    mv /tmp/anytls_bin/anytls-server "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
    rm -rf /tmp/anytls.zip /tmp/anytls_bin
fi

# 2. Select free port
if [ -z "$PORT" ]; then
    while true; do
        RAND_PORT=$(shuf -i 20000-65000 -n 1)
        if ! ss -tlnp | grep -q ":${RAND_PORT} "; then
            PORT=$RAND_PORT
            break
        fi
    done
fi

# 3. Generate password
if [ -z "$PASSWORD" ]; then
    PASSWORD=$(openssl rand -hex 16)
fi

log_info "Настройка AnyTLS на порту $PORT (TCP)..."

# 4. Create Systemd Service
cat <<EOF > /etc/systemd/system/anytls-server.service
[Unit]
Description=AnyTLS Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=$BINARY_PATH -l 0.0.0.0:$PORT -p $PASSWORD
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# 5. Start Service
systemctl daemon-reload
systemctl enable --now anytls-server
log_info "AnyTLS запущен и добавлен в автозагрузку."

# Export variables for panel
export ANYTLS_PORT="$PORT"
export ANYTLS_PASSWORD="$PASSWORD"
EOF
