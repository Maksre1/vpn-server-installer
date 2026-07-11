#!/usr/bin/env bash
set -euo pipefail

. "$(dirname "$0")/preflight.sh"

CONF_DIR="/etc/vpn-protocols"
mkdir -p "$CONF_DIR"

PORT="${NAIVE_PORT:-}"
USERNAME="${NAIVE_USER:-}"
PASSWORD="${NAIVE_PASSWORD:-}"
CERT_PATH="${CERT_PATH:-/etc/vpn-protocols/certs/cert.pem}"
KEY_PATH="${KEY_PATH:-/etc/vpn-protocols/certs/key.pem}"

# 1. Compile Caddy via xcaddy using Temporary Go (Clean Build-and-Purge)
BINARY_PATH="/usr/local/bin/caddy"
if [ ! -f "$BINARY_PATH" ]; then
    log_info "Запуск компиляции Caddy с плагином NaiveProxy (это займет 1-2 минуты)..."
    
    # Download Go compiler
    GO_VER="1.21.6"
    GO_ARCH="amd64"
    if [ "$ARCH_TYPE" = "arm64" ]; then
        GO_ARCH="arm64"
    fi
    GO_TAR="go${GO_VER}.linux-${GO_ARCH}.tar.gz"
    
    log_info "Загрузка Go компилятора ($GO_TAR)..."
    curl -L -o /tmp/go.tar.gz "https://go.dev/dl/${GO_TAR}"
    
    log_info "Распаковка Go компилятора..."
    mkdir -p /tmp/go_home
    tar -C /tmp/go_home -xzf /tmp/go.tar.gz
    
    # Set Go environment
    export GOROOT="/tmp/go_home/go"
    export GOPATH="/tmp/gopath"
    export PATH="${GOROOT}/bin:${GOPATH}/bin:${PATH}"
    
    # Compile xcaddy and caddy
    log_info "Установка xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    
    log_info "Компиляция Caddy с naive-плагином forwardproxy..."
    cd /tmp
    xcaddy build --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@naive
    
    # Install binary
    mv /tmp/caddy "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
    
    # Purge Go compiler and cache to save space
    log_info "Очистка временных файлов сборки Go..."
    rm -rf /tmp/go.tar.gz /tmp/go_home /tmp/gopath
    log_info "Caddy успешно скомпилирован и установлен."
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

# 3. Generate credentials
if [ -z "$USERNAME" ]; then
    USERNAME=$(openssl rand -hex 8)
fi
if [ -z "$PASSWORD" ]; then
    PASSWORD=$(openssl rand -hex 16)
fi

log_info "Настройка NaiveProxy (Caddy) на порту $PORT (TCP)..."

# 4. Generate Caddyfile config
CADDYFILE_CONF="${CONF_DIR}/Caddyfile"
cat <<EOF > "$CADDYFILE_CONF"
:$PORT {
    tls "$CERT_PATH" "$KEY_PATH"
    forward_proxy {
        basic_auth "$USERNAME" "$PASSWORD"
        hide_ip
        hide_via
        probe_resistance
    }
}
EOF

# 5. Create Systemd Service
cat <<EOF > /etc/systemd/system/caddy.service
[Unit]
Description=Caddy Web Server with NaiveProxy
After=network.target

[Service]
Type=simple
ExecStart=$BINARY_PATH run --config $CADDYFILE_CONF --adapter caddyfile
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# 6. Start Service
systemctl daemon-reload
systemctl enable --now caddy
log_info "Caddy/NaiveProxy запущен и добавлен в автозагрузку."

# Export variables for panel
export NAIVE_PORT="$PORT"
export NAIVE_USER="$USERNAME"
export NAIVE_PASSWORD="$PASSWORD"
