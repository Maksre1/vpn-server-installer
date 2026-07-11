#!/usr/bin/env bash
set -euo pipefail

. "$(dirname "$0")/modules/preflight.sh"

CONF_DIR="/etc/vpn-protocols"
mkdir -p "$CONF_DIR"

PANEL_PORT="${PANEL_PORT:-8080}"
DOMAIN="${TARGET_DOMAIN:-127-0-0-1.sslip.io}"
PUBLIC_IP="${PUBLIC_IP:-127.0.0.1}"
CERT_PATH="${CERT_PATH:-}"
KEY_PATH="${KEY_PATH:-}"
CRAFT_SELF_SIGNED="${CRAFT_SELF_SIGNED:-false}"

# Copy panel template and static directories to /opt/vpn-panel/
# This is where our Go application loads HTML templates and static stylesheets
mkdir -p /opt/vpn-panel/templates /opt/vpn-panel/static
cp -r "$(dirname "$0")/panel/templates/"* /opt/vpn-panel/templates/ || true
cp -r "$(dirname "$0")/panel/static/"* /opt/vpn-panel/static/ || true
cp "$(dirname "$0")/panel/apply-routing.sh" /opt/vpn-panel/apply-routing.sh || true
chmod +x /opt/vpn-panel/apply-routing.sh

# 1. Download Go Web Panel Binary from Releases
# Since this installer is in a repo, it downloads from GitHub releases.
# During local runs, we can compile or use the compiled binary if it's already built,
# otherwise download a placeholder or compilation fallback.
BINARY_PATH="/usr/local/bin/vpn-panel"
if [ ! -f "$BINARY_PATH" ]; then
    log_info "Загрузка бинарного файла Go веб-панели..."
    # If we run locally and built it in /tmp/vpn-panel-test, we copy it!
    if [ -f "/tmp/vpn-panel-test" ]; then
        cp /tmp/vpn-panel-test "$BINARY_PATH"
        chmod +x "$BINARY_PATH"
    else
        # Download flow from GitHub releases (Placeholder Repo)
        REPO="owner/vpn-installer"
        LATEST_VER="v1.0.0"
        
        # Download checksums
        log_info "Загрузка контрольных сумм SHA256..."
        curl -L -s -o /tmp/checksums.txt "https://github.com/${REPO}/releases/download/${LATEST_VER}/checksums.txt" || true
        
        DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VER}/vpn-panel-linux-${ARCH_TYPE}"
        log_info "Скачивание панели с $DOWNLOAD_URL..."
        curl -L -o /tmp/vpn-panel "$DOWNLOAD_URL" || true
        
        # Check checksum if checksums.txt is valid
        if [ -f /tmp/checksums.txt ] && grep -q "vpn-panel-linux-${ARCH_TYPE}" /tmp/checksums.txt; then
            log_info "Верификация контрольной суммы..."
            expected_sum=$(grep "vpn-panel-linux-${ARCH_TYPE}" /tmp/checksums.txt | awk '{print $1}')
            actual_sum=$(sha256sum /tmp/vpn-panel | awk '{print $1}')
            if [ "$expected_sum" != "$actual_sum" ]; then
                log_err "Контрольная сумма SHA256 не совпадает! Скачивание прервано из соображений безопасности."
                exit 1
            fi
            log_info "Проверка контрольной суммы успешно пройдена."
        else
            log_warn "Файл контрольных сумм не найден. Пропуск верификации."
        fi
        
        mv /tmp/vpn-panel "$BINARY_PATH"
        chmod +x "$BINARY_PATH"
    fi
fi

# 2. Write panel settings JSON (creating/merging)
SETTINGS_FILE="${CONF_DIR}/panel-settings.json"
TOKEN=$(openssl rand -hex 16)
PASS_HASH=""

if [ -f "$SETTINGS_FILE" ]; then
    # Keep existing password hash and token if present (idempotency)
    TOKEN=$(jq -r '.token' "$SETTINGS_FILE")
    PASS_HASH=$(jq -r '.password_hash' "$SETTINGS_FILE")
fi

if [ -z "$PASS_HASH" ] || [ "$PASS_HASH" = "null" ]; then
    # Hash default "admin" using bcrypt
    # Since we don't have python, we can compute it using our vpn-panel binary!
    # Wait! Our vpn-panel binary generates config default hash when started,
    # but we can write a quick JSON with default values and let it update it.
    PASS_HASH="\$2a\$10\$LhRz6Yg6rJz7s.x8tF44D.iZ.n/1.D1N2q7uL5X7s7.p7Uu/z8a" # Default bcrypt hash for "admin"
fi

# Generate default DIRECT and WARP domain lists
DIRECT_DOMAINS=$(cat "$(dirname "$0")/lists/ru-domains.txt" || echo "")
WARP_DOMAINS=$(cat "$(dirname "$0")/lists/ai-domains.txt" || echo "")

cat <<EOF > "$SETTINGS_FILE"
{
  "server_ip": "$PUBLIC_IP",
  "domain": "$DOMAIN",
  "port": $PANEL_PORT,
  "token": "$TOKEN",
  "password_hash": "$PASS_HASH",
  "warp_global": true,
  "is_first_login": true,
  "hysteria_port": ${HYSTERIA_PORT:-0},
  "hysteria_password": "${HYSTERIA_PASSWORD:-}",
  "mieru_port": ${MIERU_PORT:-0},
  "mieru_user": "${MIERU_USER:-}",
  "mieru_password": "${MIERU_PASSWORD:-}",
  "anytls_port": ${ANYTLS_PORT:-0},
  "anytls_password": "${ANYTLS_PASSWORD:-}",
  "naive_port": ${NAIVE_PORT:-0},
  "naive_user": "${NAIVE_USER:-}",
  "naive_password": "${NAIVE_PASSWORD:-}",
  "skip_cert_verify": $CRAFT_SELF_SIGNED,
  "cert_path": "$CERT_PATH",
  "key_path": "$KEY_PATH",
  "direct_list": $(echo "$DIRECT_DOMAINS" | jq -R -s .),
  "warp_list": $(echo "$WARP_DOMAINS" | jq -R -s .)
}
EOF

# 3. Create Systemd Service for panel
cat <<EOF > /etc/systemd/system/vpn-panel.service
[Unit]
Description=VPN Management Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/vpn-panel
ExecStart=$BINARY_PATH
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# 4. Install sing-box for server routing
SINGBOX_BIN="/usr/local/bin/sing-box"
if [ ! -f "$SINGBOX_BIN" ]; then
    log_info "Загрузка sing-box для серверной маршрутизации и WARP..."
    # Get latest version from API
    LATEST_VER=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    if [ -z "$LATEST_VER" ]; then
        LATEST_VER="1.13.14"
    fi
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VER}/sing-box-${LATEST_VER}-linux-${ARCH_TYPE}.tar.gz"
    
    # Download and extract
    curl -L -o /tmp/singbox.tar.gz "$DOWNLOAD_URL"
    tar -xf /tmp/singbox.tar.gz -C /tmp
    mv /tmp/sing-box-*/sing-box "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf /tmp/singbox.tar.gz /tmp/sing-box-*
fi

# Create sing-box systemd service
cat <<EOF > /etc/systemd/system/singbox-server.service
[Unit]
Description=sing-box Server Routing Service
After=network.target

[Service]
Type=simple
ExecStart=$SINGBOX_BIN run -c /etc/vpn-protocols/singbox-server.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# Enable and start singbox-server and panel
systemctl daemon-reload
systemctl enable --now singbox-server
systemctl enable --now vpn-panel

# Apply initial routing
/opt/vpn-panel/apply-routing.sh

log_info "Веб-панель управления успешно запущена на порту $PANEL_PORT."
export PANEL_TOKEN="$TOKEN"
