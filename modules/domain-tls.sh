#!/usr/bin/env bash
set -euo pipefail

. "$(dirname "$0")/modules/preflight.sh"

# Input params (usually passed as environment variables)
# DOMAIN: Custom user domain or empty
# CF_TOKEN: Cloudflare DNS API token or empty
# EMAIL: User email or empty for Let's Encrypt
DOMAIN="${DOMAIN:-}"
CF_TOKEN="${CF_TOKEN:-}"
EMAIL="${EMAIL:-admin@sslip.io}"

# Get public IP
PUBLIC_IP=$(curl -4 -s https://ip.sb || curl -4 -s https://api.ipify.org || echo "")
if [ -z "$PUBLIC_IP" ]; then
    log_err "Не удалось получить публичный IPv4-адрес сервера."
    exit 1
fi

HYPHEN_IP=$(echo "$PUBLIC_IP" | tr '.' '-')

# Determine target domain
TARGET_DOMAIN=""
IS_WILDCARD_DNS=false

if [ -n "$DOMAIN" ]; then
    TARGET_DOMAIN="$DOMAIN"
else
    # Auto-generate domain and test wildcard services
    IS_WILDCARD_DNS=true
    log_info "Тестирование цепочки wildcard-DNS сервисов..."
    for service in "sslip.io" "nip.io" "traefik.me"; do
        TEST_DOMAIN="${HYPHEN_IP}.${service}"
        log_info "Проверка домена $TEST_DOMAIN..."
        
        # Test lookup
        RESOLVED_IP=$(dig +short "$TEST_DOMAIN" || nslookup "$TEST_DOMAIN" | awk '/Address:/ {print $2}' | tail -n1 || echo "")
        if [ "$RESOLVED_IP" = "$PUBLIC_IP" ]; then
            TARGET_DOMAIN="$TEST_DOMAIN"
            log_info "Успешно: $TEST_DOMAIN резолвится в $PUBLIC_IP"
            break
        fi
        log_warn "$TEST_DOMAIN не резолвится."
    done
fi

if [ -z "$TARGET_DOMAIN" ]; then
    log_warn "Не удалось разрешить ни один wildcard-DNS домен в IP сервера."
    TARGET_DOMAIN="${HYPHEN_IP}.sslip.io" # Default fallback
fi

log_info "Целевой домен для TLS: $TARGET_DOMAIN"

# Setup cert paths
CERT_DIR="/etc/vpn-protocols/certs"
mkdir -p "$CERT_DIR"
CERT_PATH="${CERT_DIR}/cert.pem"
KEY_PATH="${CERT_DIR}/key.pem"

# Check if certificates are already issued and valid
CRAFT_SELF_SIGNED=false
if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    # Verify expiration (re-use if valid for > 7 days)
    if openssl x509 -checkend 604800 -noout -in "$CERT_PATH" >/dev/null 2>&1; then
        log_info "Обнаружен действующий TLS сертификат. Использование существующего."
        export TARGET_DOMAIN CERT_PATH KEY_PATH CRAFT_SELF_SIGNED
        exit 0
    fi
fi

# Install cron, standalone acme.sh tool
if [ "$PKG_MANAGER" = "apt" ]; then
    pkg_install cron socat curl || true
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pkg_install cronie socat curl || true
elif [ "$PKG_MANAGER" = "apk" ]; then
    pkg_install dcron socat curl || true
else
    pkg_install cronie crontabs socat curl || true
fi

# Enable and start cron
if command -v systemctl >/dev/null; then
    systemctl enable cron || systemctl enable cronie || true
    systemctl start cron || systemctl start cronie || true
fi

# Install acme.sh
ACME_HOME="/root/.acme.sh"
if [ ! -d "$ACME_HOME" ]; then
    log_info "Установка acme.sh..."
    curl -sSL https://get.acme.sh | sh -s email="$EMAIL" || true
fi

# Try issuing certificate
ACME_BIN="${ACME_HOME}/acme.sh"
SUCCESS_TLS=false

# Close port 80 if held by Caddy or panel
systemctl stop caddy || true
systemctl stop vpn-panel || true

# Try issuing cert
if [ -x "$ACME_BIN" ]; then
    log_info "Запрос TLS-сертификата Let's Encrypt через acme.sh..."
    
    # Register Let's Encrypt account
    "$ACME_BIN" --register-account -m "$EMAIL" --server letsencrypt || true
    
    if [ -n "$CF_TOKEN" ] && [ "$IS_WILDCARD_DNS" = "false" ]; then
        log_info "Использование Cloudflare DNS-01 API для выпуска..."
        export CF_Token="$CF_TOKEN"
        if "$ACME_BIN" --issue --dns dns_cf -d "$TARGET_DOMAIN" --server letsencrypt --force; then
            SUCCESS_TLS=true
        fi
    else
        log_info "Использование HTTP-01 Standalone вызова..."
        # Try HTTP-01 (port 80 must be open)
        if "$ACME_BIN" --issue --standalone -d "$TARGET_DOMAIN" --server letsencrypt --force; then
            SUCCESS_TLS=true
        fi
    fi
fi

if [ "$SUCCESS_TLS" = "true" ]; then
    log_info "Установка сертификата..."
    "$ACME_BIN" --install-cert -d "$TARGET_DOMAIN" \
        --key-file "$KEY_PATH" \
        --fullchain-file "$CERT_PATH" \
        --reloadcmd "systemctl reload caddy || true" || true
    log_info "Сертификат Let's Encrypt успешно получен и сохранен."
else
    log_warn "Не удалось выпустить сертификат Let's Encrypt. Fallback на самоподписанный (self-signed)."
    CRAFT_SELF_SIGNED=true
    
    # Generate self-signed certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_PATH" \
        -out "$CERT_PATH" \
        -subj "/CN=${TARGET_DOMAIN}/O=VPN Server/C=US" >/dev/null 2>&1
    log_warn "Создан самоподписанный TLS-сертификат."
fi

# Export parameters
export TARGET_DOMAIN CERT_PATH KEY_PATH CRAFT_SELF_SIGNED
