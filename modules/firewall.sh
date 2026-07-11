#!/usr/bin/env bash
set -euo pipefail

. "$(dirname "$0")/preflight.sh"

PANEL_PORT="${PANEL_PORT:-8080}"
HYSTERIA_PORT="${HYSTERIA_PORT:-0}"
MIERU_PORT="${MIERU_PORT:-0}"
ANYTLS_PORT="${ANYTLS_PORT:-0}"
NAIVE_PORT="${NAIVE_PORT:-0}"
SSH_PORT="${SSH_PORT:-22}"

log_info "Настройка портов брандмауэра и правил безопасности..."

# 1. Open Ports (UFW / Firewalld / iptables)
open_port_tcp() {
    local port="$1"
    if [ "$port" -eq 0 ]; then return; fi
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$port"/tcp >/dev/null || true
    elif command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --zone=public --add-port="$port"/tcp --permanent >/dev/null || true
        firewall-cmd --reload >/dev/null || true
    else
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
    fi
}

open_port_udp() {
    local port="$1"
    if [ "$port" -eq 0 ]; then return; fi
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$port"/udp >/dev/null || true
    elif command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --zone=public --add-port="$port"/udp --permanent >/dev/null || true
        firewall-cmd --reload >/dev/null || true
    else
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
    fi
}

# Open all required ports
open_port_tcp "$SSH_PORT"
open_port_tcp "$PANEL_PORT"
open_port_udp "$HYSTERIA_PORT"
open_port_tcp "$MIERU_PORT"
open_port_udp "$MIERU_PORT"
open_port_tcp "$ANYTLS_PORT"
open_port_tcp "$NAIVE_PORT"

log_info "Порты успешно открыты в брандмауэре."

# 2. Add traffic accounting rules in iptables
add_accounting_rule() {
    local port="$1"
    local proto="$2"
    if [ "$port" -eq 0 ]; then return; fi
    
    # Check and insert rule at the top of INPUT chain
    if ! iptables -C INPUT -p "$proto" --dport "$port" >/dev/null 2>&1; then
        iptables -I INPUT 1 -p "$proto" --dport "$port" >/dev/null 2>&1 || true
    fi
    # Check and insert rule at the top of OUTPUT chain
    if ! iptables -C OUTPUT -p "$proto" --sport "$port" >/dev/null 2>&1; then
        iptables -I OUTPUT 1 -p "$proto" --sport "$port" >/dev/null 2>&1 || true
    fi
}

add_accounting_rule "$HYSTERIA_PORT" "udp"
add_accounting_rule "$MIERU_PORT" "tcp"
add_accounting_rule "$MIERU_PORT" "udp"
add_accounting_rule "$ANYTLS_PORT" "tcp"
add_accounting_rule "$NAIVE_PORT" "tcp"

log_info "Добавлены правила учета трафика портов."

# 3. Setup Fail2ban
log_info "Настройка Fail2ban для защиты панели и SSH..."
pkg_install fail2ban || true

# Write vpn-panel filter
cat <<EOF > /etc/fail2ban/filter.d/vpn-panel.conf
[Definition]
failregex = ^<HOST> - .* - User: .* - Event: LOGIN_FAILED
ignoreregex =
EOF

# Write vpn-panel jail
cat <<EOF > /etc/fail2ban/jail.d/vpn-panel.conf
[vpn-panel]
enabled = true
port = $PANEL_PORT
filter = vpn-panel
logpath = /var/log/vpn-panel-auth.log
maxretry = 5
bantime = 3600
findtime = 600
action = iptables-multiport[name=vpn-panel, port="$PANEL_PORT"]
EOF

# Enable and restart fail2ban
if command -v systemctl >/dev/null; then
    systemctl enable fail2ban || true
    systemctl restart fail2ban || true
    log_info "Fail2ban успешно перезапущен и настроен."
fi
EOF
