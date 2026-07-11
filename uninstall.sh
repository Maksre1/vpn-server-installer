#!/usr/bin/env bash
set -eo pipefail

# Logger helpers
log_info() {
    echo -e "\033[32m[INFO]\033[0m $1"
}
log_warn() {
    echo -e "\033[33m[WARN]\033[0m $1"
}
log_err() {
    echo -e "\033[31m[ERROR]\033[0m $1" >&2
}

if [ "$(id -u)" -ne 0 ]; then
    log_err "Этот скрипт должен быть запущен с правами root."
    exit 1
fi

log_warn "ВНИМАНИЕ! Этот скрипт полностью удалит VPN-сервер, все конфигурации и учетные данные."
read -p "Вы уверены, что хотите продолжить? (y/n, по умолчанию n): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    log_info "Удаление отменено."
    exit 0
fi

# 1. Stop and disable systemd services
log_info "Остановка и отключение системных служб..."
for svc in vpn-panel singbox-server caddy anytls-server mita hysteria2; do
    if systemctl is-active --quiet "$svc" || systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        log_info "Остановка службы $svc..."
        systemctl stop "$svc" || true
        systemctl disable "$svc" || true
    fi
done

# 2. Delete systemd service files
log_info "Удаление файлов служб..."
rm -f /etc/systemd/system/vpn-panel.service
rm -f /etc/systemd/system/singbox-server.service
rm -f /etc/systemd/system/caddy.service
rm -f /etc/systemd/system/anytls-server.service
rm -f /etc/systemd/system/mita.service
rm -f /etc/systemd/system/hysteria2.service
systemctl daemon-reload

# 3. Delete binaries
log_info "Удаление исполняемых файлов..."
rm -f /usr/local/bin/vpn-panel
rm -f /usr/local/bin/sing-box
rm -f /usr/local/bin/caddy
rm -f /usr/local/bin/anytls-server
rm -f /usr/local/bin/mita
rm -f /usr/local/bin/hysteria
rm -f /usr/local/bin/wgcf

# 4. Delete configuration directories
log_info "Удаление конфигурационных файлов и логов..."
rm -rf /etc/vpn-protocols
rm -rf /opt/vpn-panel
rm -f /var/log/vpn-panel-auth.log
rm -f /var/log/vpn-installer.log
rm -f /var/log/singbox-server.log

# 5. Revert sysctl configurations
log_info "Сброс сетевого тюнинга sysctl..."
if [ -f /etc/sysctl.d/99-vpn-tune.conf ]; then
    rm -f /etc/sysctl.d/99-vpn-tune.conf
    # Reload sysctl default settings
    sysctl --system || true
fi

# 6. Revert DNS-over-TLS (resolved)
log_info "Сброс настроек DNS-over-TLS..."
if [ -f /etc/systemd/resolved.conf.d/dot.conf ]; then
    rm -f /etc/systemd/resolved.conf.d/dot.conf
    systemctl restart systemd-resolved || true
fi

# 7. Revert Fail2ban
log_info "Сброс настроек Fail2ban..."
rm -f /etc/fail2ban/filter.d/vpn-panel.conf
rm -f /etc/fail2ban/jail.d/vpn-panel.conf
if systemctl is-active --quiet fail2ban; then
    systemctl restart fail2ban || true
fi

# 8. Revert iptables traffic accounting rules
log_info "Удаление правил брандмауэра..."
# Flush or delete accounting rules by clearing INPUT/OUTPUT rules matching specific descriptions
# Or we can just restart the firewall service if ufw or firewalld is active
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw reload >/dev/null || true
elif command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
    firewall-cmd --reload >/dev/null || true
fi

# Clear iptables rules
if command -v iptables >/dev/null; then
    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200 >/dev/null 2>&1 || true
fi
if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save || true
fi
if command -v iptables-save >/dev/null && command -v iptables-restore >/dev/null; then
    iptables-save | grep -v "vpn-panel" | iptables-restore || true
fi

# Clear temporary installer files
rm -rf /tmp/go.tar.gz /tmp/go_home /tmp/gopath /tmp/vpn-installer-* /tmp/singbox.tar.gz /tmp/mita.tar.gz /tmp/anytls.zip /tmp/anytls_bin /tmp/checksums.txt

log_info "Удаление успешно завершено."
