#!/usr/bin/env bash
set -euo pipefail

# Import preflight logger helpers
. "$(dirname "$0")/modules/preflight.sh"

VIRT=$(systemd-detect-virt || echo "none")

if [ "$VIRT" = "openvz" ] || [ "$VIRT" = "lxc" ] || [ "$VIRT" = "container" ]; then
    log_warn "Контейнерная виртуализация ($VIRT). Пропуск системного sysctl тюнинга."
    exit 0
fi

log_info "Применение системных настроек сети и тюнинга..."

# Time Synchronization & Chrony
pkg_install chrony || true
if command -v systemctl >/dev/null; then
    systemctl enable --now chrony || true
fi
# Set timezone to UTC
timedatectl set-timezone UTC || true
log_info "Время синхронизировано, часовой пояс установлен в UTC."

# BBR Congestion Control
BBR_VERSION="cubic"
if modprobe tcp_bbr >/dev/null 2>&1; then
    BBR_VERSION="bbr"
    log_info "Модуль BBR доступен в ядре."
else
    log_warn "Ядро не поддерживает BBR, используется Cubic."
fi

# Detect RAM size to apply tier
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))

SYSCTL_CONF="/etc/sysctl.d/99-vpn-tune.conf"
rm -f "$SYSCTL_CONF"

# Base parameters
cat <<EOF > "$SYSCTL_CONF"
# VPN Server Optimizations
vm.swappiness = 10
net.ipv4.tcp_fastopen = 3
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = $BBR_VERSION
EOF

if [ "$TOTAL_RAM_MB" -lt 1500 ]; then
    log_info "Применен профиль Tier 1 (Low RAM < 1.5 GB)"
    cat <<EOF >> "$SYSCTL_CONF"
# Tier 1 Networking
net.core.rmem_max = 2097152
net.core.wmem_max = 2097152
net.ipv4.tcp_rmem = 4096 87380 2097152
net.ipv4.tcp_wmem = 4096 65536 2097152
net.ipv4.tcp_mem = 12288 16384 24576
net.core.somaxconn = 256
net.ipv4.tcp_max_syn_backlog = 512
EOF
elif [ "$TOTAL_RAM_MB" -lt 4000 ]; then
    log_info "Применен профиль Tier 2 (Mid RAM 1.5 GB - 4 GB)"
    cat <<EOF >> "$SYSCTL_CONF"
# Tier 2 Networking
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 65536 8388608
net.ipv4.tcp_mem = 49152 65536 98304
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 2048
EOF
else
    log_info "Применен профиль Tier 3 (High RAM > 4 GB)"
    cat <<EOF >> "$SYSCTL_CONF"
# Tier 3 Networking
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem = 98304 131072 196608
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
EOF
fi

# Load sysctl settings
sysctl -p "$SYSCTL_CONF" || true
log_info "Параметры sysctl успешно применены."

# DNS Hardening (DNS Over TLS via systemd-resolved)
if [ -d /etc/systemd/resolved.conf.d ] || [ -f /etc/systemd/resolved.conf ]; then
    log_info "Настройка DNS-over-TLS (DoT) на сервере через systemd-resolved..."
    mkdir -p /etc/systemd/resolved.conf.d
    cat <<EOF > /etc/systemd/resolved.conf.d/dot.conf
[Resolve]
DNS=1.1.1.1 8.8.8.8 2606:4700:4700::1111 2001:4860:4860::8888
DNSOverTLS=yes
EOF
    systemctl restart systemd-resolved || true
fi
