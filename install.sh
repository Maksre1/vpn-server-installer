#!/usr/bin/env bash
set -eo pipefail

# Redirect all stdout/stderr to log file, while keeping output on console
LOG_FILE="/var/log/vpn-installer.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

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

clear
echo -e "\033[35m"
echo "============================================="
echo "       VPN MULTI-PROTOCOL SERVER INSTALLER   "
echo "============================================="
echo -e "\033[0m"

# Auto / Manual selection with 10-second timeout
MODE=""
echo "Выберите режим установки:"
echo "1) Auto   (Ноль вопросов, всё под ключ, по умолчанию через 10 сек)"
echo "2) Manual (Выборочная настройка протоколов, домена, SSH, WARP)"
echo

read -t 10 -p "Введите номер режима [1-2, по умолчанию Auto]: " input_mode || input_mode="1"

if [ "$input_mode" = "2" ]; then
    MODE="manual"
    log_info "Выбран ручной режим установки (Manual)."
else
    MODE="auto"
    log_info "Выбран автоматический режим установки (Auto)."
fi

# Initialize installation variables
INSTALL_HYSTERIA=true
INSTALL_MIERU=true
INSTALL_ANYTLS=true
INSTALL_NAIVE=true

DOMAIN=""
CF_TOKEN=""
WARP_MODE=1  # 1 = Global, 2 = Selective, 3 = Disabled
PANEL_PORT=8080
SSH_PORT=22
DISABLE_SSH_PWD_AUTH=false

if [ "$MODE" = "manual" ]; then
    # 1. Custom Domain Options
    echo
    echo "=== Настройка домена и TLS ==="
    echo "1) Использовать бесплатный автоматический wildcard-DNS (sslip.io)"
    echo "2) Использовать собственный домен"
    read -p "Выберите опцию [1-2, по умолчанию 1]: " domain_choice
    if [ "$domain_choice" = "2" ]; then
        read -p "Введите ваш домен (например, vpn.my-server.com): " DOMAIN
        read -p "Использовать API Cloudflare для DNS-01 проверки? (y/n, по умолчанию n): " use_cf
        if [ "$use_cf" = "y" ] || [ "$use_cf" = "Y" ]; then
            read -p "Введите Cloudflare API Token: " CF_TOKEN
        fi
    fi

    # 2. Protocol selections
    echo
    echo "=== Выбор устанавливаемых протоколов ==="
    read -p "Установить Hysteria 2? (y/n, по умолчанию y): " inst_h
    if [ "$inst_h" = "n" ] || [ "$inst_h" = "N" ]; then INSTALL_HYSTERIA=false; fi

    read -p "Установить Mieru? (y/n, по умолчанию y): " inst_m
    if [ "$inst_m" = "n" ] || [ "$inst_m" = "N" ]; then INSTALL_MIERU=false; fi

    read -p "Установить AnyTLS? (y/n, по умолчанию y): " inst_a
    if [ "$inst_a" = "n" ] || [ "$inst_a" = "N" ]; then INSTALL_ANYTLS=false; fi

    read -p "Установить NaiveProxy? (y/n, по умолчанию y): " inst_n
    if [ "$inst_n" = "n" ] || [ "$inst_n" = "N" ]; then INSTALL_NAIVE=false; fi

    # 3. WARP configuration
    echo
    echo "=== Настройка туннелирования WARP ==="
    echo "1) Весь трафик VPS направлять через WARP (по умолчанию)"
    echo "2) Направлять только выбранные заблокированные домены через WARP"
    echo "3) Не использовать WARP"
    read -p "Выберите опцию [1-3, по умолчанию 1]: " warp_choice
    if [ "$warp_choice" = "2" ]; then
        WARP_MODE=2
    elif [ "$warp_choice" = "3" ]; then
        WARP_MODE=3
    fi

    # 4. Web panel configurations
    echo
    echo "=== Настройка веб-панели управления ==="
    read -p "Введите порт веб-панели [по умолчанию 8080]: " custom_panel_port
    if [ -n "$custom_panel_port" ]; then
        PANEL_PORT="$custom_panel_port"
    fi

    # 5. SSH Hardening
    echo
    echo "=== Безопасность и SSH-хардинг ==="
    read -p "Хотите изменить стандартный порт SSH (22)? (y/n, по умолчанию n): " change_ssh
    if [ "$change_ssh" = "y" ] || [ "$change_ssh" = "Y" ]; then
        read -p "Введите новый порт SSH: " custom_ssh_port
        if [ -n "$custom_ssh_port" ]; then
            SSH_PORT="$custom_ssh_port"
        fi
    fi

    read -p "Хотите отключить вход по паролю по SSH (только по ключам)? (y/n, по умолчанию n): " disable_pwd
    if [ "$disable_pwd" = "y" ] || [ "$disable_pwd" = "Y" ]; then
        log_warn "УБЕДИТЕСЬ, ЧТО У ВАС НАСТРОЕНЫ SSH-КЛЮЧИ, ИНАЧЕ ВЫ ПОТЕРЯЕТЕ ДОСТУП К СЕРВЕРУ!"
        read -p "Вы уверены, что хотите отключить авторизацию по паролю? (y/n, по умолчанию n): " confirm_disable
        if [ "$confirm_disable" = "y" ] || [ "$confirm_disable" = "Y" ]; then
            DISABLE_SSH_PWD_AUTH=true
        fi
    fi
fi

# Run Pre-flights
log_info "Запуск пре-флайт проверок..."
. "$(dirname "$0")/modules/preflight.sh"

# Run System Tuning
log_info "Настройка и оптимизация сетевого стека..."
. "$(dirname "$0")/modules/system-tune.sh"

# Run Domain and TLS Check
log_info "Настройка домена и выпуск сертификата..."
export DOMAIN CF_TOKEN
. "$(dirname "$0")/modules/domain-tls.sh"

# Setup protocol services
export CERT_PATH KEY_PATH CRAFT_SELF_SIGNED

if [ "$INSTALL_HYSTERIA" = "true" ]; then
    log_info "Установка Hysteria 2..."
    . "$(dirname "$0")/modules/hysteria2-setup.sh"
else
    export HYSTERIA_PORT=0 HYSTERIA_PASSWORD=""
fi

if [ "$INSTALL_MIERU" = "true" ]; then
    log_info "Установка Mieru..."
    . "$(dirname "$0")/modules/mieru-setup.sh"
else
    export MIERU_PORT=0 MIERU_USER="" MIERU_PASSWORD=""
fi

if [ "$INSTALL_ANYTLS" = "true" ]; then
    log_info "Установка AnyTLS..."
    . "$(dirname "$0")/modules/anytls-setup.sh"
else
    export ANYTLS_PORT=0 ANYTLS_PASSWORD=""
fi

if [ "$INSTALL_NAIVE" = "true" ]; then
    log_info "Установка NaiveProxy..."
    . "$(dirname "$0")/modules/naiveproxy-setup.sh"
else
    export NAIVE_PORT=0 NAIVE_USER="" NAIVE_PASSWORD=""
fi

# Setup WARP account and keys
log_info "Установка Cloudflare WARP..."
export WARP_MODE
. "$(dirname "$0")/modules/warp-setup.sh"

# Setup firewall and fail2ban rules
log_info "Настройка портов и брандмауэра..."
export PANEL_PORT SSH_PORT
. "$(dirname "$0")/modules/firewall.sh"

# Setup SSH Hardening (if manual options applied)
if [ "$MODE" = "manual" ]; then
    if [ "$SSH_PORT" -ne 22 ]; then
        log_info "Изменение SSH порта на $SSH_PORT..."
        sed -i -E "s/^#?Port[[:space:]]+[0-9]+/Port $SSH_PORT/" /etc/ssh/sshd_config
        systemctl restart sshd || systemctl restart ssh || true
    fi
    if [ "$DISABLE_SSH_PWD_AUTH" = "true" ]; then
        log_info "Отключение входа по SSH по паролю..."
        sed -i -E "s/^#?PasswordAuthentication[[:space:]]+yes/PasswordAuthentication no/" /etc/ssh/sshd_config
        sed -i -E "s/^#?PasswordAuthentication[[:space:]]+no/PasswordAuthentication no/" /etc/ssh/sshd_config
        systemctl restart sshd || systemctl restart ssh || true
    fi
fi

# Run Web panel installation
log_info "Установка веб-панели управления..."
export PANEL_PORT TARGET_DOMAIN PUBLIC_IP CERT_PATH KEY_PATH CRAFT_SELF_SIGNED
. "$(dirname "$0")/modules/panel-setup.sh"

# Log and Output final credentials
ACCESS_FILE="/etc/vpn-protocols/access.txt"
cat <<EOF > "$ACCESS_FILE"
============================================================
              VPN СЕРВЕР УСПЕШНО НАСТРОЕН
============================================================
Панель управления: https://${TARGET_DOMAIN}:${PANEL_PORT}/
Логин: admin
Пароль: admin (обязательно сменить при первом входе)

Ссылки на подписки клиентов:
1) Clash Verge (mihomo core) [Hysteria2, Mieru, AnyTLS]:
   https://${TARGET_DOMAIN}:${PANEL_PORT}/sub/clash/${PANEL_TOKEN}

2) NekoBox / sing-box [Hysteria2, Mieru, AnyTLS, NaiveProxy]:
   https://${TARGET_DOMAIN}:${PANEL_PORT}/sub/singbox/${PANEL_TOKEN}

Статус сервисов:
- Hysteria 2: Активен (Порт UDP ${HYSTERIA_PORT:-})
- Mieru:      Активен (Порт TCP/UDP ${MIERU_PORT:-})
- AnyTLS:     Активен (Порт TCP ${ANYTLS_PORT:-})
- NaiveProxy: Активен (Порт TCP ${NAIVE_PORT:-})
- WARP:       Активен
============================================================
EOF

clear
cat "$ACCESS_FILE"
log_info "Лог установки сохранен в $LOG_FILE"
log_info "Данные доступа к панели сохранены в $ACCESS_FILE"
EOF
