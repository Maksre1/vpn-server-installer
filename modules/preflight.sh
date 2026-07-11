#!/usr/bin/env bash
set -euo pipefail

# Logger helper
log_info() {
    echo -e "\033[32m[INFO]\033[0m $1"
}
log_warn() {
    echo -e "\033[33m[WARN]\033[0m $1"
}
log_err() {
    echo -e "\033[31m[ERROR]\033[0m $1" >&2
}

# 1. Require Root
if [ "$(id -u)" -ne 0 ]; then
    log_err "Этот скрипт должен быть запущен с правами root (sudo)."
    exit 1
fi

# 2. Systemd Check
if ! pidof systemd >/dev/null && [ ! -d /run/systemd/system ]; then
    log_err "Инициализация systemd не обнаружена. Скрипт требует systemd для управления сервисами."
    exit 1
fi

# 3. Detect Package Manager
PKG_MANAGER=""
if command -v apt-get >/dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf >/dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum >/dev/null; then
    PKG_MANAGER="yum"
elif command -v pacman >/dev/null; then
    PKG_MANAGER="pacman"
elif command -v apk >/dev/null; then
    PKG_MANAGER="apk"
else
    log_err "Не удалось определить поддерживаемый пакетный менеджер (apt/dnf/yum/pacman/apk)."
    exit 1
fi

log_info "Обнаружен пакетный менеджер: $PKG_MANAGER"

# Wrapper functions
pkg_update() {
    log_info "Обновление кэша пакетов..."
    case "$PKG_MANAGER" in
        apt) apt-get update -y ;;
        dnf) dnf makecache -y ;;
        yum) yum makecache -y ;;
        pacman) pacman -Sy ;;
        apk) apk update ;;
    esac
}

pkg_install() {
    local pkgs=("$@")
    log_info "Установка пакетов: ${pkgs[*]}"
    local success=false
    for i in {1..20}; do
        case "$PKG_MANAGER" in
            apt)
                DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" && success=true || true
                ;;
            dnf)
                dnf install -y "${pkgs[@]}" && success=true || true
                ;;
            yum)
                yum install -y "${pkgs[@]}" && success=true || true
                ;;
            pacman)
                pacman -S --noconfirm --needed "${pkgs[@]}" && success=true || true
                ;;
            apk)
                apk add "${pkgs[@]}" && success=true || true
                ;;
        esac
        if [ "$success" = "true" ]; then
            break
        fi
        log_warn "Пакетный менеджер занят или произошла ошибка. Повтор через 5 секунд (попытка $i/20)..."
        sleep 5
    done
    if [ "$success" != "true" ]; then
        log_err "Не удалось установить пакеты: ${pkgs[*]}"
        exit 1
    fi
}

pkg_remove() {
    local pkgs=("$@")
    log_info "Удаление пакетов: ${pkgs[*]}"
    case "$PKG_MANAGER" in
        apt) apt-get remove -y "${pkgs[@]}" ;;
        dnf) dnf remove -y "${pkgs[@]}" ;;
        yum) yum remove -y "${pkgs[@]}" ;;
        pacman) pacman -Rns --noconfirm "${pkgs[@]}" ;;
        apk) apk del "${pkgs[@]}" ;;
    esac
}

# 4. Architecture Detection
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH_TYPE="amd64"
        ;;
    aarch64|arm64)
        ARCH_TYPE="arm64"
        ;;
    *)
        log_err "Неподдерживаемая архитектура процессора: $ARCH."
        exit 1
        ;;
esac
log_info "Архитектура процессора: $ARCH_TYPE"

# 5. Check Disk Space (>= 1.5 GB on /)
FREE_KB=$(df -P / | awk 'NR==2 {print $4}')
FREE_GB=$((FREE_KB / 1024 / 1024))
log_info "Свободное место на диске: ${FREE_GB} GB"
if [ "$FREE_GB" -lt 2 ]; then
    log_err "Недостаточно места на диске. Требуется минимум 1.5 GB свободного пространства."
    exit 1
fi

# 6. Check Entropy
if [ -f /proc/sys/kernel/random/entropy_avail ]; then
    ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail)
    log_info "Доступная энтропия ядра: $ENTROPY"
    if [ "$ENTROPY" -lt 1000 ]; then
        log_warn "Низкий уровень энтропии. Установка haveged/rng-tools для ускорения генерации криптоключей."
        case "$PKG_MANAGER" in
            apt) pkg_install haveged || true ;;
            dnf|yum) pkg_install haveged || true ;;
            pacman) pkg_install haveged || true ;;
            apk) pkg_install haveged || true ;;
        esac
        if command -v systemctl >/dev/null; then
            systemctl enable --now haveged || true
        fi
    fi
fi

# 7. RAM & Swap Diagnostics
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
log_info "Всего оперативной памяти (RAM): ${TOTAL_RAM_MB} MB"

# Check if swap is active
SWAP_ACTIVE=false
if [ "$(grep -c -v '^Filename' /proc/swaps)" -gt 0 ]; then
    SWAP_ACTIVE=true
fi

if [ "$SWAP_ACTIVE" = "true" ]; then
    log_info "Файл/раздел подкачки (Swap) уже активен. Пропуск создания."
else
    # Create swap dynamically based on RAM
    SWAP_SIZE_GB=0
    if [ "$TOTAL_RAM_MB" -lt 1000 ]; then
        SWAP_SIZE_GB=2
    elif [ "$TOTAL_RAM_MB" -lt 1500 ]; then
        SWAP_SIZE_GB=1
    fi

    if [ "$SWAP_SIZE_GB" -gt 0 ]; then
        log_info "Создание файла подкачки (Swap) размером ${SWAP_SIZE_GB} GB..."
        # Allocate space
        fallocate -l "${SWAP_SIZE_GB}G" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_SIZE_GB * 1024))
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        # Persist swap
        if ! grep -q '/swapfile' /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        log_info "Swap файл создан и подключен."
    fi
fi

# Export shared variables for subsequent modules
export ARCH_TYPE PKG_MANAGER
