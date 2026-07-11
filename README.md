# Auto-VPN Multi-Protocol Installer & Management Panel

[English](#english) | [Русский](#русский)

---

## English

A production-grade, highly secure bash script that configures a complete, multi-protocol VPN server on a fresh Linux VPS, accompanied by a lightweight Go management panel with real-time analytics, and user-space Cloudflare WARP routing.

### Key Features

1. **4 Modern VPN Protocols Built-in**:
   - **Hysteria 2**: Dynamic UDP-based protocol resistant to bandwidth throttling.
   - **Mieru**: Obfuscated TCP/UDP protocol utilizing custom traffic patterns.
   - **AnyTLS**: TLS-wrapped proxy addressing nested TLS-in-TLS fingerprinting.
   - **NaiveProxy**: Chromium network stack camouflage (powered by a custom Caddy build).

2. **Go-Based Unified Management Panel**:
   - Zero heavy Python/pip dependencies.
   - Real-time SVG metrics dashboard (CPU, RAM, Swap, Disk).
   - Live traffic stats and history charts (network bandwidth, protocol breakdown).
   - In-memory rate limiting and fail2ban jails protecting the admin portal from brute-force scanning.
   - Forced password reset loop on initial login.

3. **Symmetric Userspace WARP Routing**:
   - Runs Cloudflare WARP completely in userspace inside `sing-box` to avoid kernel/virtualization restrictions (fully compatible with OpenVZ and LXC).
   - Uses policy routing rules on the VPS to prevent SSH dropouts when routing outbound traffic.
   - Dynamic DNS-over-TLS (DoT) setup using systemd-resolved to prevent server-side DNS leak fingerprinting.

4. **Multi-Client Subscription Generation**:
   - **Clash Verge Rev (Mihomo Core) Link**: Natively configures Hysteria2, Mieru, and AnyTLS.
   - **sing-box / NekoBox Link**: Configures all 4 protocols natively, including NaiveProxy.

### Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/owner/vpn-installer/main/install.sh | sudo bash
```

---

## Русский

Автоматизированный bash-скрипт промышленного уровня для полной настройки многопротокольного VPN-сервера на чистой виртуальной машине Linux (VPS), снабженный легковесной веб-панелью управления на Go с живой аналитикой и встроенным туннелированием Cloudflare WARP в пространстве пользователя.

### Основные возможности

1. **4 Современных VPN Протокола**:
   - **Hysteria 2**: Динамический протокол на базе UDP, устойчивый к троттлингу провайдеров.
   - **Mieru**: Обфусцированный TCP/UDP протокол с маскировкой трафика.
   - **AnyTLS**: Протокол, скрывающий отпечатки TLS-в-TLS (TLS in TLS).
   - **NaiveProxy**: Маскировка под стек Chromium на базе веб-сервера Caddy.

2. **Панель управления на Go**:
   - Отсутствие тяжелых зависимостей (Python, pip, venv).
   - Отображение системных ресурсов (CPU, RAM, Swap, Disk) в реальном времени.
   - Интерактивный график трафика и статистика по каждому протоколу.
   - Защита от подбора паролей: встроенный rate-limiter + кастомные фильтры fail2ban на уровне сетевого экрана.
   - Блокирующий экран принудительной смены пароля `admin` при первом входе.

3. **Маршрутизация WARP в Userspace**:
   - WARP запускается полностью в пространстве пользователя с помощью `sing-box`, снимая зависимость от модулей ядра WireGuard (полная совместимость с OpenVZ и LXC).
   - Симметричная маршрутизация предотвращает обрыв SSH-подключения при активации туннеля.
   - Безопасный DNS-over-TLS (DoT) системный резолвер через `systemd-resolved` для защиты от DNS-блокировок.

4. **Генерация подписок**:
   - **Clash Verge Rev (ядро Mihomo)**: Hysteria2, Mieru, AnyTLS.
   - **sing-box / NekoBox**: Все 4 протокола нативно, включая NaiveProxy.

### Быстрый запуск

Выполните команду на чистом VPS (поддерживаются Ubuntu, Debian, CentOS, AlmaLinux, Rocky, Fedora, Arch Linux):

```bash
curl -sSL https://raw.githubusercontent.com/owner/vpn-installer/main/install.sh | sudo bash
```

### Архитектурные решения

* **Идемпотентность**: Повторный запуск скрипта `install.sh` не ломает уже настроенные протоколы и обновляет только необходимые конфигурационные блоки.
* **Тюнинг системы**: Сетевые буферы масштабируются в зависимости от объема оперативной памяти сервера (профили Tier 1/2/3).
* **Безопасность сессий**: Сессионные куки Go-панели защищены флагами `Secure`, `HttpOnly` и `SameSite=Strict`.
* **Zero Telemetry**: Полное отсутствие фонового сбора данных или «звонков домой».

### Удаление сервера

Для полной очистки системы и отката всех изменений запустите скрипт:

```bash
sudo bash uninstall.sh
```
