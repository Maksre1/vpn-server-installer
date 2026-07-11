#!/bin/bash
set -e

REPO_DIR="/root/vpn-server-installer"
echo "=== Starting VPN Panel Auto-Update ==="

# 1. Ensure git repo exists and pull latest
if [ ! -d "$REPO_DIR" ]; then
    echo "Error: Repo directory $REPO_DIR not found."
    exit 1
fi

cd "$REPO_DIR"
echo "Pulling latest code from GitHub..."
git fetch --all
git reset --hard origin/master

# 2. Ensure Go compiler is installed on the system
if ! command -v go &> /dev/null; then
    echo "Go compiler not found. Installing Go..."
    # Determine architecture
    ARCH=$(uname -m)
    GO_ARCH="amd64"
    if [ "$ARCH" = "aarch64" ]; then
        GO_ARCH="arm64"
    fi
    
    echo "Downloading Go for $GO_ARCH..."
    curl -L -s https://go.dev/dl/go1.22.5.linux-$GO_ARCH.tar.gz -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
fi

# Add Go to PATH for this session and profile
export PATH=$PATH:/usr/local/go/bin
if ! grep -q "/usr/local/go/bin" /root/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
fi

echo "Go version: $(go version)"

# 3. Compile Go Web Panel
echo "Compiling vpn-panel..."
cd "$REPO_DIR/panel"
go build -o /usr/local/bin/vpn-panel main.go

# 4. Copy templates and static files
echo "Copying assets..."
mkdir -p /opt/vpn-panel/templates /opt/vpn-panel/static
cp -r templates/* /opt/vpn-panel/templates/
cp -r static/* /opt/vpn-panel/static/

# 5. Restart service outside current cgroup in 1 second
echo "Scheduling vpn-panel restart in 1 second..."
systemd-run --on-active=1s systemctl restart vpn-panel

echo "=== VPN Panel Update Script Finished ==="
