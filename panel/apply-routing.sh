#!/usr/bin/env bash
set -euo pipefail

SETTINGS_FILE="/etc/vpn-protocols/panel-settings.json"
WARP_CREDS="/etc/vpn-protocols/warp-credentials.json"
SINGBOX_CONFIG="/etc/vpn-protocols/singbox-server.json"

if [ ! -f "$SETTINGS_FILE" ]; then
    echo "Settings file not found!" >&2
    exit 1
fi

# Parse settings
WARP_GLOBAL=$(jq -r '.warp_global' "$SETTINGS_FILE")
DIRECT_LIST=$(jq -r '.direct_list' "$SETTINGS_FILE")
WARP_LIST=$(jq -r '.warp_list' "$SETTINGS_FILE")
PANEL_PORT=$(jq -r '.port' "$SETTINGS_FILE")

# Check if WARP credentials exist
HAS_WARP=false
WARP_IP_V4="172.16.0.2/32"
WARP_IP_V6="2606:4700:110::/128"
WARP_PRIV_KEY=""
WARP_RESERVED="[0,0,0]"

if [ -f "$WARP_CREDS" ]; then
    HAS_WARP=true
    WARP_IP_V4=$(jq -r '.local_address_v4' "$WARP_CREDS")
    WARP_IP_V6=$(jq -r '.local_address_v6' "$WARP_CREDS")
    WARP_PRIV_KEY=$(jq -r '.private_key' "$WARP_CREDS")
    WARP_RESERVED=$(jq -c '.reserved' "$WARP_CREDS")
fi

# Convert domain lists to JSON arrays
make_json_array() {
    local input="$1"
    echo "$input" | grep -v '^#' | grep -v '^[[:space:]]*$' | jq -R . | jq -s .
}

DIRECT_DOMAINS_JSON=$(make_json_array "$DIRECT_LIST")
WARP_DOMAINS_JSON=$(make_json_array "$WARP_LIST")

# Build sing-box configuration
DEFAULT_OUTBOUND="direct"
if [ "$WARP_GLOBAL" = "true" ] && [ "$HAS_WARP" = "true" ]; then
    DEFAULT_OUTBOUND="warp"
fi

# Write config json
cat <<EOF > "$SINGBOX_CONFIG"
{
  "log": {
    "level": "info",
    "output": "/var/log/singbox-server.log"
  },
  "dns": {
    "servers": [
      {
        "tag": "cloudflare",
        "address": "https://1.1.1.1/dns-query"
      },
      {
        "tag": "local",
        "address": "local",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "direct",
        "domain_suffix": [
          "sslip.io",
          "nip.io",
          "traefik.me"
        ]
      }
    ]
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "singtun0",
      "address": [
        "172.19.0.1/30",
        "fdfe:dcba:9876::1/126"
      ],
      "auto_route": true,
      "strict_route": true,
      "stack": "system",
      "sniff": true
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
EOF

if [ "$HAS_WARP" = "true" ]; then
    cat <<EOF >> "$SINGBOX_CONFIG"
    ,{
      "type": "wireguard",
      "tag": "warp",
      "server": "engage.cloudflareclient.com",
      "server_port": 2408,
      "system_interface": false,
      "local_address": [
        "$WARP_IP_V4",
        "$WARP_IP_V6"
      ],
      "private_key": "$WARP_PRIV_KEY",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": $WARP_RESERVED,
      "mtu": 1280
    }
EOF
fi

cat <<EOF >> "$SINGBOX_CONFIG"
  ],
  "route": {
    "rules": [
      {
        "port": 22,
        "outbound": "direct"
      },
      {
        "port": $PANEL_PORT,
        "outbound": "direct"
      },
      {
        "domain_suffix": $DIRECT_DOMAINS_JSON,
        "outbound": "direct"
      }
EOF

if [ "$HAS_WARP" = "true" ]; then
    cat <<EOF >> "$SINGBOX_CONFIG"
      ,{
        "domain_suffix": $WARP_DOMAINS_JSON,
        "outbound": "warp"
      }
EOF
fi

cat <<EOF >> "$SINGBOX_CONFIG"
      ,{
        "geoip": [
          "ru",
          "private"
        ],
        "outbound": "direct"
      },
      {
        "outbound": "$DEFAULT_OUTBOUND"
      }
    ]
  }
}
EOF

# Restart singbox-server if it is running / enabled
if systemctl is-active --quiet singbox-server; then
    systemctl restart singbox-server
fi
