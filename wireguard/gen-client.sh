#!/usr/bin/env bash
# gen-client.sh — Add a new WireGuard client to the running server
# Usage: ./gen-client.sh [name]
# Copied to /opt/cts-prov/wireguard-clients/ after installation.
# Run as root.

set -euo pipefail

[ "$EUID" -eq 0 ] || { echo "Run as root: sudo $0 $*"; exit 1; }
[ -f /etc/wireguard/server_public.key ] || { echo "WireGuard not installed."; exit 1; }

CLIENT_NAME="${1:-client}"
CLIENTS_DIR="/opt/cts-prov/wireguard-clients"

set -a; source /opt/cts-prov/.env; set +a
SERVER_PUBLIC=$(cat /etc/wireguard/server_public.key)
WG_PORT="${WG_PORT:-51820}"
WG_SUBNET="${WG_SUBNET:-10.9.0.0/24}"
WG_DNS_FMT=$(echo "${WG_DNS:-8.8.8.8,1.1.1.1}" | tr ',' ', ')

# Find the next available IP in the subnet
USED=$(grep -oP 'AllowedIPs = \K[\d.]+' /etc/wireguard/wg0.conf 2>/dev/null | sort -t. -k4 -n || true)
CLIENT_IP=""
for i in $(seq 2 253); do
    CANDIDATE=$(echo "$WG_SUBNET" | awk -F'[./]' -v n="$i" '{print $1"."$2"."$3"."n}')
    if ! echo "$USED" | grep -qxF "$CANDIDATE"; then
        CLIENT_IP="$CANDIDATE"
        break
    fi
done
[ -z "$CLIENT_IP" ] && { echo "ERROR: No free IPs remaining in $WG_SUBNET"; exit 1; }

# Unique directory for this client
CLIENT_DIR="$CLIENTS_DIR/$CLIENT_NAME"
[ -d "$CLIENT_DIR" ] && CLIENT_DIR="${CLIENT_DIR}-$(date +%s)"
mkdir -p "$CLIENT_DIR"

# Generate key pair
wg genkey | tee "$CLIENT_DIR/private.key" | wg pubkey > "$CLIENT_DIR/public.key"
chmod 600 "$CLIENT_DIR/private.key"
CLIENT_PRIVATE=$(cat "$CLIENT_DIR/private.key")
CLIENT_PUBLIC=$(cat "$CLIENT_DIR/public.key")

# Write client .conf
CONF_FILE="$CLIENT_DIR/$CLIENT_NAME.conf"
cat > "$CONF_FILE" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address    = $CLIENT_IP/32
DNS        = $WG_DNS_FMT

[Peer]
PublicKey  = $SERVER_PUBLIC
Endpoint   = ${VULTR_PUBLIC_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
chmod 600 "$CONF_FILE"

# Append peer to server config and add live (no restart needed)
cat >> /etc/wireguard/wg0.conf <<EOF

[Peer]
# $CLIENT_NAME
PublicKey  = $CLIENT_PUBLIC
AllowedIPs = $CLIENT_IP/32
EOF

wg set wg0 peer "$CLIENT_PUBLIC" allowed-ips "$CLIENT_IP/32"

echo "Client '$CLIENT_NAME' created:"
echo "  IP:     $CLIENT_IP"
echo "  Config: $CONF_FILE"
echo
echo "Transfer the .conf file to the device and import it into any WireGuard app."
