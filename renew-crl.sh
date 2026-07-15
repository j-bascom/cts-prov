#!/bin/bash
# Regenerate the Easy-RSA CRL and reload OpenVPN.
# Run weekly via cron — CRL expires after 180 days by default.
set -euo pipefail

EASYRSA=/etc/openvpn/easy-rsa/easyrsa
PKI_DIR=/etc/openvpn/easy-rsa/pki
CRL_DEST=/etc/openvpn/server/crl.pem

cd /etc/openvpn/easy-rsa
"$EASYRSA" gen-crl

cp "$PKI_DIR/crl.pem" "$CRL_DEST"
chmod 644 "$CRL_DEST"

systemctl kill --signal=SIGHUP openvpn-server@server

EXPIRY=$(openssl crl -in "$CRL_DEST" -noout -nextupdate 2>/dev/null)
echo "$(date): CRL renewed. $EXPIRY"
