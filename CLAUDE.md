# CTS Provisioning Proxy — Claude Code Setup Guide

## What this project is

A FastAPI-based provisioning proxy running on a Vultr VPS (Ubuntu 26.04 LTS).
Yealink phones provisioned via YMCS are redirected here. This server:

1. Intercepts the phone's config request (by MAC address)
2. Fetches the real config from SkySwitch's provisioning server server-side
3. Generates a per-device OpenVPN cert (Easy-RSA) if one doesn't exist
4. Injects VPN settings into the SkySwitch config
5. Returns the merged config to the phone
6. Serves the vpn.tar.gz bundle the phone pulls to enable OpenVPN

After provisioning, phones connect OpenVPN to this same server, and all
SIP/RTP to SkySwitch is NATted through the VPS's public IP.

## Stack

- Ubuntu 26.04 LTS (Resolute Raccoon) — note: uses sudo-rs as default sudo
- Python 3.12 + FastAPI + uvicorn + httpx + python-dotenv
- Nginx (reverse proxy + TLS termination via certbot/Let's Encrypt)
- OpenVPN server (tun0, subnet 10.8.0.0/24)
- Easy-RSA 3.x for per-device cert generation
- SQLite via device_db.py (no ORM, raw sqlite3)
- systemd service for the FastAPI app

## Project layout

```
/opt/cts-prov/
├── CLAUDE.md               ← this file
├── main.py                 ← FastAPI app (provisioning + admin endpoints)
├── cert_engine.py          ← Easy-RSA async wrapper
├── config_merge.py         ← SkySwitch cfg intercept + VPN key injection
├── device_db.py            ← SQLite device registry
├── .env                    ← secrets and config (never commit)
├── .env.example            ← committed template
├── requirements.txt
├── deploy/
│   ├── cts-prov.service    ← systemd unit
│   └── nginx-cts-prov.conf ← nginx vhost
└── cache/                  ← runtime cache (gitignored)
    ├── certs/{mac}/        ← per-device cert + vpn.tar.gz
    ├── skyswitch/{mac}.cfg ← cached SkySwitch configs (1hr TTL)
    └── output/{mac}/       ← merged cfg output
```

## Environment variables (.env)

```
SKYSWITCH_PROV_URL=https://cfg.skyswitch.net   # SkySwitch provisioning base URL
VULTR_PUBLIC_IP=1.2.3.4                         # This server's public IP
PROV_DOMAIN=https://prov.example.com            # FQDN for this server (HTTPS)
ADMIN_TOKEN=<generate with: openssl rand -hex 32>
PKI_DIR=/etc/openvpn/easy-rsa/pki
EASYRSA_BIN=/etc/openvpn/easy-rsa/easyrsa
CACHE_DIR=/opt/cts-prov/cache
```

## Setup order (Claude Code should follow this exactly)

### 1. System packages
```bash
apt update && apt install -y \
  python3 python3-pip python3-venv \
  openvpn easy-rsa \
  nginx certbot python3-certbot-nginx \
  sqlite3 \
  iptables iptables-persistent
```

### 2. Easy-RSA CA init (one-time — skip if /etc/openvpn/easy-rsa/pki/ca.crt exists)
```bash
mkdir -p /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
cd /etc/openvpn/easy-rsa
./easyrsa init-pki
./easyrsa --batch build-ca nopass
```

### 3. OpenVPN server config
Write /etc/openvpn/server/server.conf (see deploy/server.conf template).
Generate DH params:
```bash
cd /etc/openvpn/easy-rsa && ./easyrsa gen-dh
cp pki/dh.pem /etc/openvpn/server/
cp pki/ca.crt /etc/openvpn/server/
# Generate server cert
./easyrsa --batch build-server-full server nopass
cp pki/issued/server.crt pki/private/server.key /etc/openvpn/server/
systemctl enable --now openvpn-server@server
```

### 4. iptables NAT
```bash
# Enable forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Masquerade VPN traffic — replace eth0 with actual interface if different
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Persist
netfilter-persistent save
```

Check the actual interface name first: `ip route | grep default` — on Vultr it's
often `enp1s0` or `eth0`. Substitute correctly.

### 5. Python app
```bash
mkdir -p /opt/cts-prov
cd /opt/cts-prov
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn httpx python-dotenv
```
Copy all .py files and .env to /opt/cts-prov/.

### 6. Nginx + TLS
- Copy deploy/nginx-cts-prov.conf to /etc/nginx/sites-available/cts-prov
- Enable: ln -s /etc/nginx/sites-available/cts-prov /etc/nginx/sites-enabled/
- Run certbot: `certbot --nginx -d prov.example.com`
- nginx reload

### 7. systemd service
```bash
cp deploy/cts-prov.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cts-prov
```

### 8. Firewall (ufw or iptables)
Open: 22 (SSH), 80 (certbot), 443 (HTTPS prov), 1194/udp (OpenVPN)

## Verification checks Claude Code should run after setup

```bash
# OpenVPN running?
systemctl is-active openvpn-server@server

# FastAPI running?
systemctl is-active cts-prov
curl -s http://127.0.0.1:8000/docs | grep -q "FastAPI" && echo "API OK"

# Nginx forwarding?
curl -sk https://localhost/provision/aabbccdd1122 | head -5

# iptables NAT rule present?
iptables -t nat -L POSTROUTING -n | grep 10.8.0.0

# Easy-RSA PKI initialized?
test -f /etc/openvpn/easy-rsa/pki/ca.crt && echo "CA OK"
```

## Important notes for Claude Code

- The app runs as root (needed for Easy-RSA cert generation). Acceptable
  for a single-purpose VPS; tighten with sudo rules if desired later.
- /opt/cts-prov/cache/ is runtime state — do not delete between deploys.
  Certs are regenerated if missing but it's slow.
- SkySwitch provisioning URL format may need adjustment — confirm the exact
  URL pattern with the SkySwitch admin portal. Typical: 
  https://p3.zswitch.net/{MAC}.cfg  (uppercase MAC, no colons)
- The .env file contains secrets — chmod 600 .env after writing it.
- On Ubuntu 26.04, sudo-rs is default. Behavior is identical for scripts;
  no changes needed.
- If certbot fails (DNS not yet propagated), set up nginx on port 80 first,
  get the cert, then switch to 443.
