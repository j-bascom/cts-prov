# CTS VPN Provisioning Proxy

Automatic OpenVPN provisioning gateway for Yealink SIP phones. When a phone boots and checks in with your SkySwitch provisioning server, this proxy intercepts the request, injects a per-device OpenVPN config, and brings the phone up on a private tunnel — all without touching the phone manually.

## What it does

In SkySwitch, you point the device provisioning URL at this server. From there, everything is automatic:

```
Phone boots
  → contacts this server's provisioning endpoint
  → server auto-registers the phone by MAC, generates a unique OpenVPN cert
  → phone receives a VPN overlay config telling it to connect here
  → phone downloads its OpenVPN bundle (cert + key + CA, inline)
  → phone establishes an OpenVPN tunnel to this server (10.8.0.0/24)
  → all phone SIP/RTP traffic is proxied through this server's public IP
  → SkySwitch sees a consistent IP regardless of where the phone is located
```

## Stack

| Component | Purpose |
|-----------|---------|
| FastAPI + uvicorn | Provisioning API and admin dashboard |
| OpenVPN | Per-device encrypted tunnels |
| Easy-RSA | Certificate authority — one cert per phone MAC |
| Nginx | TLS termination (Let's Encrypt or self-signed) |
| SQLite | Device registry (MAC, label, tenant, last seen) |
| fail2ban | Brute-force protection on SSH, admin API, and dashboard login |
| WireGuard | Optional admin/staff VPN alongside OpenVPN |

## Requirements

- Ubuntu 22.04 / 24.04 / 26.04 VPS (Vultr or any provider)
- A public domain name with an A record pointing at the server
- Ports open in your cloud firewall: `22/tcp`, `80/tcp`, `443/tcp`, `1194/udp` (+ `51820/udp` if using WireGuard)

## Installation

Download the latest release and run it as root:

```bash
bash cts-prov-installer-YYYYMMDD.run
```

The interactive wizard walks you through:

1. **Pre-flight checks** — root, Ubuntu version, internet, disk space, apt lock
2. **Network identity** — domain, public IP (auto-detected), admin email
3. **TLS certificate** — Let's Encrypt (recommended) or self-signed
4. **SkySwitch + OpenVPN** — provisioning URL, VPN port, auto-generated tokens
5. **Dashboard credentials** — username and password for the web UI
6. **WireGuard** (optional) — subnet, port, number of initial client configs
7. **Review & confirm** — shows all settings before touching anything
8. **Installation** — runs all setup steps with live output
9. **Verification** — confirms all services are up and endpoints respond
10. **Summary** — admin token, provisioning URL, next steps

To build the installer from source:

```bash
bash build_installer.sh
```

Requires `makeself` (installed automatically if missing). Produces a self-extracting `.run` file with SHA256 integrity verification.

## Configuration

All settings live in `/opt/cts-prov/.env` (root-readable only, `chmod 600`). The installer generates this file — see `.env.example` for all available options.

| Variable | Description |
|----------|-------------|
| `PROV_DOMAIN` | HTTPS domain for this server |
| `VULTR_PUBLIC_IP` | Server's public IP (used in OpenVPN client configs) |
| `TLS_MODE` | `letsencrypt` or `selfsigned` |
| `CERTBOT_EMAIL` | Email for Let's Encrypt expiry notices |
| `ADMIN_TOKEN` | Bearer token for the admin API (`X-Admin-Token` header) |
| `PROV_TOKEN` | Optional shared secret Yealink phones send when fetching configs |
| `DASHBOARD_USER` | Dashboard login username |
| `DASHBOARD_PASSWORD` | Dashboard login password |
| `VPN_PORT` | OpenVPN UDP port (default `1194`) |
| `WG_ENABLED` | `yes` to install WireGuard |
| `WG_SUBNET` | WireGuard subnet, must not overlap `10.8.0.0/24` (default `10.9.0.0/24`) |
| `WG_PORT` | WireGuard listen port (default `51820`) |
| `WG_CLIENT_COUNT` | Number of client configs to generate at install time |

## API endpoints

### Provisioning (Yealink phones)

| Endpoint | Description |
|----------|-------------|
| `GET /provision/provision.cfg` | MAC-less — phone identified from User-Agent. Auto-registers on first contact. |
| `GET /provision/{mac}.cfg` | MAC-in-URL — requires pre-registration via admin API. |
| `GET /vpn/vpn.cnf` | OpenVPN client config (MAC-less) |
| `GET /vpn/{mac}/vpn.cnf` | OpenVPN client config (MAC-in-URL) |
| `GET /vpn/vpn.tar.gz` | OpenVPN bundle as tar.gz (MAC-less) |
| `GET /vpn/{mac}/vpn.tar.gz` | OpenVPN bundle as tar.gz (MAC-in-URL) |

### Admin API (requires `X-Admin-Token` header)

| Endpoint | Description |
|----------|-------------|
| `GET /admin/devices` | List all registered devices |
| `POST /admin/devices` | Register a device (`?mac=&label=&tenant=`) |
| `DELETE /admin/devices/{mac}` | Remove a device |
| `POST /admin/devices/{mac}/refresh-cert` | Revoke and regenerate cert (lost/stolen phone) |
| `DELETE /admin/devices/{mac}/cache` | Force VPN bundle regeneration on next request |
| `DELETE /admin/devices/stale?days=60` | Delete devices not seen in N days (connected devices protected) |
| `GET /admin/status` | All devices merged with live OpenVPN connection status |

### Other

| Endpoint | Description |
|----------|-------------|
| `GET /dashboard` | Web UI — requires dashboard login session |
| `GET /health` | Health check (public) |

## Dashboard

The web dashboard at `https://your-domain/dashboard` shows all registered devices, their VPN connection status, traffic stats, and lets you revoke certs or delete devices.

Authentication uses a session cookie (8-hour sliding window). After 5 failed login attempts within 5 minutes, that IP is locked out for 15 minutes. fail2ban also bans at the nginx level after repeated 401 responses.

## Adding phones

```bash
# Register a phone by MAC address
curl -X POST 'https://your-domain/admin/devices' \
     -H 'X-Admin-Token: your-token' \
     -G -d 'mac=aabbccdd1122' -d 'label=Lobby' -d 'tenant=acme'

# Set the YMCS provisioning URL in SkySwitch to:
https://your-domain/provision/provision.cfg
```

On first contact the phone is auto-registered, a certificate is generated via Easy-RSA, and the OpenVPN bundle is cached for subsequent downloads.

## WireGuard

If WireGuard was enabled during installation, client configs are at `/opt/cts-prov/wireguard-clients/client{N}/client{N}.conf`. Import any `.conf` file into the WireGuard app on iOS, Android, Windows, macOS, or Linux.

To add a new client after installation:

```bash
/opt/cts-prov/wireguard-clients/gen-client.sh [name]
```

This generates a new keypair, finds the next available IP, adds the peer to the running server live (no restart needed), and writes the client `.conf` file.

## Security

- **TLS everywhere** — all phone and admin traffic goes over HTTPS
- **Per-device certificates** — each phone MAC gets a unique Easy-RSA cert; revoke individually without affecting other phones
- **CRL enforcement** — OpenVPN checks the certificate revocation list on every connection attempt
- **Token auth** — admin API requires a 64-char hex bearer token; provisioning endpoints optionally require a token too
- **Dashboard session auth** — httponly + secure cookie, 8-hour sliding sessions
- **fail2ban** — SSH, admin API (403s), and dashboard login (401s) all monitored; 5 failures in 10 minutes = 1-hour ban
- **NAT isolation** — `tun0↔tun0` forwarding is blocked; phones cannot talk to each other through the tunnel

## Cron jobs

| Schedule | Job | Log |
|----------|-----|-----|
| Sundays 2am | CRL renewal (`renew-crl.sh`) — Easy-RSA CRL expires after 180 days | `/var/log/cts-crl-renewal.log` |
| Sundays 3am | Geoblock update (`geo/update-geoblock.sh`) | `/var/log/cts-geoblock.log` |

## Useful commands

```bash
journalctl -u cts-prov -f                  # live app logs
journalctl -u openvpn-server@server -n 50  # VPN server logs
fail2ban-client status cts-admin           # banned IPs (admin + dashboard)
fail2ban-client status sshd                # SSH bans
systemctl restart cts-prov                 # restart after .env changes
cat /opt/cts-prov/.env                     # view config (root only)
```
