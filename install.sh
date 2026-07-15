#!/usr/bin/env bash
# install.sh — CTS VPN Provisioning Proxy interactive installer wizard
# Supports: Ubuntu 22.04 / 24.04 / 26.04
# Run as root: bash install.sh

set -euo pipefail

VERSION="1.0.0"
INSTALL_DIR="/opt/cts-prov"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Color helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
err()  { echo -e "  ${RED}✗${RESET} $*"; }
info() { echo -e "  ${CYAN}→${RESET}  $*"; }
hr()   { printf "${DIM}%${COLUMNS:-80}s${RESET}\n" "" | tr ' ' '─'; }
bold() { echo -e "${BOLD}$*${RESET}"; }

ask() {
    local _var="$1" _prompt="$2" _default="${3:-}"
    local _val
    if [ -n "$_default" ]; then
        echo -en "  ${BOLD}${_prompt}${RESET} ${DIM}[$_default]${RESET}: "
    else
        echo -en "  ${BOLD}${_prompt}${RESET}: "
    fi
    read -r _val
    printf -v "$_var" '%s' "${_val:-$_default}"
}

pause() { echo; read -rp "  Press ENTER to continue..."; echo; }

# ── Screen 0: Welcome ─────────────────────────────────────────────────────────
show_welcome() {
    clear
    echo
    echo -e "${BOLD}${BLUE}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║      CTS VPN Provisioning Proxy — Installer v${VERSION}         ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo "  Installs the CTS OpenVPN provisioning proxy for Yealink SIP phones."
    echo
    echo "  What gets installed:"
    echo "    • FastAPI provisioning API  — proxied via nginx"
    echo "    • OpenVPN server            — per-device PKI via Easy-RSA"
    echo "    • Nginx reverse proxy       — TLS via Let's Encrypt or self-signed"
    echo "    • fail2ban                  — SSH + admin API brute-force protection"
    echo "    • WireGuard VPN             — optional, for admin/staff access"
    echo "    • CRL renewal cron job      — weekly, keeps cert revocation current"
    echo
    echo "  Estimated time: 5–10 minutes (DH params generation takes ~60s)"
    echo
    pause
}

# ── Screen 1: Pre-flight checks ───────────────────────────────────────────────
EXISTING_INSTALL=false
PREFLIGHT_OK=true

run_preflight() {
    clear
    bold "  Pre-flight checks"
    echo; hr; echo

    # Root
    if [[ $EUID -eq 0 ]]; then
        ok "Running as root"
    else
        err "Must run as root — re-run: sudo bash install.sh"
        PREFLIGHT_OK=false
    fi

    # Ubuntu version
    local ver
    ver=$(lsb_release -rs 2>/dev/null || echo "0")
    if awk "BEGIN{exit !(${ver:-0} >= 22.04)}"; then
        ok "Ubuntu $ver"
    else
        err "Ubuntu $ver — requires 22.04 or later"
        PREFLIGHT_OK=false
    fi

    # Internet
    if curl -sf --max-time 10 https://deb.debian.org/ -o /dev/null 2>/dev/null; then
        ok "Internet connectivity"
    else
        err "No internet access — check routing/firewall"
        PREFLIGHT_OK=false
    fi

    # apt lock
    if ! fuser /var/lib/dpkg/lock-frontend &>/dev/null; then
        ok "apt not locked"
    else
        err "apt is locked by another process — wait and retry"
        PREFLIGHT_OK=false
    fi

    # Disk space
    local free_gb
    free_gb=$(df / --output=avail -BG | tail -1 | tr -d 'G ')
    if [[ ${free_gb:-0} -ge 2 ]]; then
        ok "Disk space (${free_gb}GB free)"
    else
        err "Only ${free_gb:-0}GB free — need at least 2GB"
        PREFLIGHT_OK=false
    fi

    # Existing installation
    if systemctl is-active --quiet cts-prov 2>/dev/null && [ -f "$INSTALL_DIR/.env" ]; then
        echo
        warn "Existing CTS installation detected."
        warn "This wizard will RECONFIGURE it — device database and"
        warn "certificates will be PRESERVED."
        EXISTING_INSTALL=true
    fi

    echo
    if [ "$PREFLIGHT_OK" = false ]; then
        echo -e "  ${RED}${BOLD}Pre-flight failed — fix the issues above and re-run.${RESET}"
        exit 1
    fi
    ok "All pre-flight checks passed"
    pause
}

# ── Screen 2: Configuration wizard ───────────────────────────────────────────
load_existing_env() {
    if [ "$EXISTING_INSTALL" = true ] && [ -f "$INSTALL_DIR/.env" ]; then
        set -a; source "$INSTALL_DIR/.env" 2>/dev/null || true; set +a
        # Strip https:// prefix from PROV_DOMAIN if present (stored with it)
        PROV_DOMAIN="${PROV_DOMAIN#https://}"
    fi
}

collect_config() {
    # Auto-detect public IP
    local detected_ip
    detected_ip=$(curl -sf --max-time 10 https://api.ipify.org 2>/dev/null || \
                  curl -sf --max-time 10 https://ifconfig.me 2>/dev/null || echo "")

    # ── Page 1/4: Network identity ─────────────────────────────────────────────
    clear
    bold "  Configuration — Network Identity  (1 of 4)"
    echo; hr; echo

    while true; do
        ask PROV_DOMAIN "Provisioning domain (e.g. prov.yourcompany.com)" "${PROV_DOMAIN:-}"
        PROV_DOMAIN="${PROV_DOMAIN#https://}"
        PROV_DOMAIN="${PROV_DOMAIN%/}"
        if [[ "$PROV_DOMAIN" =~ ^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        fi
        warn "Invalid domain — example: prov.yourcompany.com"
    done

    while true; do
        ask VULTR_PUBLIC_IP "Server public IP" "${VULTR_PUBLIC_IP:-$detected_ip}"
        if [[ "$VULTR_PUBLIC_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            break
        fi
        warn "Invalid IP address"
    done

    while true; do
        ask CERTBOT_EMAIL "Admin email (for Let's Encrypt + alerts)" "${CERTBOT_EMAIL:-}"
        if [[ "$CERTBOT_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
            break
        fi
        warn "Invalid email address"
    done

    # ── Page 2/4: TLS mode ────────────────────────────────────────────────────
    echo
    bold "  Configuration — TLS Certificate  (2 of 4)"
    echo; hr; echo
    echo "  1) Let's Encrypt (recommended)"
    echo "     Free automatic certificate, auto-renews every 60 days."
    echo "     Requires: valid public DNS pointing here + port 80 open."
    echo
    echo "  2) Self-signed certificate"
    echo "     Generated locally, valid 10 years. No DNS check required."
    echo -e "     ${YELLOW}Note: Yealink phones reject self-signed certs unless you push${RESET}"
    echo -e "     ${YELLOW}the CA cert to them. Suitable for testing only.${RESET}"
    echo

    local _tls_default=1
    [ "${TLS_MODE:-}" = "selfsigned" ] && _tls_default=2
    while true; do
        ask _TLS_CHOICE "Choice" "$_tls_default"
        case "${_TLS_CHOICE:-1}" in
            1) TLS_MODE=letsencrypt; info "Using Let's Encrypt";            break ;;
            2) TLS_MODE=selfsigned;  info "Using self-signed certificate";  break ;;
            *) warn "Enter 1 or 2" ;;
        esac
    done

    # ── Page 3/4: SkySwitch + OpenVPN ─────────────────────────────────────────
    echo
    bold "  Configuration — SkySwitch + OpenVPN  (3 of 4)"
    echo; hr; echo

    while true; do
        ask SKYSWITCH_PROV_URL "SkySwitch provisioning URL" "${SKYSWITCH_PROV_URL:-https://cfg.skyswitch.net}"
        if [[ "$SKYSWITCH_PROV_URL" =~ ^https:// ]]; then
            break
        fi
        warn "URL must start with https://"
    done

    while true; do
        ask VPN_PORT "OpenVPN UDP port" "${VPN_PORT:-1194}"
        if [[ "$VPN_PORT" =~ ^[0-9]+$ ]] && [ "$VPN_PORT" -ge 1 ] && [ "$VPN_PORT" -le 65535 ]; then
            break
        fi
        warn "Port must be 1–65535"
    done

    echo
    echo "  PROV_TOKEN — optional shared secret Yealink phones present when"
    echo "  fetching configs. Press ENTER to auto-generate (recommended)."
    ask _PROV_INPUT "Provisioning token" "auto-generate"
    if [ "${_PROV_INPUT:-auto-generate}" = "auto-generate" ]; then
        PROV_TOKEN=$(openssl rand -hex 16)
        info "PROV_TOKEN auto-generated"
    else
        PROV_TOKEN="$_PROV_INPUT"
    fi

    if [ "$EXISTING_INSTALL" = true ] && [ -n "${ADMIN_TOKEN:-}" ]; then
        info "ADMIN_TOKEN: keeping existing value"
    else
        ADMIN_TOKEN=$(openssl rand -hex 32)
        info "ADMIN_TOKEN auto-generated (shown in summary)"
    fi

    # ── Page 4/5: Dashboard credentials ──────────────────────────────────────
    echo
    bold "  Configuration — Dashboard Credentials  (4 of 5)"
    echo; hr; echo
    echo "  The status dashboard (/dashboard) requires a username and password."
    echo "  Sessions last 8 hours. After 5 wrong attempts in 5 minutes, that"
    echo "  IP is locked out for 15 minutes (fail2ban also bans at nginx level)."
    echo

    ask DASHBOARD_USER "Dashboard username" "${DASHBOARD_USER:-admin}"
    DASHBOARD_USER="${DASHBOARD_USER:-admin}"

    while true; do
        echo -en "  ${BOLD}Dashboard password${RESET}: "
        read -rs _DASH_PW1; echo
        if [ -z "$_DASH_PW1" ] && [ -n "${DASHBOARD_PASSWORD:-}" ] && [ "$EXISTING_INSTALL" = true ]; then
            info "Dashboard password: keeping existing value"
            break
        fi
        if [ "${#_DASH_PW1}" -lt 8 ]; then
            warn "Password must be at least 8 characters"
            continue
        fi
        echo -en "  ${BOLD}Confirm password${RESET}: "
        read -rs _DASH_PW2; echo
        if [ "$_DASH_PW1" = "$_DASH_PW2" ]; then
            DASHBOARD_PASSWORD="$_DASH_PW1"
            break
        fi
        warn "Passwords do not match — try again"
    done

    # ── Page 5/5: WireGuard ───────────────────────────────────────────────────
    echo
    bold "  Configuration — WireGuard VPN (optional)  (5 of 5)"
    echo; hr; echo
    echo "  WireGuard provides a fast, modern VPN for admin and staff access."
    echo "  It runs alongside OpenVPN (which handles Yealink phones)."
    echo "  Client configs are generated as .conf files you import into any"
    echo "  WireGuard app (iOS, Android, Windows, macOS, Linux)."
    echo

    local _wg_default="N"
    [ "${WG_ENABLED:-no}" = "yes" ] && _wg_default="y"
    ask _WG_CHOICE "Install WireGuard? [y/N]" "$_wg_default"

    if [[ "${_WG_CHOICE:-N}" =~ ^[Yy] ]]; then
        WG_ENABLED=yes

        while true; do
            ask WG_SUBNET "WireGuard subnet (must not overlap 10.8.0.0/24)" "${WG_SUBNET:-10.9.0.0/24}"
            if [[ "$WG_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                break
            fi
            warn "Invalid CIDR — example: 10.9.0.0/24"
        done

        while true; do
            ask WG_PORT "WireGuard listen port" "${WG_PORT:-51820}"
            if [[ "$WG_PORT" =~ ^[0-9]+$ ]] && [ "$WG_PORT" -ge 1 ] && [ "$WG_PORT" -le 65535 ]; then
                break
            fi
            warn "Invalid port"
        done

        while true; do
            ask WG_CLIENT_COUNT "Number of initial client configs to generate" "${WG_CLIENT_COUNT:-5}"
            if [[ "$WG_CLIENT_COUNT" =~ ^[0-9]+$ ]] && [ "$WG_CLIENT_COUNT" -ge 1 ] && [ "$WG_CLIENT_COUNT" -le 50 ]; then
                break
            fi
            warn "Enter a number between 1 and 50"
        done

        ask WG_DNS "DNS servers for WireGuard clients" "${WG_DNS:-8.8.8.8,1.1.1.1}"
    else
        WG_ENABLED=no
    fi

    # ── Advanced paths ─────────────────────────────────────────────────────────
    echo
    echo -e "  ${DIM}Advanced: PKI/cache/DB paths. Press ENTER for defaults, or type 'edit':${RESET}"
    ask _PATHS_EDIT "" "ENTER"
    if [ "${_PATHS_EDIT:-ENTER}" = "edit" ]; then
        ask PKI_DIR     "PKI directory"   "${PKI_DIR:-/etc/openvpn/easy-rsa/pki}"
        ask EASYRSA_BIN "Easy-RSA binary" "${EASYRSA_BIN:-/etc/openvpn/easy-rsa/easyrsa}"
        ask CACHE_DIR   "Cache directory" "${CACHE_DIR:-/opt/cts-prov/cache}"
        ask DB_PATH     "Database path"   "${DB_PATH:-/opt/cts-prov/devices.db}"
    else
        PKI_DIR="${PKI_DIR:-/etc/openvpn/easy-rsa/pki}"
        EASYRSA_BIN="${EASYRSA_BIN:-/etc/openvpn/easy-rsa/easyrsa}"
        CACHE_DIR="${CACHE_DIR:-/opt/cts-prov/cache}"
        DB_PATH="${DB_PATH:-/opt/cts-prov/devices.db}"
    fi
}

# ── Screen 3: DNS verification ────────────────────────────────────────────────
verify_dns() {
    [ "$TLS_MODE" = "selfsigned" ] && return  # no DNS needed for self-signed

    clear
    bold "  DNS Verification"
    echo; hr; echo
    echo "  Let's Encrypt requires $PROV_DOMAIN to resolve to $VULTR_PUBLIC_IP"
    echo "  before running certbot, or the ACME challenge will fail."
    echo

    while true; do
        echo -en "  Checking DNS..."
        local resolved
        resolved=$(dig +short "$PROV_DOMAIN" A 2>/dev/null | tail -1 || \
                   host "$PROV_DOMAIN" 2>/dev/null | awk '/has address/{print $NF}' | head -1 || \
                   echo "")
        echo

        if [ "$resolved" = "$VULTR_PUBLIC_IP" ]; then
            ok "$PROV_DOMAIN → $VULTR_PUBLIC_IP"
            break
        elif [ -z "$resolved" ]; then
            warn "$PROV_DOMAIN — no A record found"
        else
            warn "$PROV_DOMAIN resolves to $resolved (expected $VULTR_PUBLIC_IP)"
        fi

        echo
        echo "  Add an A record:  $PROV_DOMAIN  →  $VULTR_PUBLIC_IP"
        echo "  DNS propagation can take up to 60 seconds after adding."
        echo
        echo "  [C]ontinue anyway   [R]e-check   [A]bort"
        ask _DNS_CHOICE "" "R"
        case "${_DNS_CHOICE:-R}" in
            [Cc]) warn "Continuing — certbot may fail if DNS is not propagated"; break ;;
            [Aa]) echo "  Aborted."; exit 0 ;;
            *)    echo ;;
        esac
    done

    pause
}

# ── Screen 4: Firewall checklist ──────────────────────────────────────────────
show_firewall_checklist() {
    clear
    bold "  Firewall Requirements"
    echo; hr; echo
    echo "  The installer configures iptables automatically, but your cloud"
    echo "  firewall panel must also allow inbound traffic on these ports:"
    echo
    printf "  %-8s %-6s %s\n" "Port" "Proto" "Purpose"
    printf "  %-8s %-6s %s\n" "────" "─────" "───────"
    printf "  %-8s %-6s %s\n" "22"   "TCP"   "SSH (keep open or you'll be locked out)"
    printf "  %-8s %-6s %s\n" "80"   "TCP"   "HTTP (Let's Encrypt ACME challenge)"
    printf "  %-8s %-6s %s\n" "443"  "TCP"   "HTTPS (provisioning + admin dashboard)"
    printf "  %-8s %-6s %s\n" "$VPN_PORT" "UDP" "OpenVPN (phone VPN connections)"
    if [ "${WG_ENABLED:-no}" = "yes" ]; then
        printf "  %-8s %-6s %s\n" "$WG_PORT" "UDP" "WireGuard (admin VPN)"
    fi
    echo
    echo "  Vultr: Networking → Firewall → Add Rule for each port above."
    echo "  AWS:   Edit your Security Group inbound rules."
    echo "  Other: Check your provider's security group / ACL settings."
    echo
    ask _FW_ACK "Confirm ports are open in your cloud firewall [y/skip]" "skip"
    echo
}

# ── Screen 5: Review and confirm ──────────────────────────────────────────────
show_review() {
    clear
    bold "  Configuration Review"
    echo; hr; echo

    printf "  %-24s %s\n" "Domain:"           "https://$PROV_DOMAIN"
    printf "  %-24s %s\n" "Server IP:"        "$VULTR_PUBLIC_IP"
    printf "  %-24s %s\n" "Admin email:"      "$CERTBOT_EMAIL"
    printf "  %-24s %s\n" "TLS mode:"         "$TLS_MODE"
    printf "  %-24s %s\n" "SkySwitch URL:"    "$SKYSWITCH_PROV_URL"
    printf "  %-24s %s\n" "OpenVPN port:"     "${VPN_PORT}/udp"
    printf "  %-24s %s\n" "PROV_TOKEN:"       "(set, ${#PROV_TOKEN} chars)"
    printf "  %-24s %s\n" "ADMIN_TOKEN:"      "(set, ${#ADMIN_TOKEN} chars — shown after install)"
    printf "  %-24s %s\n" "Dashboard user:"   "$DASHBOARD_USER"
    printf "  %-24s %s\n" "Dashboard password:" "(set, ${#DASHBOARD_PASSWORD} chars)"
    printf "  %-24s %s\n" "WireGuard:"        "$WG_ENABLED"
    if [ "${WG_ENABLED:-no}" = "yes" ]; then
        printf "  %-24s %s\n" "  WG subnet:"  "$WG_SUBNET"
        printf "  %-24s %s\n" "  WG port:"    "${WG_PORT}/udp"
        printf "  %-24s %s\n" "  WG clients:" "$WG_CLIENT_COUNT initial configs"
        printf "  %-24s %s\n" "  WG DNS:"     "$WG_DNS"
    fi
    printf "  %-24s %s\n" "PKI dir:"          "$PKI_DIR"
    printf "  %-24s %s\n" "DB path:"          "$DB_PATH"
    echo; hr; echo

    local _pkgs="openvpn easy-rsa nginx certbot fail2ban python3-venv"
    [ "${WG_ENABLED:-no}" = "yes" ] && _pkgs="$_pkgs wireguard"
    echo "  Will install: $_pkgs"
    echo "  Will write:   $INSTALL_DIR/.env  (chmod 600)"
    echo "  Will enable:  cts-prov  openvpn-server@server  nginx  fail2ban"
    [ "${WG_ENABLED:-no}" = "yes" ] && echo "  Will enable:  wg-quick@wg0"
    echo

    ask _CONFIRM "Ready to install? [Y/n/q]" "Y"
    case "${_CONFIRM:-Y}" in
        [Qq]) echo "  Aborted."; exit 0 ;;
        [Nn]) return 1 ;;
        *)    return 0 ;;
    esac
}

# ── Screen 6: Installation ─────────────────────────────────────────────────────
write_env() {
    install -d -m 755 "$INSTALL_DIR"
    cat > "$INSTALL_DIR/.env" <<ENV
# Generated by CTS installer v${VERSION} on $(date -u +"%Y-%m-%d %H:%M UTC")

PROV_DOMAIN=https://$PROV_DOMAIN
VULTR_PUBLIC_IP=$VULTR_PUBLIC_IP
CERTBOT_EMAIL=$CERTBOT_EMAIL
TLS_MODE=$TLS_MODE
SKYSWITCH_PROV_URL=$SKYSWITCH_PROV_URL
VPN_PORT=$VPN_PORT
ADMIN_TOKEN=$ADMIN_TOKEN
PROV_TOKEN=$PROV_TOKEN
DASHBOARD_USER=$DASHBOARD_USER
DASHBOARD_PASSWORD=$DASHBOARD_PASSWORD
WG_ENABLED=${WG_ENABLED:-no}
WG_SUBNET=${WG_SUBNET:-10.9.0.0/24}
WG_PORT=${WG_PORT:-51820}
WG_DNS=${WG_DNS:-8.8.8.8,1.1.1.1}
WG_CLIENT_COUNT=${WG_CLIENT_COUNT:-5}
PKI_DIR=$PKI_DIR
EASYRSA_BIN=$EASYRSA_BIN
CACHE_DIR=$CACHE_DIR
DB_PATH=$DB_PATH
ENV
    chmod 600 "$INSTALL_DIR/.env"
}

copy_app_files() {
    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
        info "Copying application files to $INSTALL_DIR..."
        mkdir -p "$INSTALL_DIR"
        rsync -a \
            --exclude='.env' \
            --exclude='venv/' \
            --exclude='cache/' \
            --exclude='devices.db' \
            --exclude='__pycache__/' \
            --exclude='*.run' \
            --exclude='*.pyc' \
            "$SCRIPT_DIR/" "$INSTALL_DIR/"
        ok "Files copied"
    fi
}

run_install() {
    clear
    bold "  Installing"
    echo; hr; echo

    copy_app_files
    info "Writing $INSTALL_DIR/.env"
    write_env
    ok "Config written"
    echo; hr

    if CTS_INSTALL_MODE=1 bash "$INSTALL_DIR/setup.sh" 2>&1 | sed 's/^/        /'; then
        hr; echo
        ok "Installation completed"
    else
        hr; echo
        err "setup.sh failed"
        echo
        echo "  Diagnose:"
        echo "    journalctl -u cts-prov -n 50"
        echo "    journalctl -u openvpn-server@server -n 50"
        echo "    cat /var/log/nginx/error.log"
        echo
        echo "  This installer is safe to re-run after fixing the issue."
        exit 1
    fi

    # CRL renewal cron
    install -m 644 /dev/stdin /etc/cron.d/cts-crl-renewal <<'CRON'
0 2 * * 0 root /opt/cts-prov/renew-crl.sh >> /var/log/cts-crl-renewal.log 2>&1
CRON
    ok "CRL renewal cron installed (Sundays 2am)"

    # Geoblock update cron (only if the script is present)
    if [ -f "$INSTALL_DIR/geo/update-geoblock.sh" ]; then
        install -m 644 /dev/stdin /etc/cron.d/cts-geoblock <<'CRON'
0 3 * * 0 root /opt/cts-prov/geo/update-geoblock.sh >> /var/log/cts-geoblock.log 2>&1
CRON
        ok "Geoblock update cron installed (Sundays 3am)"
    fi

    pause
}

# ── Screen 7: Post-install verification ───────────────────────────────────────
run_verification() {
    clear
    bold "  Verification"
    echo; hr; echo

    sleep 3  # give services time to settle

    local _all_ok=true

    vcheck() {
        local name="$1"; shift
        if eval "$*" &>/dev/null; then
            ok "$name"
        else
            err "$name"
            _all_ok=false
        fi
    }

    vcheck "OpenVPN server running"   "systemctl is-active --quiet openvpn-server@server"
    vcheck "cts-prov running"         "systemctl is-active --quiet cts-prov"
    vcheck "nginx running"            "systemctl is-active --quiet nginx"
    vcheck "fail2ban running"         "systemctl is-active --quiet fail2ban"
    [ "${WG_ENABLED:-no}" = "yes" ] && \
    vcheck "WireGuard running"        "systemctl is-active --quiet wg-quick@wg0"
    vcheck "FastAPI responding"       "curl -sf --max-time 5 http://127.0.0.1:8000/health"
    vcheck "HTTPS responding"         "curl -sf --max-time 10 -k https://$PROV_DOMAIN/health"
    vcheck "Easy-RSA CA present"      "test -f '$PKI_DIR/ca.crt'"
    vcheck "tun0 interface up"        "ip link show tun0"
    vcheck "NAT masquerade rule"      "iptables -t nat -L POSTROUTING -n | grep -q 10.8.0.0"
    vcheck "CRL cron installed"       "test -f /etc/cron.d/cts-crl-renewal"
    vcheck "fail2ban jail active"     "fail2ban-client status cts-admin"

    if [ "$TLS_MODE" = "letsencrypt" ]; then
        vcheck "Let's Encrypt cert valid" \
            "openssl s_client -connect '$PROV_DOMAIN:443' -servername '$PROV_DOMAIN' </dev/null 2>/dev/null | openssl x509 -noout -checkend 0"
    else
        vcheck "Self-signed cert present" "test -f /etc/ssl/certs/cts-prov.crt"
    fi

    echo
    if [ "$_all_ok" = false ]; then
        warn "Some checks failed — see output above"
        warn "journalctl -u cts-prov -n 50    to diagnose"
        warn "This installer is safe to re-run"
    else
        ok "All checks passed"
    fi

    pause
}

# ── Screen 8: Summary ─────────────────────────────────────────────────────────
show_summary() {
    clear
    echo -e "${BOLD}${GREEN}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║              Installation Complete                          ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    echo "  ${BOLD}Services running:${RESET}"
    printf "    %-36s %s\n" "openvpn-server@server" "UDP $VPN_PORT"
    printf "    %-36s %s\n" "nginx"                  "TCP 80/443"
    printf "    %-36s %s\n" "cts-prov"               "http://127.0.0.1:8000"
    printf "    %-36s %s\n" "fail2ban"               "SSH + admin protection"
    [ "${WG_ENABLED:-no}" = "yes" ] && \
    printf "    %-36s %s\n" "wg-quick@wg0"           "UDP $WG_PORT"
    echo

    echo "  ${BOLD}Dashboard:${RESET}"
    echo "    https://$PROV_DOMAIN/dashboard"
    echo "    Login: $DASHBOARD_USER / (password you set)"
    echo "    Sessions last 8 hours. Logout link is in the header."
    echo

    echo -e "  ${BOLD}${YELLOW}SAVE YOUR ADMIN TOKEN — not shown again:${RESET}"
    echo -e "  ${BOLD}$ADMIN_TOKEN${RESET}"
    echo

    echo "  ${BOLD}SkySwitch YMCS provisioning URL:${RESET}"
    echo "    https://$PROV_DOMAIN/provision/provision.cfg"
    echo

    echo "  ${BOLD}Add a phone:${RESET}"
    echo "    curl -X POST 'https://$PROV_DOMAIN/admin/devices' \\"
    echo "         -H 'X-Admin-Token: $ADMIN_TOKEN' \\"
    echo "         -G -d 'mac=aabbccdd1122' -d 'label=Lobby' -d 'tenant=acme'"
    echo

    if [ "${WG_ENABLED:-no}" = "yes" ]; then
        echo "  ${BOLD}WireGuard client configs:${RESET}"
        echo "    /opt/cts-prov/wireguard-clients/client{1..${WG_CLIENT_COUNT}}/"
        echo "    Import client*.conf into any WireGuard app to connect."
        echo "    Add more clients: /opt/cts-prov/wireguard-clients/gen-client.sh [name]"
        echo
    fi

    echo "  ${BOLD}Cron jobs:${RESET}"
    echo "    CRL renewal:  Sundays 2am  → /var/log/cts-crl-renewal.log"
    [ -f /etc/cron.d/cts-geoblock ] && \
    echo "    Geoblock:     Sundays 3am  → /var/log/cts-geoblock.log"
    echo

    echo "  ${BOLD}Useful commands:${RESET}"
    echo "    journalctl -u cts-prov -f            # live app logs"
    echo "    journalctl -u openvpn-server@server  # VPN logs"
    echo "    fail2ban-client status cts-admin      # banned IPs"
    echo "    fail2ban-client status sshd           # SSH bans"
    echo "    cat /opt/cts-prov/.env               # config (root only)"
    echo
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    show_welcome
    run_preflight
    load_existing_env

    # Config + review loop — allow going back to config from review
    while true; do
        collect_config
        verify_dns
        show_firewall_checklist
        if show_review; then
            break
        fi
    done

    run_install
    run_verification
    show_summary
}

main
