import os
import re
import secrets
import shutil
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header, Query, Request, Cookie, Form
from fastapi.responses import FileResponse, Response, HTMLResponse, RedirectResponse
from dotenv import load_dotenv

from device_db import init_db, get_device, add_device, delete_device, list_devices, update_last_seen, delete_stale_devices
from cert_engine import get_or_create_cert
from config_merge import vpn_overlay

load_dotenv()
init_db()

app = FastAPI(title="CTS Provisioning Proxy", version="1.0.0")

CACHE_DIR          = os.getenv("CACHE_DIR", "/opt/cts-prov/cache")
ADMIN_TOKEN        = os.getenv("ADMIN_TOKEN", "")
PROV_TOKEN         = os.getenv("PROV_TOKEN", "")
DASHBOARD_USER     = os.getenv("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")

# ── Session store ──────────────────────────────────────────────────────────────
# In-memory; resets on service restart (intentional — forces re-login after deploy)
_sessions: dict[str, float] = {}  # token → expiry timestamp
SESSION_TTL = 8 * 3600  # 8-hour sliding window

def _session_create() -> str:
    now = time.time()
    for tok in [t for t, exp in list(_sessions.items()) if exp < now]:
        del _sessions[tok]
    tok = secrets.token_hex(32)
    _sessions[tok] = now + SESSION_TTL
    return tok

def _session_valid(token: str | None) -> bool:
    if not token or token not in _sessions:
        return False
    if _sessions[token] < time.time():
        del _sessions[token]
        return False
    _sessions[token] = time.time() + SESSION_TTL  # slide window on each use
    return True

# ── Login flood detection ──────────────────────────────────────────────────────
# Complements fail2ban (which bans at nginx level); this provides in-process
# lockout that survives across HTTP connections within the same service lifetime.
_login_failures: dict[str, list[float]] = {}  # IP → timestamps of recent failures
LOGIN_MAX  = 5    # max failures within window before lockout
LOGIN_WIN  = 300  # 5-minute sliding window
LOGIN_LOCK = 900  # 15-minute lockout once threshold hit

def _rate_ok(ip: str) -> bool:
    """Return False if this IP has exceeded the failure threshold."""
    now = time.time()
    recent = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_LOCK]
    _login_failures[ip] = recent
    return len([t for t in recent if now - t < LOGIN_WIN]) < LOGIN_MAX

def _rate_fail(ip: str):
    now = time.time()
    recent = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_LOCK]
    _login_failures[ip] = recent + [now]

def _rate_clear(ip: str):
    _login_failures.pop(ip, None)


# ── Login page HTML ────────────────────────────────────────────────────────────

def _login_html(error: str = "") -> str:
    error_block = f'<div class="error-msg">{error}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CTS Provisioning — Sign in</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #f1f5f9; color: #1e293b; min-height: 100vh;
          display: flex; flex-direction: column; }}
  header {{ background: #1e2a3a; color: #fff; padding: 16px 24px; }}
  header h1 {{ font-size: 1.25rem; font-weight: 700; letter-spacing: 0.02em; }}
  .login-wrap {{ flex: 1; display: flex; align-items: center; justify-content: center; padding: 24px; }}
  .login-card {{ background: #fff; border-radius: 12px; box-shadow: 0 4px 16px rgba(0,0,0,0.1);
                 padding: 40px; width: 100%; max-width: 380px; }}
  .login-card h2 {{ font-size: 1.3rem; font-weight: 700; color: #1e2a3a; margin-bottom: 24px; }}
  label {{ display: block; font-size: 0.82rem; font-weight: 600; color: #475569; margin-bottom: 16px; }}
  label span {{ display: block; margin-bottom: 6px; }}
  input[type=text], input[type=password] {{
    width: 100%; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 6px;
    font-size: 0.9rem; color: #1e293b; outline: none; transition: border 0.15s;
  }}
  input:focus {{ border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }}
  button[type=submit] {{
    width: 100%; margin-top: 8px; padding: 11px; background: #1e2a3a; color: #fff;
    border: none; border-radius: 6px; font-size: 0.92rem; font-weight: 600;
    cursor: pointer; transition: background 0.15s;
  }}
  button[type=submit]:hover {{ background: #2d3e52; }}
  .error-msg {{
    background: #fef2f2; border: 1px solid #fecaca; color: #dc2626;
    border-radius: 6px; padding: 10px 14px; font-size: 0.83rem; margin-bottom: 18px;
  }}
</style>
</head>
<body>
<header><h1>CTS Provisioning</h1></header>
<div class="login-wrap">
  <div class="login-card">
    <h2>Sign in</h2>
    {error_block}
    <form method="POST" action="/dashboard/login">
      <label><span>Username</span>
        <input type="text" name="username" autofocus autocomplete="username" required>
      </label>
      <label><span>Password</span>
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Sign in</button>
    </form>
  </div>
</div>
</body>
</html>"""


# ── Dashboard HTML ─────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CTS Provisioning</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f1f5f9; color: #1e293b; }
  header { background: #1e2a3a; color: #fff; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 1.25rem; font-weight: 700; letter-spacing: 0.02em; }
  .header-right { display: flex; align-items: center; gap: 20px; }
  .header-meta { font-size: 0.78rem; color: #94a3b8; text-align: right; line-height: 1.6; }
  .signout { color: #94a3b8; text-decoration: none; font-size: 0.78rem; padding: 5px 11px;
             border: 1px solid #334155; border-radius: 4px; transition: color 0.15s, border-color 0.15s; }
  .signout:hover { color: #e2e8f0; border-color: #64748b; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .stat-card { background: #fff; border-radius: 10px; padding: 20px 28px; flex: 1; min-width: 160px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .stat-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; margin-bottom: 6px; }
  .stat-card .value { font-size: 2rem; font-weight: 700; color: #1e2a3a; }
  .stat-card .value.green { color: #22c55e; }
  .toolbar { display: flex; justify-content: flex-end; margin-bottom: 16px; gap: 10px; }
  button { cursor: pointer; border: none; border-radius: 6px; padding: 8px 16px; font-size: 0.85rem; font-weight: 600; transition: opacity 0.15s; }
  button:hover { opacity: 0.85; }
  .btn-danger { background: #ef4444; color: #fff; }
  .btn-secondary { background: #e2e8f0; color: #1e2a3a; }
  .btn-sm { padding: 4px 10px; font-size: 0.78rem; }
  .btn-warn { background: #f59e0b; color: #fff; }
  .btn-info { background: #3b82f6; color: #fff; }
  .card { background: #fff; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { background: #f8fafc; text-align: left; padding: 10px 14px; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.07em; color: #64748b; border-bottom: 1px solid #e2e8f0; }
  td { padding: 10px 14px; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
  .dot.online { background: #22c55e; box-shadow: 0 0 0 2px #bbf7d0; }
  .dot.offline { background: #94a3b8; }
  .mac { font-family: monospace; font-size: 0.82rem; }
  .actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .empty-state { text-align: center; padding: 48px 24px; color: #94a3b8; }
  .loading { text-align: center; padding: 48px; color: #94a3b8; font-size: 0.9rem; }
  #toast-container { position: fixed; bottom: 24px; right: 24px; display: flex; flex-direction: column; gap: 8px; z-index: 9999; }
  .toast { background: #1e2a3a; color: #fff; padding: 12px 18px; border-radius: 8px; font-size: 0.85rem; box-shadow: 0 4px 12px rgba(0,0,0,0.2); animation: slide-in 0.2s ease; max-width: 320px; }
  .toast.success { border-left: 4px solid #22c55e; }
  .toast.error { border-left: 4px solid #ef4444; }
  @keyframes slide-in { from { transform: translateX(40px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  .countdown { font-variant-numeric: tabular-nums; }
</style>
</head>
<body>
<header>
  <h1>CTS Provisioning</h1>
  <div class="header-right">
    <div class="header-meta">
      <div>Last updated: <span id="last-updated">—</span></div>
      <div>Refreshing in <span id="countdown" class="countdown">30</span>s</div>
    </div>
    <a class="signout" href="/dashboard/logout">Sign out</a>
  </div>
</header>

<div class="container">
  <div class="stats">
    <div class="stat-card">
      <div class="label">Total Devices</div>
      <div class="value" id="total-count">—</div>
    </div>
    <div class="stat-card">
      <div class="label">Connected (VPN)</div>
      <div class="value green" id="connected-count">—</div>
    </div>
  </div>

  <div class="toolbar">
    <button class="btn-danger" onclick="deleteStale()">Delete Stale (60d)</button>
    <button class="btn-secondary" onclick="loadData()">Refresh</button>
  </div>

  <div class="card">
    <div id="table-wrapper" class="loading">Loading devices…</div>
  </div>
</div>

<div id="toast-container"></div>

<script>
let refreshTimer = null;
let countdownInterval = null;
let countdown = 30;

function fmtBytes(n) {
  if (n == null || n === '') return '—';
  n = parseInt(n, 10);
  if (isNaN(n)) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function fmtRelative(ts) {
  if (!ts) return '—';
  const d = new Date(ts.replace(' ', 'T') + (ts.includes('T') ? '' : 'Z'));
  if (isNaN(d)) return ts;
  const diff = Math.floor((Date.now() - d) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

function fmtMac(mac) {
  return mac.replace(/(.{2})(?=.)/g, '$1:');
}

function toast(msg, type) {
  const c = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast ' + (type || 'success');
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function handleUnauth(status) {
  if (status === 403) {
    window.location.href = '/dashboard/login';
    return true;
  }
  return false;
}

async function apiCall(method, url, onSuccess) {
  try {
    const res = await fetch(url, { method });
    if (handleUnauth(res.status)) return;
    const data = await res.json();
    if (res.ok) {
      onSuccess(data);
    } else {
      toast((data.detail || 'Request failed') + ' (' + res.status + ')', 'error');
    }
  } catch (e) {
    toast('Network error: ' + e.message, 'error');
  }
}

function refreshCert(mac) {
  if (!confirm('Revoke and regenerate cert for ' + mac + '?')) return;
  apiCall('POST', '/admin/devices/' + mac + '/refresh-cert', d => {
    toast('Cert refreshed for ' + mac, 'success');
    loadData();
  });
}

function flushCache(mac) {
  apiCall('DELETE', '/admin/devices/' + mac + '/cache', d => {
    toast('Cache cleared for ' + mac, 'success');
  });
}

function deleteDevice(mac) {
  if (!confirm('Delete device ' + mac + '? This cannot be undone.')) return;
  apiCall('DELETE', '/admin/devices/' + mac, d => {
    toast('Deleted ' + mac, 'success');
    loadData();
  });
}

function deleteStale() {
  if (!confirm('Delete all devices not seen in the last 60 days?\\nConnected devices are protected.')) return;
  apiCall('DELETE', '/admin/devices/stale?days=60', d => {
    toast('Deleted ' + d.count + ' stale device(s)', 'success');
    loadData();
  });
}

function renderTable(devices) {
  const wrapper = document.getElementById('table-wrapper');
  if (!devices || devices.length === 0) {
    wrapper.innerHTML = '<div class="empty-state">No devices registered yet.</div>';
    return;
  }
  const rows = devices.map(d => {
    const online = d.connected ? 'online' : 'offline';
    const statusLabel = d.connected ? 'Online' : 'Offline';
    const mac = d.mac || '';
    const vpnIp = d.vpn_ip || '—';
    const since = d.connected_since ? fmtRelative(d.connected_since) : '—';
    const rx = fmtBytes(d.bytes_rx);
    const tx = fmtBytes(d.bytes_tx);
    const lastSeen = fmtRelative(d.last_seen);
    return `<tr>
      <td><span class="dot ${online}"></span>${statusLabel}</td>
      <td class="mac">${fmtMac(mac)}</td>
      <td>${d.label || '—'}</td>
      <td>${d.tenant || '—'}</td>
      <td>${vpnIp}</td>
      <td>${since}</td>
      <td>↑${tx} / ↓${rx}</td>
      <td>${lastSeen}</td>
      <td class="actions">
        <button class="btn-secondary btn-sm" onclick="flushCache('${mac}')">Flush</button>
        <button class="btn-warn btn-sm" onclick="refreshCert('${mac}')">Revoke</button>
        <button class="btn-danger btn-sm" onclick="deleteDevice('${mac}')">Delete</button>
      </td>
    </tr>`;
  }).join('');

  wrapper.innerHTML = `<table>
    <thead><tr>
      <th>Status</th><th>MAC</th><th>Model</th><th>Tenant</th>
      <th>VPN IP</th><th>Connected Since</th><th>Bytes ↑↓</th>
      <th>Last Seen</th><th>Actions</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

async function loadData() {
  try {
    const res = await fetch('/admin/status');
    if (handleUnauth(res.status)) return;
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      document.getElementById('table-wrapper').innerHTML =
        '<div class="empty-state">Error loading data: ' + (err.detail || res.status) + '</div>';
      return;
    }
    const data = await res.json();
    document.getElementById('total-count').textContent = data.total_count ?? '—';
    document.getElementById('connected-count').textContent = data.connected_count ?? '—';
    document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
    renderTable(data.devices);
  } catch (e) {
    document.getElementById('table-wrapper').innerHTML =
      '<div class="empty-state">Failed to load: ' + e.message + '</div>';
  }
  resetCountdown();
}

function resetCountdown() {
  countdown = 30;
  document.getElementById('countdown').textContent = countdown;
  clearInterval(countdownInterval);
  countdownInterval = setInterval(() => {
    countdown--;
    document.getElementById('countdown').textContent = countdown;
    if (countdown <= 0) {
      clearInterval(countdownInterval);
      loadData();
    }
  }, 1000);
}

loadData();
</script>
</body>
</html>"""


# ── Helpers ────────────────────────────────────────────────────────────────────

def normalize_mac(raw: str) -> str:
    """Accept any MAC format — with/without colons/dashes, .cfg suffix, upper/lower."""
    return raw.lower().replace(":", "").replace("-", "").removesuffix(".cfg").strip()


def mac_from_useragent(ua: str) -> str | None:
    """Extract MAC from Yealink User-Agent — handles both C4FC223CB2C4 and c4:fc:22:3c:b2:c4 formats."""
    match = re.search(r'([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12}', ua or "")
    if not match:
        return None
    return match.group(0).lower().replace(":", "").replace("-", "")


def model_from_useragent(ua: str) -> str:
    """Extract 'Yealink SIP-T85W' from User-Agent string."""
    match = re.match(r'(Yealink\s+\S+)', ua or "", re.IGNORECASE)
    return match.group(1) if match else "unknown"


def require_prov_token(token: str = Query(None)):
    if PROV_TOKEN and not secrets.compare_digest(token or "", PROV_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid or missing token")


def require_admin(
    x_admin_token: Optional[str] = Header(default=None),
    cts_session: Optional[str] = Cookie(default=None),
):
    """Accept either a bearer token (API clients) or a valid session cookie (dashboard browser)."""
    token_ok = bool(
        ADMIN_TOKEN and x_admin_token and
        secrets.compare_digest(x_admin_token, ADMIN_TOKEN)
    )
    if not token_ok and not _session_valid(cts_session):
        raise HTTPException(status_code=403, detail="Forbidden")


def parse_vpn_status() -> dict:
    """
    Parse /var/log/openvpn/status.log and return a dict keyed by common_name.
    Status.log format:
      CLIENT_LIST,<cn>,<real_addr>,<vpn_ip>,<vpn_ipv6>,<bytes_rx>,<bytes_tx>,<connected_since>,<ts>,<user>,<cid>,<pid>,<cipher>
    """
    result = {}
    try:
        with open("/var/log/openvpn/status.log", "r") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("CLIENT_LIST,"):
                    continue
                parts = line.split(",")
                if len(parts) < 8:
                    continue
                cn = parts[1]
                real_addr = parts[2]
                vpn_ip = parts[3]
                try:
                    bytes_rx = int(parts[5])
                except (ValueError, IndexError):
                    bytes_rx = 0
                try:
                    bytes_tx = int(parts[6])
                except (ValueError, IndexError):
                    bytes_tx = 0
                connected_since = parts[7] if len(parts) > 7 else ""
                result[cn] = {
                    "real_ip": real_addr,
                    "vpn_ip": vpn_ip,
                    "bytes_rx": bytes_rx,
                    "bytes_tx": bytes_tx,
                    "connected_since": connected_since,
                }
    except FileNotFoundError:
        pass
    return result


# ── Provisioning endpoints ─────────────────────────────────────────────────────

@app.get("/provision/provision.cfg")
async def provision_ua(request: Request, _: None = Depends(require_prov_token)):
    """
    MAC-less provisioning endpoint — phone identified via User-Agent.
    Set in NDP: auto_provision.server2.url = https://proxy.charlestontel.com/provision/provision.cfg
    """
    ua = request.headers.get("user-agent", "")
    mac = mac_from_useragent(ua)
    if not mac:
        raise HTTPException(status_code=400, detail=f"Cannot extract MAC from User-Agent: {ua!r}")

    if not get_device(mac):
        add_device(mac, label=model_from_useragent(ua), tenant="auto")

    await get_or_create_cert(mac)
    return Response(content=vpn_overlay(mac), media_type="text/plain; charset=utf-8")


@app.get("/provision/{filename}")
async def provision(filename: str, _: None = Depends(require_prov_token)):
    """MAC-in-URL provisioning — kept for direct curl testing and manual use."""
    mac = normalize_mac(filename)

    device = get_device(mac)
    if not device:
        raise HTTPException(
            status_code=404,
            detail=f"MAC {mac} not registered. Add it via POST /admin/devices."
        )

    await get_or_create_cert(mac)

    return Response(content=vpn_overlay(mac), media_type="text/plain; charset=utf-8")


@app.get("/vpn/{mac}/vpn.tar.gz")
async def serve_vpn_bundle(mac: str):
    """
    Phone fetches this after applying the provisioning overlay.
    Returns the per-device OpenVPN cert bundle (client.ovpn inside tar.gz).
    """
    mac = normalize_mac(mac)
    tar_path = f"{CACHE_DIR}/certs/{mac}/vpn.tar.gz"

    if not os.path.exists(tar_path):
        device = get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail=f"MAC {mac} not registered")
        await get_or_create_cert(mac)

    if not os.path.exists(tar_path):
        raise HTTPException(status_code=500, detail="Cert bundle generation failed")

    return FileResponse(
        tar_path,
        media_type="application/gzip",
        filename="vpn.tar.gz"
    )


@app.get("/vpn/vpn.cnf")
async def serve_vpn_cnf_ua(request: Request, _: None = Depends(require_prov_token)):
    """
    MAC-less OpenVPN config endpoint — phone identified via User-Agent.
    Set in NDP: static.network.vpn.cnf.url = https://proxy.charlestontel.com/vpn/vpn.cnf
    Unknown MACs are auto-registered on first contact.
    """
    ua = request.headers.get("user-agent", "")
    mac = mac_from_useragent(ua)
    if not mac:
        raise HTTPException(status_code=400, detail=f"Cannot extract MAC from User-Agent: {ua!r}")

    if not get_device(mac):
        add_device(mac, label=model_from_useragent(ua), tenant="auto")

    update_last_seen(mac)

    await get_or_create_cert(mac)

    cnf_path = f"{CACHE_DIR}/certs/{mac}/client.ovpn"
    return FileResponse(cnf_path, media_type="text/plain", filename="vpn.cnf")


@app.get("/vpn/{mac}/vpn.cnf")
async def serve_vpn_cnf(mac: str, _: None = Depends(require_prov_token)):
    """MAC-in-URL OpenVPN config — for direct testing."""
    mac = normalize_mac(mac)
    device = get_device(mac)
    if not device:
        raise HTTPException(status_code=404, detail=f"MAC {mac} not registered")

    await get_or_create_cert(mac)

    cnf_path = f"{CACHE_DIR}/certs/{mac}/client.ovpn"
    return FileResponse(cnf_path, media_type="text/plain", filename="vpn.cnf")


@app.get("/vpn/vpn.tar.gz")
async def serve_vpn_bundle_ua(request: Request):
    """MAC-less tar.gz bundle — kept for backward compat."""
    ua = request.headers.get("user-agent", "")
    mac = mac_from_useragent(ua)
    if not mac:
        raise HTTPException(status_code=400, detail=f"Cannot extract MAC from User-Agent: {ua!r}")

    if not get_device(mac):
        add_device(mac, label=model_from_useragent(ua), tenant="auto")

    tar_path = f"{CACHE_DIR}/certs/{mac}/vpn.tar.gz"
    if not os.path.exists(tar_path):
        await get_or_create_cert(mac)

    return FileResponse(tar_path, media_type="application/gzip", filename="vpn.tar.gz")


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Admin API ──────────────────────────────────────────────────────────────────

@app.get("/admin/devices", dependencies=[Depends(require_admin)])
def admin_list():
    """List all registered devices."""
    return list_devices()


@app.post("/admin/devices", dependencies=[Depends(require_admin)])
def admin_add(
    mac:    str = Query(..., description="MAC address (any format)"),
    label:  str = Query("", description="Human label, e.g. 'Lobby phone'"),
    tenant: str = Query("", description="Tenant/client name")
):
    """Register a new device MAC. Required before a phone can provision."""
    mac = normalize_mac(mac)
    add_device(mac, label, tenant)
    return {"status": "added", "mac": mac, "label": label, "tenant": tenant}


@app.delete("/admin/devices/stale", dependencies=[Depends(require_admin)])
def admin_delete_stale(days: int = Query(60)):
    """Delete devices not seen within the given number of days. Connected devices are protected."""
    vpn_status = parse_vpn_status()
    connected_macs = set(vpn_status.keys())
    deleted = delete_stale_devices(days, connected_macs)
    for mac in deleted:
        cert_dir = f"{CACHE_DIR}/certs/{mac}"
        if os.path.exists(cert_dir):
            shutil.rmtree(cert_dir)
    return {"deleted": deleted, "count": len(deleted)}


@app.delete("/admin/devices/{mac}", dependencies=[Depends(require_admin)])
def admin_delete(mac: str):
    """Remove a device from the registry. Does not revoke its cert."""
    mac = normalize_mac(mac)
    delete_device(mac)
    return {"status": "deleted", "mac": mac}


@app.post("/admin/devices/{mac}/refresh-cert", dependencies=[Depends(require_admin)])
async def admin_refresh_cert(mac: str):
    """Revoke and regenerate the cert for a device (lost/stolen phone)."""
    import asyncio
    mac = normalize_mac(mac)

    if not get_device(mac):
        raise HTTPException(status_code=404, detail=f"MAC {mac} not registered")

    cert_dir = f"{CACHE_DIR}/certs/{mac}"
    if os.path.exists(cert_dir):
        shutil.rmtree(cert_dir)

    pki_dir = os.getenv("PKI_DIR", "/etc/openvpn/easy-rsa/pki")
    easyrsa  = os.getenv("EASYRSA_BIN", "/etc/openvpn/easy-rsa/easyrsa")
    cert_path = f"{pki_dir}/issued/{mac}.crt"

    if os.path.exists(cert_path):
        proc = await asyncio.create_subprocess_exec(
            easyrsa, "--batch", "revoke", mac,
            cwd=os.path.dirname(easyrsa),
            env={**os.environ, "EASYRSA_PKI": pki_dir},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()
        proc2 = await asyncio.create_subprocess_exec(
            easyrsa, "--batch", "gen-crl",
            cwd=os.path.dirname(easyrsa),
            env={**os.environ, "EASYRSA_PKI": pki_dir}
        )
        await proc2.communicate()

    await get_or_create_cert(mac)
    return {"status": "cert refreshed", "mac": mac}


@app.delete("/admin/devices/{mac}/cache", dependencies=[Depends(require_admin)])
def admin_clear_cache(mac: str):
    """Force regeneration of the VPN bundle on next provision request."""
    mac = normalize_mac(mac)
    cert_dir = f"{CACHE_DIR}/certs/{mac}"
    tar_path = f"{cert_dir}/vpn.tar.gz"
    if os.path.exists(tar_path):
        os.remove(tar_path)
    return {"status": "cache cleared", "mac": mac}


@app.get("/admin/status", dependencies=[Depends(require_admin)])
def admin_status():
    """Return all devices merged with current VPN connection status."""
    devices = list_devices()
    vpn_status = parse_vpn_status()
    enriched = []
    for d in devices:
        mac = d["mac"]
        vpn = vpn_status.get(mac, {})
        enriched.append({
            **d,
            "connected": mac in vpn_status,
            "vpn_ip": vpn.get("vpn_ip"),
            "real_ip": vpn.get("real_ip"),
            "bytes_rx": vpn.get("bytes_rx"),
            "bytes_tx": vpn.get("bytes_tx"),
            "connected_since": vpn.get("connected_since"),
        })
    return {
        "devices": enriched,
        "connected_count": sum(1 for d in enriched if d["connected"]),
        "total_count": len(enriched),
    }


# ── Dashboard ──────────────────────────────────────────────────────────────────

@app.get("/dashboard/login", response_class=HTMLResponse)
def dashboard_login_page():
    if not DASHBOARD_PASSWORD:
        return HTMLResponse(content=_login_html(
            "Dashboard authentication is not configured. "
            "Add DASHBOARD_USER and DASHBOARD_PASSWORD to /opt/cts-prov/.env and restart the service."
        ), status_code=503)
    return HTMLResponse(content=_login_html())


@app.post("/dashboard/login")
async def dashboard_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ip = request.client.host

    if not DASHBOARD_PASSWORD:
        return HTMLResponse(content=_login_html("Dashboard authentication is not configured."), status_code=503)

    if not _rate_ok(ip):
        return HTMLResponse(
            content=_login_html("Too many failed attempts. Try again in 15 minutes."),
            status_code=429,
        )

    if (secrets.compare_digest(username, DASHBOARD_USER) and
            secrets.compare_digest(password, DASHBOARD_PASSWORD)):
        _rate_clear(ip)
        token = _session_create()
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(
            key="cts_session",
            value=token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=SESSION_TTL,
        )
        return response

    _rate_fail(ip)
    remaining = LOGIN_MAX - len([
        t for t in _login_failures.get(ip, [])
        if time.time() - t < LOGIN_WIN
    ])
    return HTMLResponse(
        content=_login_html(f"Invalid username or password. {max(remaining, 0)} attempt(s) remaining."),
        status_code=401,
    )


@app.get("/dashboard/logout")
def dashboard_logout():
    response = RedirectResponse(url="/dashboard/login", status_code=303)
    response.delete_cookie("cts_session")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(cts_session: Optional[str] = Cookie(default=None)):
    if not DASHBOARD_PASSWORD:
        return RedirectResponse(url="/dashboard/login", status_code=302)
    if not _session_valid(cts_session):
        return RedirectResponse(url="/dashboard/login", status_code=302)
    return HTMLResponse(content=DASHBOARD_HTML)
