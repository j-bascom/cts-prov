import asyncio
import os
import tarfile
from dotenv import load_dotenv

load_dotenv()

PKI_DIR   = os.getenv("PKI_DIR",    "/etc/openvpn/easy-rsa/pki")
EASYRSA   = os.getenv("EASYRSA_BIN", "/etc/openvpn/easy-rsa/easyrsa")
CACHE_DIR = os.getenv("CACHE_DIR",  "/opt/cts-prov/cache")
VULTR_IP  = os.getenv("VULTR_PUBLIC_IP", "")
VPN_PORT  = os.getenv("VPN_PORT", "1194")


async def get_or_create_cert(mac: str) -> str:
    """
    Returns path to vpn.tar.gz for this MAC.
    Generates a new per-device cert via Easy-RSA if one doesn't already exist.
    Idempotent — safe to call on every provision request.
    """
    cert_dir  = f"{CACHE_DIR}/certs/{mac}"
    tar_path  = f"{cert_dir}/vpn.tar.gz"
    cert_path = f"{PKI_DIR}/issued/{mac}.crt"
    key_path  = f"{PKI_DIR}/private/{mac}.key"

    os.makedirs(cert_dir, exist_ok=True)

    # Generate cert if not present in PKI
    if not os.path.exists(cert_path):
        proc = await asyncio.create_subprocess_exec(
            EASYRSA, "--batch", "build-client-full", mac, "nopass",
            cwd=os.path.dirname(EASYRSA),
            env={**os.environ, "EASYRSA_PKI": PKI_DIR},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"Easy-RSA cert generation failed for {mac}:\n{stderr.decode()}"
            )

    # Build tar.gz if not already cached
    if not os.path.exists(tar_path):
        _build_vpn_bundle(mac, cert_dir, cert_path, key_path)

    return tar_path


def _build_vpn_bundle(mac: str, cert_dir: str, cert_path: str, key_path: str):
    """
    Assembles the vpn.tar.gz Yealink expects.
    Archive contains a single client.ovpn with inline certs (no separate files).
    """
    ca_path = f"{PKI_DIR}/ca.crt"

    ta_path = "/etc/openvpn/server/ta.key"

    with open(ca_path)   as f: ca   = f.read().strip()
    with open(cert_path) as f: cert = f.read().strip()
    with open(key_path)  as f: key  = f.read().strip()
    with open(ta_path)   as f: ta   = f.read().strip()

    # Strip everything before the actual cert/key block
    # Easy-RSA includes extra headers that confuse some Yealink firmware
    cert = _extract_pem_block(cert, "CERTIFICATE")
    key  = _extract_pem_block(key,  "PRIVATE KEY")

    ovpn_content = f"""client
dev tun
proto udp
remote {VULTR_IP} {VPN_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
key-direction 1
verb 3
keepalive 10 120

<ca>
{ca}
</ca>
<cert>
{cert}
</cert>
<key>
{key}
</key>
<tls-auth>
{ta}
</tls-auth>
"""

    ovpn_path = f"{cert_dir}/client.ovpn"
    with open(ovpn_path, "w") as f:
        f.write(ovpn_content)

    tar_path = f"{cert_dir}/vpn.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        # Yealink expects client.ovpn at root of the archive
        tar.add(ovpn_path, arcname="client.ovpn")

    # Secure the key material
    os.chmod(key_path, 0o600)
    os.chmod(ovpn_path, 0o600)


def _extract_pem_block(pem_text: str, block_type: str) -> str:
    """Extract just the -----BEGIN ... END----- block, stripping any preceding headers."""
    lines = pem_text.splitlines()
    in_block = False
    result = []
    for line in lines:
        if f"-----BEGIN {block_type}-----" in line or f"-----BEGIN" in line and block_type in line:
            in_block = True
        if in_block:
            result.append(line)
        if f"-----END" in line and in_block:
            break
    return "\n".join(result)
