import os
from dotenv import load_dotenv

load_dotenv()

PROV_DOMAIN = os.getenv("PROV_DOMAIN", "https://prov.example.com")
PROV_TOKEN  = os.getenv("PROV_TOKEN", "")


def vpn_overlay(mac: str) -> str:
    """
    Minimal Yealink config overlay containing only VPN settings.
    Served as the secondary provisioning source; sipcfg.io remains primary.
    The phone merges this with its primary config on each provisioning cycle.
    """
    lines = [
        "#!version:1.0.0.1",
        f"# CTS VPN overlay for {mac}",
        "",
        "static.network.vpn.enable = 1",
        f"static.network.vpn.cnf.url = {PROV_DOMAIN}/vpn/vpn.cnf?token={PROV_TOKEN}",
        "",
    ]
    return "\r\n".join(lines)
