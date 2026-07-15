#!/bin/bash
# Download fresh US CIDR list and rebuild the geoblock ipset.
# Run weekly via cron. Safe to run while live — uses a swap-in approach.
set -euo pipefail

ZONE_URL="https://www.ipdeny.com/ipblocks/data/aggregated/us-aggregated.zone"
ZONE_FILE="/opt/cts-prov/geo/us.zone"
SET_NAME="cts-us-allow"
TMP_SET="cts-us-allow-new"

curl -sS "$ZONE_URL" -o "$ZONE_FILE"

# Build new set into a temp name, then swap
ipset create "$TMP_SET" hash:net family inet hashsize 65536 maxelem 65536 2>/dev/null || ipset flush "$TMP_SET"
while IFS= read -r cidr; do
    [[ -z "$cidr" || "$cidr" == \#* ]] && continue
    ipset add "$TMP_SET" "$cidr" 2>/dev/null || true
done < "$ZONE_FILE"

# Atomic swap
ipset create "$SET_NAME" hash:net family inet hashsize 65536 maxelem 65536 2>/dev/null || true
ipset swap "$TMP_SET" "$SET_NAME"
ipset destroy "$TMP_SET"

echo "$(date): geoblock updated — $(ipset list $SET_NAME | grep -c '/') CIDRs loaded"
