#!/usr/bin/env bash
# build_installer.sh — Build a self-extracting CTS installer .run package
# Usage: bash build_installer.sh [output-dir]
# Requires: makeself (installed automatically if missing)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR}"
OUTPUT_NAME="cts-prov-installer-$(date +%Y%m%d).run"
OUTPUT_PATH="$OUTPUT_DIR/$OUTPUT_NAME"
STAGING="/tmp/cts-prov-staging-$$"

echo "=== CTS Installer Package Builder ==="
echo

# Install makeself if needed
if ! command -v makeself &>/dev/null; then
    echo "Installing makeself..."
    apt-get install -y makeself -q
fi

# Create staging directory with only the files users need
echo "Staging files..."
mkdir -p "$STAGING"

rsync -a \
    --exclude='.env' \
    --exclude='.git/' \
    --exclude='venv/' \
    --exclude='cache/' \
    --exclude='devices.db' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='*.run' \
    --exclude='wireguard-clients/' \
    "$SCRIPT_DIR/" "$STAGING/"

# Ensure all scripts are executable in the package
chmod +x "$STAGING/install.sh"
chmod +x "$STAGING/setup.sh"
chmod +x "$STAGING/renew-crl.sh"
chmod +x "$STAGING/wireguard/gen-client.sh"

echo "Staged $(find "$STAGING" -type f | wc -l) files."
echo

# Build the self-extracting archive
# makeself extracts to a temp dir and runs ./install.sh from inside it.
makeself \
    --gzip \
    --sha256 \
    "$STAGING" \
    "$OUTPUT_PATH" \
    "CTS VPN Provisioning Proxy Installer" \
    ./install.sh

# Report
SIZE=$(du -sh "$OUTPUT_PATH" | cut -f1)
SHA=$(sha256sum "$OUTPUT_PATH" | awk '{print $1}')

echo
echo "  Output:  $OUTPUT_PATH"
echo "  Size:    $SIZE"
echo "  SHA256:  $SHA"
echo
echo "Deploy:"
echo "  scp $OUTPUT_PATH root@<server>:~/"
echo "  ssh root@<server> 'bash ~/$OUTPUT_NAME'"
echo

# Cleanup
rm -rf "$STAGING"
