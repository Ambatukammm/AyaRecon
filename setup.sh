#!/usr/bin/env bash
# AyaRecon setup launcher for Linux/macOS. Made by Ruel.
# Installs Python dependencies, then reports which external tools are missing.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "  AyaRecon setup - made by Ruel"
echo "========================================"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 not found. Install Python 3.9+ first."
    exit 1
fi

python3 "$DIR/install.py" "$@"
echo
echo "To start AyaRecon:  python3 \"$DIR/main.py\""
echo "Tip: live packet capture needs root — run capture features with sudo."
