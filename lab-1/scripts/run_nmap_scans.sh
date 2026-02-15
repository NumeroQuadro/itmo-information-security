#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <TARGET_IP_OR_HOST>"
    exit 1
fi

TARGET="$1"

if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: nmap is not installed."
    exit 1
fi

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run this script as root (sudo) for raw packet scans."
    exit 1
fi

echo "[1/6] OS detection scan"
nmap -O -Pn -v "$TARGET"
sleep 1

echo "[2/6] SYN scan"
nmap -sS -Pn -p 1-1024 -T3 "$TARGET"
sleep 1

echo "[3/6] FIN scan"
nmap -sF -Pn -p 1-1024 -T3 "$TARGET"
sleep 1

echo "[4/6] NULL scan"
nmap -sN -Pn -p 1-1024 -T3 "$TARGET"
sleep 1

echo "[5/6] XMAS scan"
nmap -sX -Pn -p 1-1024 -T3 "$TARGET"
sleep 1

echo "[6/6] UDP scan (top 50 ports)"
nmap -sU -Pn --top-ports 50 -T3 "$TARGET"

echo "Done."
