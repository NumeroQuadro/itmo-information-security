#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 <INTERFACE> <TARGET_IP_OR_HOST> [SNORT_CONF]"
    echo "Example: $0 eth0 192.168.56.101 /etc/snort/snort.conf"
    exit 1
fi

IFACE="$1"
TARGET="$2"
SNORT_CONF="${3:-/etc/snort/snort.conf}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run this script as root (sudo)."
    exit 1
fi

if ! command -v snort >/dev/null 2>&1; then
    echo "Error: snort is not installed."
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: nmap is not installed."
    exit 1
fi

if [[ ! -f "$SNORT_CONF" ]]; then
    echo "Error: snort config not found: $SNORT_CONF"
    exit 1
fi

SNORT_PID=""
cleanup() {
    if [[ -n "$SNORT_PID" ]] && kill -0 "$SNORT_PID" 2>/dev/null; then
        kill "$SNORT_PID" >/dev/null 2>&1 || true
        wait "$SNORT_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[+] Testing Snort config"
snort -T -c "$SNORT_CONF" -i "$IFACE" >/dev/null

echo "[+] Starting Snort on $IFACE"
snort -q -A fast -c "$SNORT_CONF" -i "$IFACE" -l "$LOG_DIR" &
SNORT_PID=$!
sleep 3

echo "[+] Running Nmap scans against $TARGET"
"$SCRIPT_DIR/run_nmap_scans.sh" "$TARGET"
sleep 3

echo "[+] Stopping Snort"
cleanup
SNORT_PID=""

ALERT_FILE="$LOG_DIR/alert"
if [[ ! -f "$ALERT_FILE" ]]; then
    echo "No alert file found: $ALERT_FILE"
    exit 1
fi

echo "[+] LAB alerts summary"
grep "LAB " "$ALERT_FILE" || echo "No LAB alerts matched."

echo "[+] Full alert log: $ALERT_FILE"
