#!/usr/bin/env bash
set -u

BASE_DIR="${SMPP_MONITOR_HOME:-$(cd "$(dirname "$0")" && pwd)}"
INCIDENT_DIR="$BASE_DIR/incidents"
CONFIG_FILE="$BASE_DIR/smpp_suppliers.conf"

if [ $# -lt 4 ]; then
    echo "Usage: $0 supplier diagnosis.txt details.json pcap [...]" >&2
    exit 1
fi

SUPPLIER="$1"
DIAGNOSIS_FILE="$2"
DETAILS_FILE="$3"
shift 3

INCIDENT_ID=$(basename "$DIAGNOSIS_FILE" .txt)
WORK_DIR="$INCIDENT_DIR/$INCIDENT_ID"
ARCHIVE="$INCIDENT_DIR/${INCIDENT_ID}.tar.gz"
mkdir -p "$WORK_DIR/pcap"

{
    echo "time=$(date '+%F %T %Z')"
    echo "supplier=$SUPPLIER"
    echo "hostname=$(hostname)"
} > "$WORK_DIR/info.txt"

awk -v section="[$SUPPLIER]" '
    $0 == section { found=1 }
    found && /^\[/ && $0 != section { exit }
    found { print }
' "$CONFIG_FILE" > "$WORK_DIR/supplier.conf"

cp -p "$DIAGNOSIS_FILE" "$WORK_DIR/diagnosis.txt"
cp -p "$DETAILS_FILE" "$WORK_DIR/details.json"

for pcap in "$@"; do
    if [ -f "$pcap" ]; then
        cp -p "$pcap" "$WORK_DIR/pcap/"
    fi
done

if command -v ss >/dev/null 2>&1; then
    ss -antp > "$WORK_DIR/ss.txt" 2>&1 || true
else
    echo "ss command not found" > "$WORK_DIR/ss.txt"
fi

tar -C "$INCIDENT_DIR" -czf "$ARCHIVE" "$INCIDENT_ID"
echo "incident created: $ARCHIVE"
