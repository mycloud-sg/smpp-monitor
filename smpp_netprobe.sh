#!/usr/bin/env bash
# Collect live network evidence for one incident while the problem may still be
# happening: an ICMP mtr toward the supplier (where along the path loss starts)
# and periodic `ss -tin` samples of the real SMPP sockets (what TCP itself sees).
# smpp_netprobe_summary.py then turns both, plus the incident's pcap
# retransmission events, into a few lines of conclusions in net/summary.txt and
# the incident's diagnosis.txt. The incident archive is rebuilt (and re-exported
# when EXPORT_DIR is set).
#
# There is deliberately no `mtr -T`: mtr opens real TCP connections to the
# supplier's SMPP port, the kernel's SYN retries make its latencies read as
# 1s/3s/7s, and the probe connections land in the shared PCAP ring where the
# detector counted them as TCP_RESET events. The real SMPP connections are the
# better TCP probe and are already captured.
#
# smpp_incident.sh starts this detached, so the detector is never blocked.
set -u

BASE_DIR="${SMPP_MONITOR_HOME:-$(cd "$(dirname "$0")" && pwd)}"
INCIDENT_DIR="$BASE_DIR/incidents"
LOCK_DIR="$BASE_DIR/locks"

MTR_COUNT="${NETPROBE_MTR_COUNT:-120}"
MTR_INTERVAL="${NETPROBE_MTR_INTERVAL:-1}"
SS_SECONDS="${NETPROBE_SS_SECONDS:-120}"
SS_INTERVAL="${NETPROBE_SS_INTERVAL:-2}"

if [ $# -ne 3 ]; then
    echo "Usage: $0 incident_id ip port" >&2
    exit 1
fi

INCIDENT_ID="$1"
IP="$2"
PORT="$3"
WORK_DIR="$INCIDENT_DIR/$INCIDENT_ID"
NET_DIR="$WORK_DIR/net"
ARCHIVE="$INCIDENT_DIR/${INCIDENT_ID}.tar.gz"

if [ ! -d "$WORK_DIR" ]; then
    echo "incident dir not found: $WORK_DIR" >&2
    exit 1
fi

# One probe per target at a time; a second incident for the same target while
# one is running would only duplicate the same measurement.
mkdir -p "$LOCK_DIR" "$NET_DIR"
LOCK_FILE="$LOCK_DIR/netprobe-${IP}-${PORT}.lock"
# Open without truncating so a loser can still read the holder's incident id.
exec 9<>"$LOCK_FILE"
if ! flock -n 9; then
    HOLDER=$(head -1 "$LOCK_FILE" 2>/dev/null)
    {
        echo "skipped: another netprobe for $IP:$PORT is running"
        [ -n "$HOLDER" ] && echo "see: incidents/$HOLDER/net/"
    } > "$NET_DIR/skipped.txt"
    exit 0
fi
echo "$INCIDENT_ID" > "$LOCK_FILE"

now() { date '+%F %T.%3N %Z'; }

run_mtr() {
    # $1 = output file, rest = extra mtr args
    local out="$1"; shift
    if ! command -v mtr >/dev/null 2>&1; then
        echo "mtr command not found" > "$out"
        return
    fi
    {
        echo "# start $(now)"
        echo "# mtr -n -r -w -c $MTR_COUNT -i $MTR_INTERVAL $* $IP"
        mtr -n -r -w -c "$MTR_COUNT" -i "$MTR_INTERVAL" "$@" "$IP" 2>&1
        echo "# end $(now)"
    } > "$out"
}

sample_ss() {
    local out="$NET_DIR/ss-series.txt"
    local end=$(( $(date +%s) + SS_SECONDS ))
    : > "$out"
    while [ "$(date +%s)" -lt "$end" ]; do
        {
            echo "### $(now)"
            ss -tin "dst $IP and dport = :$PORT" 2>&1
        } >> "$out"
        sleep "$SS_INTERVAL"
    done
}

{
    echo "incident=$INCIDENT_ID"
    echo "target=$IP:$PORT"
    echo "start=$(now)"
    echo "mtr_count=$MTR_COUNT mtr_interval=$MTR_INTERVAL"
    echo "ss_seconds=$SS_SECONDS ss_interval=$SS_INTERVAL"
} > "$NET_DIR/info.txt"

command -v nstat >/dev/null 2>&1 && nstat -asz > "$NET_DIR/nstat-start.txt" 2>&1
ip route get "$IP" > "$NET_DIR/route.txt" 2>&1

run_mtr "$NET_DIR/mtr-icmp.txt" &
sample_ss &
wait

command -v nstat >/dev/null 2>&1 && nstat -asz > "$NET_DIR/nstat-end.txt" 2>&1
ip -s link > "$NET_DIR/ip-link-stats-end.txt" 2>&1
echo "end=$(now)" >> "$NET_DIR/info.txt"

# Conclusions go to net/summary.txt and into the incident's diagnosis.txt (the
# copy under incidents/, which the re-export below sends to the web backend).
python3 "$BASE_DIR/smpp_netprobe_summary.py" "$NET_DIR" "$IP" \
    --details "$WORK_DIR/details.json" --diagnosis "$WORK_DIR/diagnosis.txt" \
    > "$NET_DIR/summary.txt" 2> "$NET_DIR/summary.err" \
    || echo "netprobe summary failed: see $NET_DIR/summary.err"
[ -s "$NET_DIR/summary.err" ] || rm -f "$NET_DIR/summary.err"

# Rebuild the archive atomically so readers never see a half-written file.
tar -C "$INCIDENT_DIR" -czf "$ARCHIVE.tmp" "$INCIDENT_ID" && mv -f "$ARCHIVE.tmp" "$ARCHIVE"
echo "netprobe done: $ARCHIVE"

if [ -n "${EXPORT_DIR:-}" ]; then
    python3 "$BASE_DIR/smpp_incident_export.py" "$EXPORT_DIR" "$INCIDENT_ID" \
        "$WORK_DIR/details.json" "$WORK_DIR/diagnosis.txt" "$ARCHIVE" 2>&1 \
        || echo "incident re-export failed: $INCIDENT_ID"
fi
