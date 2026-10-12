#!/usr/bin/env bash
set -u

BASE_DIR="${SMPP_MONITOR_HOME:-$(cd "$(dirname "$0")" && pwd)}"
CONFIG_FILE="$BASE_DIR/smpp_suppliers.conf"
CAPTURE_DIR="$BASE_DIR/captures/ring"
PID_DIR="$BASE_DIR/pids"
PID_FILE="$PID_DIR/capture.pid"
DUMPCAP_PID_FILE="$PID_DIR/capture.dumpcap.pid"
INTERFACE="${INTERFACE:-any}"
ROTATE_SECONDS="${ROTATE_SECONDS:-60}"
SNAPLEN="${SNAPLEN:-1024}"
CONFIG_CHECK_INTERVAL="${CONFIG_CHECK_INTERVAL:-5}"
CAPTURE_RETENTION_MINUTES="${CAPTURE_RETENTION_MINUTES:-30}"
# Internal cadence; retention is the only user-facing cleanup setting.
CAPTURE_CLEANUP_INTERVAL=300

mkdir -p "$CAPTURE_DIR" "$PID_DIR"
echo $$ > "$PID_FILE"
dumpcap_pid=""
config_signature=""
reload_requested=1
last_capture_cleanup=0

log() { echo "$(date '+%F %T') $*"; }
configuration_signature() { cksum "$CONFIG_FILE" 2>/dev/null | awk '{print $1 ":" $2}'; }

build_capture_filter() {
    awk '
        function emit() {
            if (section != "" && ip != "" && port ~ /^[0-9]+$/) {
                if (count > 0) printf " or "
                printf "(host %s and port %s)", ip, port
                count++
            }
        }
        /^\[/ { emit(); section=$0; ip=""; port=""; next }
        /^[[:space:]]*ip[[:space:]]*=/ {
            split($0, a, "="); ip=a[2]; gsub(/[[:space:]]/, "", ip); next
        }
        /^[[:space:]]*port[[:space:]]*=/ {
            split($0, a, "="); port=a[2]; gsub(/[[:space:]]/, "", port); next
        }
        END { emit() }
    ' "$CONFIG_FILE"
}

stop_dumpcap() {
    if [ -n "$dumpcap_pid" ] && kill -0 "$dumpcap_pid" 2>/dev/null; then
        kill -TERM "$dumpcap_pid" 2>/dev/null || true
        wait "$dumpcap_pid" 2>/dev/null || true
    fi
    dumpcap_pid=""
    rm -f "$DUMPCAP_PID_FILE"
}

start_dumpcap() {
    if ! command -v dumpcap >/dev/null 2>&1; then
        log "ERROR dumpcap not found"
        return 1
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
        log "ERROR config not found: $CONFIG_FILE"
        return 1
    fi
    local capture_filter started_at output new_pid
    capture_filter=$(build_capture_filter)
    if [ -z "$capture_filter" ]; then
        log "ERROR no valid supplier ip/port found in $CONFIG_FILE"
        return 1
    fi
    started_at=$(date +%Y%m%d_%H%M%S)
    output="$CAPTURE_DIR/smpp_${started_at}.pcapng"
    log "starting dumpcap interface=$INTERFACE rotate=${ROTATE_SECONDS}s snaplen=$SNAPLEN"
    log "capture filter: $capture_filter"
    dumpcap -q -i "$INTERFACE" -s "$SNAPLEN" -f "$capture_filter" \
        -b "duration:$ROTATE_SECONDS" -w "$output" &
    new_pid=$!
    sleep 1
    if ! kill -0 "$new_pid" 2>/dev/null; then
        wait "$new_pid" 2>/dev/null || true
        log "ERROR dumpcap failed to start"
        return 1
    fi
    dumpcap_pid="$new_pid"
    echo "$dumpcap_pid" > "$DUMPCAP_PID_FILE"
    config_signature=$(configuration_signature)
    log "dumpcap running pid=$dumpcap_pid"
}

restart_dumpcap() {
    log "reloading capture configuration"
    stop_dumpcap
    start_dumpcap
}

cleanup_expired_captures() {
    local now capture newest
    now=$(date +%s)
    if [ $((now - last_capture_cleanup)) -lt "$CAPTURE_CLEANUP_INTERVAL" ]; then
        return
    fi

    # Never remove the newest file because dumpcap may still be writing it.
    newest=$(
        find "$CAPTURE_DIR" -maxdepth 1 -type f \
            \( -name '*.pcap' -o -name '*.pcapng' \) \
            -printf '%T@ %p\n' 2>/dev/null \
        | sort -nr | head -1 | cut -d' ' -f2-
    )

    while IFS= read -r capture; do
        [ -n "$capture" ] || continue
        [ "$capture" = "$newest" ] && continue
        log "remove expired capture: $capture"
        rm -f "$capture"
    done < <(
        find "$CAPTURE_DIR" -maxdepth 1 -type f \
            \( -name '*.pcap' -o -name '*.pcapng' \) \
            -mmin +"$CAPTURE_RETENTION_MINUTES" 2>/dev/null
    )
    last_capture_cleanup="$now"
}

cleanup() {
    log "stopping capture supervisor"
    stop_dumpcap
    rm -f "$PID_FILE"
    exit 0
}
request_reload() { reload_requested=1; }
trap cleanup TERM INT
trap request_reload HUP
log "capture supervisor started"

while true; do
    current_signature=$(configuration_signature)
    if [ "$reload_requested" -eq 1 ] || [ "$current_signature" != "$config_signature" ]; then
        reload_requested=0
        if ! restart_dumpcap; then
            sleep "$CONFIG_CHECK_INTERVAL"
            continue
        fi
    elif [ -z "$dumpcap_pid" ] || ! kill -0 "$dumpcap_pid" 2>/dev/null; then
        log "dumpcap stopped unexpectedly; restarting"
        start_dumpcap || true
    fi
    cleanup_expired_captures
    sleep "$CONFIG_CHECK_INTERVAL"
done
