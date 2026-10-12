#!/usr/bin/env bash
set -u

BASE_DIR="${SMPP_MONITOR_HOME:-$(cd "$(dirname "$0")" && pwd)}"
CAPTURE_DIR="$BASE_DIR/captures/ring"
DETECTOR="$BASE_DIR/smpp_detector.py"
PID_DIR="$BASE_DIR/pids"
STATE_DIR="$BASE_DIR/state/processed"
INCIDENT_DIR="$BASE_DIR/incidents"
LOG_FILE="$BASE_DIR/detector.log"
PID_FILE="$PID_DIR/detector.pid"
LAST_CLEANUP_FILE="$BASE_DIR/state/last_cleanup"
INTERVAL="${INTERVAL:-15}"
CAPTURE_KEEP_FILES="${CAPTURE_KEEP_FILES:-60}"
INCIDENT_RETENTION_DAYS="${INCIDENT_RETENTION_DAYS:-7}"

mkdir -p "$CAPTURE_DIR" "$PID_DIR" "$STATE_DIR" "$INCIDENT_DIR"
echo $$ > "$PID_FILE"

log() { echo "$(date '+%F %T') $*" >> "$LOG_FILE"; }

cleanup() {
    log "detector worker stopped"
    rm -f "$PID_FILE"
    exit 0
}
trap cleanup TERM INT

process_capture() {
    local capture="$1" filename done_file output result
    filename=$(basename "$capture")
    done_file="$STATE_DIR/${filename}.done"
    [ -f "$done_file" ] && return

    output=$(python3 "$DETECTOR" "$capture" 2>&1)
    result=$?
    case "$result" in
        0)
            touch "$done_file"
            ;;
        2)
            log "diagnosis created from $filename"
            touch "$done_file"
            ;;
        *)
            log "detector failed capture=$capture result=$result"
            [ -z "$output" ] || log "$output"
            ;;
    esac
}

scan_completed_captures() {
    local newest capture
    newest=$(
        find "$CAPTURE_DIR" -maxdepth 1 -type f \
            \( -name '*.pcap' -o -name '*.pcapng' \) \
            -printf '%T@ %p\n' 2>/dev/null \
        | sort -nr | head -1 | cut -d' ' -f2-
    )

    while IFS= read -r capture; do
        [ -n "$capture" ] || continue
        [ "$capture" = "$newest" ] && continue
        process_capture "$capture"
    done < <(
        find "$CAPTURE_DIR" -maxdepth 1 -type f \
            \( -name '*.pcap' -o -name '*.pcapng' \) \
            -printf '%T@ %p\n' 2>/dev/null \
        | sort -n | cut -d' ' -f2-
    )
}

periodic_cleanup() {
    local now last=0 count remove_count file done_file
    now=$(date +%s)
    if [ -f "$LAST_CLEANUP_FILE" ]; then
        last=$(cat "$LAST_CLEANUP_FILE" 2>/dev/null || echo 0)
    fi
    [ $((now - last)) -lt 3600 ] && return

    count=$(
        find "$CAPTURE_DIR" -maxdepth 1 -type f \
            \( -name '*.pcap' -o -name '*.pcapng' \) | wc -l
    )
    if [ "$count" -gt "$CAPTURE_KEEP_FILES" ]; then
        remove_count=$((count - CAPTURE_KEEP_FILES))
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            rm -f "$file"
            done_file="$STATE_DIR/$(basename "$file").done"
            rm -f "$done_file"
        done < <(
            find "$CAPTURE_DIR" -maxdepth 1 -type f \
                \( -name '*.pcap' -o -name '*.pcapng' \) \
                -printf '%T@ %p\n' 2>/dev/null \
            | sort -n | head -n "$remove_count" | cut -d' ' -f2-
        )
    fi

    find "$INCIDENT_DIR" -maxdepth 1 -type f -name '*.tar.gz' \
        -mtime +"$INCIDENT_RETENTION_DAYS" -delete 2>/dev/null || true
    find "$INCIDENT_DIR" -mindepth 1 -maxdepth 1 -type d \
        -mtime +"$INCIDENT_RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null || true
    echo "$now" > "$LAST_CLEANUP_FILE"
}

if ! command -v tshark >/dev/null 2>&1; then
    log "tshark not found"
    rm -f "$PID_FILE"
    exit 1
fi

log "detector worker started interval=${INTERVAL}s"
while true; do
    scan_completed_captures
    periodic_cleanup
    sleep "$INTERVAL"
done
