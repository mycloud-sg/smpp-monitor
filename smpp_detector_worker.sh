#!/usr/bin/env bash
set -u

BASE_DIR="${SMPP_MONITOR_HOME:-$(cd "$(dirname "$0")" && pwd)}"
CAPTURE_DIR="$BASE_DIR/captures/ring"
DETECTOR="$BASE_DIR/smpp_detector.py"
PID_DIR="$BASE_DIR/pids"
STATE_DIR="$BASE_DIR/state/processed"
LAST_PROCESSED_FILE="$BASE_DIR/state/last-processed.txt"
INCIDENT_DIR="$BASE_DIR/incidents"
LOG_FILE="$BASE_DIR/detector.log"
PID_FILE="$PID_DIR/detector.pid"
LAST_CLEANUP_FILE="$BASE_DIR/state/last_cleanup"
INTERVAL="${INTERVAL:-15}"
INCIDENT_RETENTION_DAYS="${INCIDENT_RETENTION_DAYS:-3}"

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
            {
                echo "time=$(date '+%F %T %Z')"
                echo "status=normal"
                echo "capture=$capture"
            } > "$LAST_PROCESSED_FILE"
            ;;
        2)
            log "diagnosis created from $filename"
            touch "$done_file"
            {
                echo "time=$(date '+%F %T %Z')"
                echo "status=diagnosis_created"
                echo "capture=$capture"
            } > "$LAST_PROCESSED_FILE"
            ;;
        *)
            log "detector failed capture=$capture result=$result"
            [ -z "$output" ] || log "$output"
            {
                echo "time=$(date '+%F %T %Z')"
                echo "status=failed"
                echo "capture=$capture"
                echo "result=$result"
            } > "$LAST_PROCESSED_FILE"
            ;;
    esac
}

scan_completed_captures() {
    local capture previous=""

    # Take one ordered snapshot. Using separate "newest" and "all files"
    # queries creates a race when dumpcap rotates between the two queries.
    # Hold one item back while reading so the last item is never processed.
    while IFS= read -r capture; do
        [ -n "$capture" ] || continue
        if [ -n "$previous" ] && [ -f "$previous" ]; then
            process_capture "$previous"
        fi
        previous="$capture"
    done < <(
        find "$CAPTURE_DIR" -maxdepth 1 -type f \
            \( -name '*.pcap' -o -name '*.pcapng' \) \
            -printf '%T@ %p\n' 2>/dev/null \
        | sort -n | cut -d' ' -f2-
    )
}

periodic_cleanup() {
    local now last=0 done_file capture_name
    now=$(date +%s)
    if [ -f "$LAST_CLEANUP_FILE" ]; then
        last=$(cat "$LAST_CLEANUP_FILE" 2>/dev/null || echo 0)
    fi
    [ $((now - last)) -lt 3600 ] && return

    # Capture worker owns PCAP retention. Detector only removes stale state.
    while IFS= read -r done_file; do
        [ -n "$done_file" ] || continue
        capture_name=$(basename "$done_file" .done)
        if [ ! -f "$CAPTURE_DIR/$capture_name" ]; then
            rm -f "$done_file"
        fi
    done < <(find "$STATE_DIR" -maxdepth 1 -type f -name '*.done' 2>/dev/null)

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
