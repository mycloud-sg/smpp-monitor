#!/usr/bin/env bash
set -u

BASE_DIR="${SMPP_MONITOR_HOME:-$(cd "$(dirname "$0")" && pwd)}"
PID_DIR="$BASE_DIR/pids"
CAPTURE_WORKER="$BASE_DIR/smpp_capture_worker.sh"
DETECTOR_WORKER="$BASE_DIR/smpp_detector_worker.sh"
CAPTURE_PID_FILE="$PID_DIR/capture.pid"
CAPTURE_ENGINE_PID_FILE="$PID_DIR/capture.dumpcap.pid"
DETECTOR_PID_FILE="$PID_DIR/detector.pid"
mkdir -p "$PID_DIR"

is_running() {
    local pid_file="$1" pid
    [ -f "$pid_file" ] || return 1
    pid=$(cat "$pid_file" 2>/dev/null) || return 1
    kill -0 "$pid" 2>/dev/null
}

start_one() {
    local name="$1" script="$2" pid_file="$3" log_file="$4"
    if is_running "$pid_file"; then
        echo "$name already running pid=$(cat "$pid_file")"
        return
    fi
    rm -f "$pid_file"
    echo "start $name"
    nohup bash "$script" >> "$log_file" 2>&1 &
    sleep 1
    if ! is_running "$pid_file"; then
        echo "$name failed to start; check $log_file" >&2
        return 1
    fi
}

start() {
    start_one "capture" "$CAPTURE_WORKER" "$CAPTURE_PID_FILE" "$BASE_DIR/capture.log"
    start_one "detector" "$DETECTOR_WORKER" "$DETECTOR_PID_FILE" "$BASE_DIR/detector.log"
}

stop_one() {
    local name="$1" pid_file="$2" pid count=0
    if ! is_running "$pid_file"; then
        echo "$name not running"
        rm -f "$pid_file"
        return
    fi
    pid=$(cat "$pid_file")
    echo "stop $name pid=$pid"
    kill "$pid" 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null && [ "$count" -lt 20 ]; do
        sleep 0.25
        count=$((count + 1))
    done
    rm -f "$pid_file"
}

stop() {
    stop_one "detector" "$DETECTOR_PID_FILE"
    stop_one "capture" "$CAPTURE_PID_FILE"
}

reload_capture() {
    if ! is_running "$CAPTURE_PID_FILE"; then
        echo "capture not running" >&2
        return 1
    fi
    kill -HUP "$(cat "$CAPTURE_PID_FILE")"
    echo "capture reload requested"
}

show_status() {
    if is_running "$CAPTURE_PID_FILE"; then
        echo "capture supervisor running pid=$(cat "$CAPTURE_PID_FILE")"
    else
        echo "capture supervisor stopped"
    fi
    if is_running "$CAPTURE_ENGINE_PID_FILE"; then
        echo "dumpcap running pid=$(cat "$CAPTURE_ENGINE_PID_FILE")"
    else
        echo "dumpcap stopped"
    fi
    if is_running "$DETECTOR_PID_FILE"; then
        echo "detector running pid=$(cat "$DETECTOR_PID_FILE")"
    else
        echo "detector stopped"
    fi
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    reload) reload_capture ;;
    status|tcpdump-status) show_status ;;
    *) echo "Usage: $0 {start|stop|restart|reload|status}"; exit 1 ;;
esac
