#!/bin/bash
# Aggressive concurrent load test to detect segfault
# High concurrency + continuous connections

PROXY="http://127.0.0.1:11080"
SERVER_PORT=18443
LISTEN_PORT=11080
NUM_PARALLEL=50  # Heavy concurrent load
DURATION=300     # 5 minutes
LOG_DIR="test/logs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

mkdir -p "$LOG_DIR"

cleanup() {
    log_info "Cleaning up..."
    pkill -f "curl.*proxy" 2>/dev/null || true
    pkill -9 -f qtunnel_server 2>/dev/null || true
    pkill -9 -f qtunnel_client 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

log_info "=========================================="
log_info "Aggressive Concurrent Load Test"
log_info "=========================================="
log_info "Concurrent requests: $NUM_PARALLEL"
log_info "Duration: ${DURATION}s (5 minutes)"
log_info "Target proxy: $PROXY"

# Start services
log_info "Starting qtunnel server..."
./build/qtunnel_server --listen "$SERVER_PORT" \
    --cert-file test/certs/server.crt \
    --key-file test/certs/server.key \
    --log-level Info > "$LOG_DIR/aggressive_server.log" 2>&1 &
SERVER_PID=$!

log_info "Starting qtunnel client..."
./build/qtunnel_client "127.0.0.1:$SERVER_PORT" \
    --listen "$LISTEN_PORT" \
    --log-level info > "$LOG_DIR/aggressive_client.log" 2>&1 &
CLIENT_PID=$!

sleep 3

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    log_error "Server failed"
    exit 1
fi

# Start continuous monitoring in background
monitor_server() {
    while true; do
        if ! ps -p $SERVER_PID > /dev/null 2>&1; then
            log_error "SERVER CRASHED!"
            echo "CRASH_DETECTED_$(date +%s)" >> "$LOG_DIR/crash.log"
            return 1
        fi

        if grep -i "segfault\|segmentation" "$LOG_DIR/aggressive_server.log" 2>/dev/null; then
            log_error "SEGFAULT DETECTED!"
            return 1
        fi

        sleep 1
    done
}

monitor_server &
MONITOR_PID=$!

log_info ""
log_info "Launching concurrent requests..."
log_info "Press Ctrl+C to stop"
echo ""

start_time=$(date +%s)
request_count=0
success_count=0
fail_count=0

while [ $(($(date +%s) - start_time)) -lt $DURATION ]; do
    # Launch NUM_PARALLEL concurrent requests
    for i in $(seq 1 $NUM_PARALLEL); do
        {
            url="https://www.google.com/"
            timeout 20 curl -s -x "$PROXY" \
                --max-time 15 \
                -H "User-Agent: aggressive-load-test" \
                "$url" > /dev/null 2>&1

            result=$?
            if [ $result -eq 0 ]; then
                ((success_count++))
            else
                ((fail_count++))
            fi
            ((request_count++))
        } &
    done

    # Check server still alive
    if ! ps -p $SERVER_PID > /dev/null 2>&1; then
        log_error "Server crashed during load!"
        kill $MONITOR_PID 2>/dev/null
        exit 1
    fi

    # Print progress
    elapsed=$(($(date +%s) - start_time))
    percent=$((elapsed * 100 / DURATION))
    echo -ne "\r[${percent}%] Requests: $request_count (Success: $success_count, Failed: $fail_count)"

    # Wait a bit
    sleep 2
done

echo ""
log_info ""
log_info "=========================================="

# Stop monitor
kill $MONITOR_PID 2>/dev/null
wait $MONITOR_PID 2>/dev/null

# Check final state
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    log_error "Server crashed!"
    exit 1
fi

if grep -i "segfault\|segmentation" "$LOG_DIR/aggressive_server.log" > /dev/null 2>&1; then
    log_error "SEGMENTATION FAULT FOUND!"
    grep -i "segfault\|segmentation" "$LOG_DIR/aggressive_server.log"
    exit 1
fi

log_info "Test completed successfully"
log_info "Total requests: $request_count"
log_info "Successful: $success_count"
log_info "Failed: $fail_count"
log_info "Server: STABLE (no segfault)"

exit 0
