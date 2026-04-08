#!/bin/bash
# Direct Chrome browser stress test
# Uses Chrome in headless mode with direct network requests through proxy

set -e

PROXY="http://127.0.0.1:11080"
SERVER_PORT=18443
LISTEN_PORT=11080
NUM_CHROME=5
PAGES_PER_CHROME=5
LOG_DIR="test/logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

mkdir -p "$LOG_DIR"

cleanup() {
    log_info "Cleaning up..."
    pkill -9 -f qtunnel_server 2>/dev/null || true
    pkill -9 -f qtunnel_client 2>/dev/null || true
    pkill -9 -f chromium-browser 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

log_info "================================"
log_info "Chrome Direct Stress Test"
log_info "================================"
log_info "Proxy: $PROXY"
log_info "Chrome instances: $NUM_CHROME"
log_info "Pages per instance: $PAGES_PER_CHROME"

# Start server and client
log_info "Starting qtunnel server..."
./build/qtunnel_server --listen "$SERVER_PORT" \
    --cert-file test/certs/server.crt \
    --key-file test/certs/server.key \
    --log-level Info > "$LOG_DIR/chrome_server.log" 2>&1 &
SERVER_PID=$!

log_info "Starting qtunnel client..."
./build/qtunnel_client "127.0.0.1:$SERVER_PORT" \
    --listen "$LISTEN_PORT" \
    --log-level info > "$LOG_DIR/chrome_client.log" 2>&1 &
CLIENT_PID=$!

sleep 3

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    log_error "Server failed to start"
    exit 1
fi

if ! ps -p $CLIENT_PID > /dev/null 2>&1; then
    log_error "Client failed to start"
    exit 1
fi

log_info "Servers started (PID: $SERVER_PID, $CLIENT_PID)"

# Test URLs
declare -a URLS=(
    "https://www.google.com/"
    "https://www.github.com/"
    "https://www.wikipedia.org/"
)

# Chrome launch function
launch_chrome_instance() {
    local instance_id=$1
    local instance_log="$LOG_DIR/chrome_instance_$instance_id.log"

    log_info "Chrome $instance_id: Starting..."

    for page_idx in $(seq 0 $((PAGES_PER_CHROME - 1))); do
        url=${URLS[$((page_idx % ${#URLS[@]}))]}

        log_info "Chrome $instance_id: Loading $url"

        # Use Chrome in headless mode through proxy
        timeout 30 /usr/bin/chromium-browser \
            --headless=new \
            --no-sandbox \
            --disable-gpu \
            --disable-dev-shm-usage \
            --proxy-server="$PROXY" \
            --ignore-certificate-errors \
            --disable-extensions \
            --disable-popup-blocking \
            "$url" \
            > "$instance_log" 2>&1

        result=$?

        if [ $result -eq 0 ]; then
            log_info "Chrome $instance_id: ✓ Page $((page_idx + 1))/$PAGES_PER_CHROME loaded"
        elif [ $result -eq 124 ]; then
            log_warn "Chrome $instance_id: ⏱ Page $((page_idx + 1))/$PAGES_PER_CHROME timed out"
        else
            log_warn "Chrome $instance_id: ✗ Page $((page_idx + 1))/$PAGES_PER_CHROME failed (code: $result)"
        fi

        # Check if server crashed
        if ! ps -p $SERVER_PID > /dev/null 2>&1; then
            log_error "Server crashed during Chrome $instance_id page load!"
            return 1
        fi

        sleep 1
    done

    log_info "Chrome $instance_id: Completed"
    return 0
}

# Launch Chrome instances in parallel
log_info ""
log_info "Launching Chrome instances..."

for i in $(seq 1 $NUM_CHROME); do
    launch_chrome_instance $i &
done

# Wait for all to complete
log_info "Waiting for all Chrome instances..."
failed=0
for job in $(jobs -p); do
    wait $job || ((failed++))
done

log_info ""
log_info "================================"

# Check results
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    log_error "Server crashed!"
    grep -i "segfault" "$LOG_DIR/chrome_server.log" && echo "SEGMENTATION FAULT FOUND"
    exit 1
fi

if grep -i "segmentation fault\|segfault" "$LOG_DIR/chrome_server.log" > /dev/null 2>&1; then
    log_error "SEGMENTATION FAULT DETECTED!"
    grep -i "segmentation fault\|segfault" "$LOG_DIR/chrome_server.log"
    exit 1
fi

log_info "Server is stable ✓"
log_info "Failed instances: $failed"

if [ $failed -eq 0 ]; then
    log_info "✓ All Chrome instances completed successfully"
    exit 0
else
    log_warn "⚠ Some Chrome instances had issues"
    exit 1
fi
