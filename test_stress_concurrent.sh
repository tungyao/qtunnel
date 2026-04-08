#!/bin/bash
# Concurrent stress test for qtunnel HTTP proxy
# Opens multiple concurrent requests to stress test the proxy

set -e

# Configuration
PROXY="http://127.0.0.1:11080"
SERVER_PORT=18443
SOCKS_PORT=11080
NUM_CONCURRENT=20
NUM_CYCLES=5
TIMEOUT=15

# Logging
LOG_DIR="test/logs"
SERVER_LOG="$LOG_DIR/stress_server.log"
CLIENT_LOG="$LOG_DIR/stress_client.log"
STRESS_LOG="$LOG_DIR/stress_test.log"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*" | tee -a "$STRESS_LOG"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "$STRESS_LOG"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$STRESS_LOG"; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $*" | tee -a "$STRESS_LOG"; }

cleanup() {
    log_info "Cleaning up..."
    pkill -f qtunnel_server || true
    pkill -f qtunnel_client || true
    sleep 1
}

trap cleanup EXIT

# Create log directory
mkdir -p "$LOG_DIR"
> "$STRESS_LOG"

log_info "========================================"
log_info "qtunnel HTTP Proxy Stress Test"
log_info "========================================"
log_info "Concurrent connections: $NUM_CONCURRENT"
log_info "Test cycles: $NUM_CYCLES"

# Start server and client
log_info "Starting qtunnel server..."
./build/qtunnel_server --listen "$SERVER_PORT" \
    --cert-file test/certs/server.crt \
    --key-file test/certs/server.key \
    --log-level Info > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

log_info "Starting qtunnel client..."
./build/qtunnel_client "127.0.0.1:$SERVER_PORT" \
    --listen "$SOCKS_PORT" \
    --log-level info > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 2

# Verify processes started
if ! ps -p $SERVER_PID > /dev/null; then
    log_error "Server failed to start"
    exit 1
fi

if ! ps -p $CLIENT_PID > /dev/null; then
    log_error "Client failed to start"
    exit 1
fi

log_info "Processes started: SERVER_PID=$SERVER_PID, CLIENT_PID=$CLIENT_PID"

# Test URLs
URLS=(
    "https://example.com/"
    "https://www.google.com/"
    "https://www.github.com/"
    "https://www.wikipedia.org/"
)

passed=0
failed=0

# Run stress test
log_info "Starting stress test..."
echo ""

for cycle in $(seq 1 $NUM_CYCLES); do
    log_info "========== Cycle $cycle/$NUM_CYCLES =========="

    # Run concurrent requests
    for i in $(seq 1 $NUM_CONCURRENT); do
        {
            url=${URLS[$((i % ${#URLS[@]}))]}

            # Use curl with proxy
            response=$(timeout $TIMEOUT curl -s -x "$PROXY" "$url" \
                -H "User-Agent: qtunnel-stress-test" \
                -H "Accept: */*" \
                -w "\n%{http_code}" 2>/dev/null | tail -1)

            if [ -n "$response" ] && [ "$response" != "000" ]; then
                if [[ "$response" =~ ^[23] ]]; then
                    echo "[Cycle $cycle] Request $i: ✓ $url (HTTP $response)"
                    ((passed++))
                else
                    echo "[Cycle $cycle] Request $i: ✗ $url (HTTP $response)"
                    ((failed++))
                fi
            else
                echo "[Cycle $cycle] Request $i: ✗ $url (No response)"
                ((failed++))
            fi
        } &
    done

    # Wait for all background jobs in this cycle
    wait

    log_info "Cycle $cycle complete. Passed: $passed, Failed: $failed"

    # Check if server is still running
    if ! ps -p $SERVER_PID > /dev/null; then
        log_error "Server crashed!"
        break
    fi

    # Small delay between cycles
    sleep 1
done

echo ""
log_info "========================================"
log_info "Test Results"
log_info "========================================"
log_info "Total Passed: $passed"
log_info "Total Failed: $failed"

if [ $((passed + failed)) -gt 0 ]; then
    success_rate=$((passed * 100 / (passed + failed)))
    log_info "Success Rate: $success_rate%"
fi

# Check server logs for segfault
log_info "Checking for crashes..."
if grep -i "segmentation fault\|segfault" "$SERVER_LOG" > /dev/null; then
    log_error "SEGMENTATION FAULT DETECTED!"
    grep -i "segmentation fault\|segfault" "$SERVER_LOG" | tee -a "$STRESS_LOG"
    exit 1
fi

# Check if server is still alive
if ! ps -p $SERVER_PID > /dev/null; then
    log_error "Server crashed during test!"
    exit 1
else
    log_info "Server is still running: OK"
fi

# Print last lines of server log
log_info "Server log (last 30 lines):"
tail -30 "$SERVER_LOG" | sed 's/^/  /'

if [ $failed -eq 0 ] && ps -p $SERVER_PID > /dev/null; then
    log_info "All tests passed! Server is stable."
    exit 0
else
    log_warn "Some issues detected"
    exit 1
fi
