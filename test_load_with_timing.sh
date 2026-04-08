#!/bin/bash
# Load test with timing measurements for qtunnel HTTP proxy
# Tests real webpage requests with concurrent load and timing analysis

set -e

PROXY="http://127.0.0.1:11080"
SERVER_PORT=18443
LISTEN_PORT=11080
NUM_PARALLEL=20
TEST_DURATION=300  # 5 minutes of testing
LOG_DIR="test/logs"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $*"; }

# Setup
mkdir -p "$LOG_DIR"
RESULT_FILE="$LOG_DIR/load_test_results.txt"
TIMING_FILE="$LOG_DIR/load_test_timings.txt"
SERVER_LOG="$LOG_DIR/load_test_server.log"
CLIENT_LOG="$LOG_DIR/load_test_client.log"

> "$RESULT_FILE"
> "$TIMING_FILE"

cleanup() {
    log_info "Cleaning up..."
    pkill -f qtunnel_server 2>/dev/null || true
    pkill -f qtunnel_client 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

log_info "========================================"
log_info "qtunnel Load Test with Timing Metrics"
log_info "========================================"
log_info "Proxy: $PROXY"
log_info "Concurrent requests: $NUM_PARALLEL"
log_info "Test duration: ${TEST_DURATION}s"

# Start server and client
log_info "Starting qtunnel server..."
./build/qtunnel_server --listen "$SERVER_PORT" \
    --cert-file test/certs/server.crt \
    --key-file test/certs/server.key \
    --log-level Info > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

log_info "Starting qtunnel client..."
./build/qtunnel_client "127.0.0.1:$SERVER_PORT" \
    --listen "$LISTEN_PORT" \
    --log-level info > "$CLIENT_LOG" 2>&1 &
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

log_info "Server PID: $SERVER_PID, Client PID: $CLIENT_PID"

# Test URLs (real websites)
declare -a URLS=(
    "https://www.google.com/"
    "https://www.github.com/"
    "https://www.wikipedia.org/"
    "https://www.example.com/"
)

log_info "Test URLs:"
for url in "${URLS[@]}"; do
    log_info "  - $url"
done

# Stats
total_requests=0
successful_requests=0
failed_requests=0
total_time_sum=0
min_time=999999
max_time=0

# Start time
start_time=$(date +%s)
now=$start_time

log_info ""
log_info "Starting load test ($(date))"
log_info ""

# Main load test loop
while [ $(($(date +%s) - start_time)) -lt $TEST_DURATION ]; do
    # Run parallel requests
    for i in $(seq 1 $NUM_PARALLEL); do
        {
            url=${URLS[$((i % ${#URLS[@]}))]}

            # Measure request time
            req_start=$(date +%s%N)

            response=$(timeout 30 curl -s -x "$PROXY" "$url" \
                -H "User-Agent: qtunnel-load-test" \
                -w "\n%{http_code}:%{time_total}" \
                2>/dev/null | tail -1)

            req_end=$(date +%s%N)
            req_time=$(( (req_end - req_start) / 1000000 ))  # Convert to milliseconds

            if [ -n "$response" ]; then
                http_code=$(echo "$response" | cut -d':' -f1)
                curl_time=$(echo "$response" | cut -d':' -f2)

                if [[ "$http_code" =~ ^[23] ]]; then
                    ((successful_requests++))
                    status="✓"
                else
                    ((failed_requests++))
                    status="✗"
                fi
            else
                ((failed_requests++))
                status="✗"
                http_code="000"
                curl_time="timeout"
                req_time=30000
            fi

            ((total_requests++))

            # Update timing stats
            if [ "$curl_time" != "timeout" ]; then
                curl_ms=$(echo "$curl_time * 1000" | bc)
                total_time_sum=$(echo "$total_time_sum + $curl_ms" | bc)

                if [ $(echo "$curl_ms < $min_time" | bc) -eq 1 ]; then
                    min_time=$curl_ms
                fi
                if [ $(echo "$curl_ms > $max_time" | bc) -eq 1 ]; then
                    max_time=$curl_ms
                fi
            fi

            # Log result
            timestamp=$(date "+%H:%M:%S")
            echo "$timestamp $status $url (HTTP $http_code) - curl: ${curl_time}s, total: ${req_time}ms" >> "$TIMING_FILE"

            # Print progress every 10 requests
            if [ $((total_requests % 10)) -eq 0 ]; then
                echo -n "."
            fi
        } &
    done

    # Wait for batch to complete
    wait

    # Check if server is still alive
    if ! ps -p $SERVER_PID > /dev/null 2>&1; then
        log_error "Server crashed!"
        echo "Server crashed at $(date)" >> "$RESULT_FILE"
        exit 1
    fi

    elapsed=$(($(date +%s) - start_time))
    percent=$((elapsed * 100 / TEST_DURATION))
    echo " [$percent%]"
done

end_time=$(date +%s)
total_duration=$((end_time - start_time))

echo ""
log_info "Load test completed"
log_info ""

# Calculate statistics
if [ $successful_requests -gt 0 ]; then
    avg_time=$(echo "scale=2; $total_time_sum / $successful_requests" | bc)
    min_time_s=$(echo "scale=3; $min_time / 1000" | bc)
    max_time_s=$(echo "scale=3; $max_time / 1000" | bc)
else
    avg_time="N/A"
    min_time_s="N/A"
    max_time_s="N/A"
fi

# Print results
echo "========================================"
echo "Test Results"
echo "========================================"
echo "Total requests:     $total_requests"
echo "Successful:         $successful_requests"
echo "Failed:             $failed_requests"
echo "Test duration:      ${total_duration}s"

if [ $total_requests -gt 0 ]; then
    success_rate=$((successful_requests * 100 / total_requests))
    echo "Success rate:       $success_rate%"
fi

echo ""
echo "Timing Statistics (ms):"
echo "Average response:   ${avg_time}ms"
echo "Minimum response:   ${min_time_s}s"
echo "Maximum response:   ${max_time_s}s"

# Save results
{
    echo "========================================"
    echo "qtunnel Load Test Results"
    echo "========================================"
    echo "Test time: $(date)"
    echo "Total requests:     $total_requests"
    echo "Successful:         $successful_requests"
    echo "Failed:             $failed_requests"
    echo "Test duration:      ${total_duration}s"
    echo "Success rate:       $success_rate%"
    echo ""
    echo "Timing Statistics (ms):"
    echo "Average:   ${avg_time}ms"
    echo "Minimum:   ${min_time_s}s"
    echo "Maximum:   ${max_time_s}s"
    echo ""
    echo "Details logged to: $TIMING_FILE"
} | tee "$RESULT_FILE"

# Check for server crashes
log_info ""
log_info "Checking for server stability..."

if grep -i "segmentation fault\|segfault" "$SERVER_LOG" > /dev/null 2>&1; then
    log_error "SEGMENTATION FAULT DETECTED!"
    exit 1
fi

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    log_error "Server crashed!"
    exit 1
fi

log_info "Server is stable ✓"

# Summary
echo ""
echo "========================================"
if [ $failed_requests -eq 0 ] && ps -p $SERVER_PID > /dev/null 2>&1; then
    log_info "✓ Load test PASSED - All requests successful, server stable"
    exit 0
else
    log_warn "⚠ Load test completed with issues"
    echo "Check $RESULT_FILE and $TIMING_FILE for details"
    exit 1
fi
