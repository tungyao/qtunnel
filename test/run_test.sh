#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
TEST_DIR="$PROJECT_DIR/test"
CERT_DIR="$TEST_DIR/certs"
LOG_DIR="$TEST_DIR/logs"
RESULTS_DIR="$TEST_DIR/results"

# Configuration
SERVER_PORT=18443
SOCKS_PORT=11080
SERVER_HOST="127.0.0.1"
PARALLEL_CONNECTIONS=50
BIG_FILE_SIZE=10000000
PARALLEL_SMALL_REQUESTS=30

# Cleanup
cleanup() {
    echo -e "${YELLOW}[cleanup] Stopping server and client...${NC}"
    if [ -n "$SERVER_PID" ]; then kill $SERVER_PID 2>/dev/null || true; fi
    if [ -n "$CLIENT_PID" ]; then kill $CLIENT_PID 2>/dev/null || true; fi
    sleep 1
}

trap cleanup EXIT

# Color helpers
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# Create directories
mkdir -p "$CERT_DIR" "$LOG_DIR" "$RESULTS_DIR"

info "====== qtunnel Reactor Improvement Test Suite ======"
info "Project directory: $PROJECT_DIR"
info "Build directory: $BUILD_DIR"

# Step 1: Generate certificates if needed
if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ]; then
    info "Generating self-signed certificates..."
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" -days 365 -nodes \
        -subj "/CN=localhost" 2>&1 | grep -v "^Generating\|^Writing"
    info "Certificates created: $CERT_DIR/server.{crt,key}"
fi

# Step 2: Build project
if [ ! -f "$BUILD_DIR/qtunnel_server" ] || [ ! -f "$BUILD_DIR/qtunnel_client" ]; then
    info "Building project..."
    cd "$PROJECT_DIR"
    cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-O3" > /dev/null 2>&1
    cmake --build "$BUILD_DIR" -j$(nproc) > /dev/null 2>&1
    info "Build completed"
fi

# Step 3: Start server
info "Starting server on port $SERVER_PORT..."
"$BUILD_DIR/qtunnel_server" \
    --listen "$SERVER_PORT" \
    --cert-file "$CERT_DIR/server.crt" \
    --key-file "$CERT_DIR/server.key" \
    --log-level Info \
    > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

if ! ps -p $SERVER_PID > /dev/null; then
    error "Server failed to start"
    cat "$LOG_DIR/server.log"
    exit 1
fi
info "Server started (PID: $SERVER_PID)"

# Step 4: Start client (SOCKS5 proxy)
info "Starting client on port $SOCKS_PORT..."
"$BUILD_DIR/qtunnel_client" "$SERVER_HOST:$SERVER_PORT" \
    --listen "$SOCKS_PORT" \
    --log-level info \
    > "$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 1

if ! ps -p $CLIENT_PID > /dev/null; then
    error "Client failed to start"
    cat "$LOG_DIR/client.log"
    exit 1
fi
info "Client started (PID: $CLIENT_PID, listening on port $SOCKS_PORT)"

# Step 5: Health check
info "Performing health check..."
max_retries=5
retry=0
while [ $retry -lt $max_retries ]; do
    if curl -s --socks5 "$SERVER_HOST:$SOCKS_PORT" "https://www.apple.com/library/test/success.html" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200\|301\|302\|307\|308"; then
        info "Health check passed"
        break
    fi
    retry=$((retry + 1))
    if [ $retry -lt $max_retries ]; then
        warn "Health check attempt $retry failed, retrying..."
        sleep 1
    fi
done

if [ $retry -eq $max_retries ]; then
    error "Health check failed after $max_retries attempts"
    cat "$LOG_DIR/server.log" "$LOG_DIR/client.log"
    exit 1
fi

# Step 6: Test 1 - Concurrent light requests
info "====== TEST 1: Concurrent Light Requests ($PARALLEL_CONNECTIONS parallel) ======"
TEST1_START=$(date +%s%N)
TEST1_SUCCESS=0
TEST1_FAILED=0

for i in $(seq 1 $PARALLEL_CONNECTIONS); do
    (
        curl -s --socks5 "$SERVER_HOST:$SOCKS_PORT" \
            "https://baidu.com?test=1&id=$i" \
            -o /dev/null -w "%{http_code}" 2>/dev/null | \
        if grep -q "200\|301\|302"; then
            echo "OK" > "$LOG_DIR/test1_$i.result"
        else
            echo "FAIL" > "$LOG_DIR/test1_$i.result"
        fi
    ) &
done
wait

TEST1_END=$(date +%s%N)
TEST1_DURATION=$(( (TEST1_END - TEST1_START) / 1000000 ))

for i in $(seq 1 $PARALLEL_CONNECTIONS); do
    if [ -f "$LOG_DIR/test1_$i.result" ]; then
        if grep -q "OK" "$LOG_DIR/test1_$i.result"; then
            TEST1_SUCCESS=$((TEST1_SUCCESS + 1))
        else
            TEST1_FAILED=$((TEST1_FAILED + 1))
        fi
    else
        TEST1_FAILED=$((TEST1_FAILED + 1))
    fi
    rm -f "$LOG_DIR/test1_$i.result"
done

TEST1_RATE=$(echo "scale=2; $TEST1_SUCCESS * 1000 / $TEST1_DURATION" | bc 2>/dev/null || echo "0")
info "Result: Success=$TEST1_SUCCESS, Failed=$TEST1_FAILED, Duration=${TEST1_DURATION}ms, Rate=${TEST1_RATE} req/sec"

# Step 7: Test 2 - Big file + concurrent requests
info "====== TEST 2: Big File Download + Concurrent Requests ======"
TEST2_START=$(date +%s%N)

# Start big file download in background (using httpbin.org for reliability)
BIGFILE_LOG="$LOG_DIR/bigfile.log"
BIG_FILE_START=$(date +%s)
timeout 180 curl -s --socks5 "$SERVER_HOST:$SOCKS_PORT" \
    "https://speed.cloudflare.com/__down?bytes=10000000" \
    -o "$LOG_DIR/bigfile.bin" -w "HTTP:%{http_code},Size:%{size_download},Speed:%{speed_download}" \
    > "$BIGFILE_LOG" 2>&1 &
BIGFILE_PID=$!

# Wait a bit for big file to start
sleep 2

# Launch concurrent requests while big file is downloading
TEST2_SUCCESS=0
TEST2_FAILED=0
for i in $(seq 1 $PARALLEL_SMALL_REQUESTS); do
    (
        curl -s --socks5 "$SERVER_HOST:$SOCKS_PORT" \
            "https://baidu.com?test=2&id=$i" \
            -o /dev/null -w "%{http_code}" 2>/dev/null | \
        if grep -q "200\|301\|302"; then
            echo "OK" > "$LOG_DIR/test2_$i.result"
        else
            echo "FAIL" > "$LOG_DIR/test2_$i.result"
        fi
    ) &
done

# Wait for all concurrent requests and big file
wait $BIGFILE_PID 2>/dev/null || true
wait

BIG_FILE_END=$(date +%s)
BIG_FILE_DURATION=$((BIG_FILE_END - BIG_FILE_START))

for i in $(seq 1 $PARALLEL_SMALL_REQUESTS); do
    if [ -f "$LOG_DIR/test2_$i.result" ]; then
        if grep -q "OK" "$LOG_DIR/test2_$i.result"; then
            TEST2_SUCCESS=$((TEST2_SUCCESS + 1))
        else
            TEST2_FAILED=$((TEST2_FAILED + 1))
        fi
    else
        TEST2_FAILED=$((TEST2_FAILED + 1))
    fi
    rm -f "$LOG_DIR/test2_$i.result"
done

TEST2_END=$(date +%s%N)
TEST2_DURATION=$(( (TEST2_END - TEST2_START) / 1000000 ))

# Parse big file result
BIGFILE_SIZE=$([ -f "$LOG_DIR/bigfile.bin" ] && stat -f%z "$LOG_DIR/bigfile.bin" 2>/dev/null || stat -c%s "$LOG_DIR/bigfile.bin" 2>/dev/null || echo "0")
BIG_FILE_SPEED=$(grep -o "Speed:[0-9.]*" "$BIGFILE_LOG" 2>/dev/null | cut -d: -f2 || echo "0")

info "Big file: ${BIG_FILE_DURATION}s, Size=${BIGFILE_SIZE} bytes, Speed=${BIG_FILE_SPEED} bytes/sec"
info "Concurrent requests: Success=$TEST2_SUCCESS, Failed=$TEST2_FAILED, Duration=${TEST2_DURATION}ms"

# Step 8: Summary and save results
info "====== Test Summary ======"

# Calculate success rates
TEST1_RATE_PERCENT=$(echo "scale=2; $TEST1_SUCCESS * 100 / ($TEST1_SUCCESS + $TEST1_FAILED)" | bc 2>/dev/null || echo "0")
TEST2_RATE_PERCENT=$(echo "scale=2; $TEST2_SUCCESS * 100 / ($TEST2_SUCCESS + $TEST2_FAILED)" | bc 2>/dev/null || echo "0")

RESULT_FILE="$RESULTS_DIR/result_$(date +%Y%m%d_%H%M%S).txt"
cat > "$RESULT_FILE" << EOF
====== qtunnel Test Results ======
Timestamp: $(date)

TEST 1: Concurrent Light Requests
  Parallel connections: $PARALLEL_CONNECTIONS
  Success: $TEST1_SUCCESS
  Failed: $TEST1_FAILED
  Success rate: ${TEST1_RATE_PERCENT}%
  Duration: ${TEST1_DURATION}ms
  Throughput: ${TEST1_RATE} req/sec

TEST 2: Big File + Concurrent Requests
  Big file size: $BIG_FILE_SIZE bytes
  Big file duration: ${BIG_FILE_DURATION}s
  Big file speed: ${BIG_FILE_SPEED} bytes/sec
  Concurrent requests: $PARALLEL_SMALL_REQUESTS
  Success: $TEST2_SUCCESS
  Failed: $TEST2_FAILED
  Success rate: ${TEST2_RATE_PERCENT}%
  Duration: ${TEST2_DURATION}ms

SERVER LOG (last 20 lines):
$(tail -20 "$LOG_DIR/server.log")

CLIENT LOG (last 20 lines):
$(tail -20 "$LOG_DIR/client.log")
EOF

info "Results saved to: $RESULT_FILE"
cat "$RESULT_FILE"

# Determine pass/fail
if [ "$(echo "$TEST1_RATE_PERCENT >= 90" | bc 2>/dev/null || echo "0")" -eq 1 ] && \
   [ "$(echo "$TEST2_RATE_PERCENT >= 80" | bc 2>/dev/null || echo "0")" -eq 1 ]; then
    info "====== ALL TESTS PASSED ======"
    exit 0
else
    error "====== TESTS FAILED ======"
    exit 1
fi
