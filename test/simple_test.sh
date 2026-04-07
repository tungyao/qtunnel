#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
TEST_DIR="$PROJECT_DIR/test"
CERT_DIR="$TEST_DIR/certs"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Configuration
SERVER_PORT=18443
SOCKS_PORT=11080
PARALLEL_CONNECTIONS=20

cleanup() {
    pkill -f "qtunnel_server --listen $SERVER_PORT" 2>/dev/null || true
    pkill -f "qtunnel_client.*:$SERVER_PORT" 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

info "Building..."
cd "$PROJECT_DIR"
cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
cmake --build "$BUILD_DIR" -j$(nproc) > /dev/null 2>&1

info "Starting server..."
"$BUILD_DIR/qtunnel_server" --listen "$SERVER_PORT" \
    --cert-file "$CERT_DIR/server.crt" --key-file "$CERT_DIR/server.key" \
    > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 1

info "Starting client..."
"$BUILD_DIR/qtunnel_client" "127.0.0.1:$SERVER_PORT" --listen "$SOCKS_PORT" \
    > /tmp/client.log 2>&1 &
CLIENT_PID=$!
sleep 2

info "Testing concurrent requests ($PARALLEL_CONNECTIONS parallel)..."
SUCCESS=0
FAILED=0

for i in $(seq 1 $PARALLEL_CONNECTIONS); do
    (
        timeout 10 curl -s --socks5 "127.0.0.1:$SOCKS_PORT" \
            "https://baidu.com?test=$i" \
            -o /dev/null -w "%{http_code}" 2>/dev/null | \
        grep -q "200\|301\|302" && echo "OK" || echo "FAIL"
    ) > /tmp/test_$i.result &
done

wait

for i in $(seq 1 $PARALLEL_CONNECTIONS); do
    if [ -f "/tmp/test_$i.result" ]; then
        if grep -q "OK" "/tmp/test_$i.result"; then
            SUCCESS=$((SUCCESS + 1))
        else
            FAILED=$((FAILED + 1))
        fi
        rm -f "/tmp/test_$i.result"
    else
        FAILED=$((FAILED + 1))
    fi
done

SUCCESS_RATE=$(echo "scale=1; $SUCCESS * 100 / ($SUCCESS + $FAILED)" | bc 2>/dev/null || echo "0")

info "Test Results:"
info "  Success: $SUCCESS / $(($SUCCESS + $FAILED))"
info "  Rate: ${SUCCESS_RATE}%"

if [ "$(echo "$SUCCESS_RATE >= 80" | bc 2>/dev/null || echo "0")" -eq 1 ]; then
    info "PASSED"
    exit 0
else
    error "FAILED"
    cat /tmp/server.log | tail -10
    cat /tmp/client.log | tail -10
    exit 1
fi
