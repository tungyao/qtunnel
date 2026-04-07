#!/bin/bash
# Quick test for async DNS functionality

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
TEST_DIR="$PROJECT_DIR/test"
CERT_DIR="$TEST_DIR/certs"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

cleanup() {
    pkill -f "qtunnel_server --listen 18443" 2>/dev/null || true
    pkill -f "qtunnel_client.*:18443" 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

info "Building..."
cd "$PROJECT_DIR"
cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug > /dev/null 2>&1
cmake --build "$BUILD_DIR" -j$(nproc) > /dev/null 2>&1

# Generate certs if needed
if [ ! -f "$CERT_DIR/server.crt" ]; then
    info "Generating certificates..."
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" -days 365 -nodes \
        -subj "/CN=localhost" 2>/dev/null
fi

info "Starting server on port 18443..."
"$BUILD_DIR/qtunnel_server" --listen 18443 \
    --cert-file "$CERT_DIR/server.crt" \
    --key-file "$CERT_DIR/server.key" \
    --log-level Info \
    > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    error "Server failed to start"
    tail -20 /tmp/server.log
    exit 1
fi
info "Server started (PID: $SERVER_PID)"

info "Starting client on port 11080..."
"$BUILD_DIR/qtunnel_client" "127.0.0.1:18443" --listen 11080 \
    > /tmp/client.log 2>&1 &
CLIENT_PID=$!
sleep 2

if ! ps -p $CLIENT_PID > /dev/null 2>&1; then
    error "Client failed to start"
    tail -20 /tmp/client.log
    exit 1
fi
info "Client started (PID: $CLIENT_PID)"

info "Testing 5 sequential requests..."
SUCCESS=0
for i in {1..5}; do
    if timeout 15 curl -s --socks5 127.0.0.1:11080 \
        "https://www.baidu.com" \
        -H "User-Agent: Mozilla/5.0" \
        -o /dev/null -w "Request $i: %{http_code}\n" 2>/dev/null; then
        SUCCESS=$((SUCCESS + 1))
    else
        warn "Request $i failed or timed out"
    fi
    sleep 1
done

info "Testing 3 concurrent requests..."
CONCURRENT_SUCCESS=0
for i in {1..3}; do
    (
        if timeout 20 curl -s --socks5 127.0.0.1:11080 \
            "https://www.bing.com" \
            -H "User-Agent: Mozilla/5.0" \
            -o /dev/null -w "Concurrent $i: OK\n" 2>/dev/null; then
            echo "OK" > /tmp/concurrent_$i.result
        fi
    ) &
done
wait
for i in {1..3}; do
    if [ -f "/tmp/concurrent_$i.result" ] && grep -q "OK" "/tmp/concurrent_$i.result"; then
        CONCURRENT_SUCCESS=$((CONCURRENT_SUCCESS + 1))
        rm -f "/tmp/concurrent_$i.result"
    fi
done

info "Results:"
info "  Sequential: $SUCCESS / 5"
info "  Concurrent: $CONCURRENT_SUCCESS / 3"

echo ""
info "Server log (last 15 lines):"
tail -15 /tmp/server.log | sed 's/^/  /'

echo ""
info "Client log (last 10 lines):"
tail -10 /tmp/client.log | sed 's/^/  /'

if [ $SUCCESS -ge 3 ] && [ $CONCURRENT_SUCCESS -ge 2 ]; then
    info "✓ Test PASSED"
    exit 0
else
    error "✗ Test FAILED"
    exit 1
fi
