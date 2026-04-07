#!/bin/bash
# Local loopback test (no external network needed)

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
    pkill -f "qtunnel_client.*18443" 2>/dev/null || true
    pkill -f "python.*http.server" 2>/dev/null || true
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

# Start a simple HTTP server on localhost:9999
info "Starting local HTTP server on port 9999..."
python3 -m http.server 9999 -d /tmp > /tmp/http_server.log 2>&1 &
HTTP_PID=$!
sleep 2
if ! ps -p $HTTP_PID > /dev/null 2>&1; then
    error "HTTP server failed to start"
    exit 1
fi
info "HTTP server started"

# Test direct connection first (to verify HTTP server works)
info "Testing direct connection to HTTP server..."
if timeout 5 curl -s http://localhost:9999 -o /dev/null -w "Direct: %{http_code}\n" 2>/dev/null; then
    info "Direct connection works"
else
    error "Direct connection failed"
    kill $HTTP_PID 2>/dev/null || true
    exit 1
fi

info "Starting qtunnel server on port 18443..."
"$BUILD_DIR/qtunnel_server" --listen 18443 \
    --cert-file "$CERT_DIR/server.crt" \
    --key-file "$CERT_DIR/server.key" \
    --log-level Info \
    --target "localhost:9999" \
    --target-type direct \
    > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    error "qtunnel server failed to start"
    tail -20 /tmp/server.log
    kill $HTTP_PID 2>/dev/null || true
    exit 1
fi
info "qtunnel server started"

info "Starting qtunnel client on port 11080..."
"$BUILD_DIR/qtunnel_client" "127.0.0.1:18443" --listen 11080 \
    > /tmp/client.log 2>&1 &
CLIENT_PID=$!
sleep 2

if ! ps -p $CLIENT_PID > /dev/null 2>&1; then
    error "qtunnel client failed to start"
    tail -20 /tmp/client.log
    kill $HTTP_PID $SERVER_PID 2>/dev/null || true
    exit 1
fi
info "qtunnel client started"

info "Testing through SOCKS5 proxy..."
SUCCESS=0
TIMEOUT_COUNT=0

for i in {1..3}; do
    echo "  Request $i: " | tr -d '\n'
    OUTPUT=$(timeout 10 curl -s --socks5 127.0.0.1:11080 http://localhost:9999 \
        -o /dev/null -w "%{http_code}" 2>&1)
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 124 ]; then
        warn "TIMEOUT"
        TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1))
    elif [ $EXIT_CODE -eq 0 ]; then
        echo "HTTP $OUTPUT"
        if [ "$OUTPUT" = "200" ]; then
            SUCCESS=$((SUCCESS + 1))
        fi
    else
        warn "FAILED (curl exit $EXIT_CODE)"
    fi
    sleep 1
done

echo ""
info "Results: $SUCCESS / 3 successful requests"
if [ $TIMEOUT_COUNT -gt 0 ]; then
    warn "$TIMEOUT_COUNT requests timed out"
fi

echo ""
info "qtunnel server log (last 20 lines):"
tail -20 /tmp/server.log | sed 's/^/  /'

echo ""
info "qtunnel client log (last 10 lines):"
tail -10 /tmp/client.log | sed 's/^/  /'

if [ $SUCCESS -ge 2 ]; then
    info "✓ Test PASSED"
    exit 0
else
    error "✗ Test FAILED - Only $SUCCESS/3 requests succeeded"
    if [ $TIMEOUT_COUNT -gt 0 ]; then
        error "Requests are timing out - DNS resolution may be hanging"
    fi
    exit 1
fi
