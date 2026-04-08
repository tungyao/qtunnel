#!/bin/bash
# Common test utilities shared by all test scripts

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'  # No Color

# Logging functions
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
debug() { echo -e "${BLUE}[DEBUG]${NC} $*"; }

# Setup project paths
setup_paths() {
    PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    BUILD_DIR="$PROJECT_DIR/build"
    TEST_DIR="$PROJECT_DIR/test"
    CERT_DIR="$TEST_DIR/certs"
    LOG_DIR="$TEST_DIR/logs"
    RESULTS_DIR="$TEST_DIR/results"

    # Create necessary directories
    mkdir -p "$CERT_DIR" "$LOG_DIR" "$RESULTS_DIR"
}

# Generate certificates
generate_certs() {
    if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
        debug "Certificates already exist"
        return 0
    fi

    info "Generating self-signed certificates..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -days 365 -nodes \
        -subj "/CN=localhost" 2>/dev/null
    info "Certificates created: $CERT_DIR/server.{crt,key}"
}

# Build project
build_project() {
    if [ -f "$BUILD_DIR/qtunnel_server" ] && [ -f "$BUILD_DIR/qtunnel_client" ]; then
        debug "Binaries already built"
        return 0
    fi

    info "Building project..."
    cd "$PROJECT_DIR"
    cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_FLAGS="-O2" > /dev/null 2>&1
    cmake --build "$BUILD_DIR" -j"$(nproc)" > /dev/null 2>&1

    if [ ! -f "$BUILD_DIR/qtunnel_server" ] || [ ! -f "$BUILD_DIR/qtunnel_client" ]; then
        error "Build failed"
        return 1
    fi
    info "Build completed"
}

# Start qtunnel server
start_server() {
    local port=${1:-18443}
    local log_file="$LOG_DIR/server.log"

    # Ensure port is free before starting
    debug "Waiting for port $port to be free..."
    wait_for_port_free "$port" 5 || {
        error "Port $port still in use, cannot start server"
        return 1
    }

    info "Starting server on port $port..."
    "$BUILD_DIR/qtunnel_server" \
        --listen "$port" \
        --cert-file "$CERT_DIR/server.crt" \
        --key-file "$CERT_DIR/server.key" \
        --log-level Info \
        > "$log_file" 2>&1 &

    local server_pid=$!
    sleep 2

    if ! ps -p "$server_pid" > /dev/null 2>&1; then
        error "Server failed to start"
        tail -10 "$log_file"
        return 1
    fi

    echo "$server_pid"
    info "Server started (PID: $server_pid)"
}

# Start qtunnel client
start_client() {
    local server_addr=${1:-"127.0.0.1:18443"}
    local listen_port=${2:-11080}
    local log_file="$LOG_DIR/client.log"

    # Ensure port is free before starting
    debug "Waiting for port $listen_port to be free..."
    wait_for_port_free "$listen_port" 5 || {
        error "Port $listen_port still in use, cannot start client"
        return 1
    }

    info "Starting client on port $listen_port..."
    "$BUILD_DIR/qtunnel_client" "$server_addr" \
        --listen "$listen_port" \
        --log-level info \
        > "$log_file" 2>&1 &

    local client_pid=$!
    sleep 2

    if ! ps -p "$client_pid" > /dev/null 2>&1; then
        error "Client failed to start"
        tail -10 "$log_file"
        return 1
    fi

    echo "$client_pid"
    info "Client started (PID: $client_pid, listening on $listen_port)"
}

# Cleanup all processes
cleanup_all() {
    local pids=("$@")

    # First pass: graceful kill (SIGTERM)
    for pid in "${pids[@]}"; do
        if [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1; then
            debug "Gracefully killing process $pid"
            kill "$pid" 2>/dev/null || true
        fi
    done

    # Wait for processes to terminate
    sleep 2

    # Second pass: force kill any remaining processes (SIGKILL)
    for pid in "${pids[@]}"; do
        if [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1; then
            debug "Force killing process $pid"
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    # Wait for port to be released
    sleep 2
}

# Wait for a port to be free
wait_for_port_free() {
    local port=$1
    local max_wait=${2:-5}
    local waited=0

    while [ $waited -lt $max_wait ]; do
        if ! netstat -tuln 2>/dev/null | grep -q ":$port " && \
           ! ss -tuln 2>/dev/null | grep -q ":$port " && \
           ! lsof -i ":$port" 2>/dev/null | grep -q LISTEN; then
            debug "Port $port is now free"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    warn "Port $port still in use after ${max_wait}s, forcing..."
    # Force kill any processes using the port
    local pids=$(lsof -t -i ":$port" 2>/dev/null || echo "")
    for pid in $pids; do
        debug "Force killing process on port $port (PID: $pid)"
        kill -9 "$pid" 2>/dev/null || true
    done
    sleep 1
    return 0
}

# Health check using curl
health_check() {
    local proxy_addr=${1:-"127.0.0.1:11080"}
    local max_retries=${2:-5}
    local retry=0

    info "Performing health check..."
    while [ $retry -lt "$max_retries" ]; do
        if curl -s --socks5 "$proxy_addr" \
            "https://www.apple.com/library/test/success.html" \
            -o /dev/null -w "%{http_code}" 2>/dev/null | \
            grep -q "200\|301\|302"; then
            info "Health check passed"
            return 0
        fi
        retry=$((retry + 1))
        if [ $retry -lt "$max_retries" ]; then
            warn "Health check attempt $retry failed, retrying..."
            sleep 1
        fi
    done

    error "Health check failed after $max_retries attempts"
    return 1
}

# Single request test
test_single_request() {
    local proxy_addr=${1:-"127.0.0.1:11080"}
    local url=${2:-"https://www.baidu.com"}

    info "Testing single request..."
    if timeout 15 curl -s --socks5 "$proxy_addr" "$url" \
        -H "User-Agent: Mozilla/5.0" \
        -o /dev/null -w "HTTP %{http_code}\n" 2>/dev/null | \
        grep -q "200\|301\|302"; then
        info "✓ Single request succeeded"
        return 0
    else
        error "✗ Single request failed"
        return 1
    fi
}

# Concurrent requests test
test_concurrent_requests() {
    local proxy_addr=${1:-"127.0.0.1:11080"}
    local num_requests=${2:-20}
    local url=${3:-"https://www.baidu.com"}

    info "Testing $num_requests concurrent requests..."
    local success=0
    local failed=0

    for i in $(seq 1 "$num_requests"); do
        (
            if timeout 15 curl -s --socks5 "$proxy_addr" \
                "$url?test=$i" \
                -o /dev/null -w "%{http_code}" 2>/dev/null | \
                grep -q "200\|301\|302"; then
                echo "OK" > "$LOG_DIR/concurrent_$i.result"
            fi
        ) &
    done

    wait

    for i in $(seq 1 "$num_requests"); do
        if [ -f "$LOG_DIR/concurrent_$i.result" ]; then
            success=$((success + 1))
            rm -f "$LOG_DIR/concurrent_$i.result"
        else
            failed=$((failed + 1))
        fi
    done

    local success_rate=$((success * 100 / (success + failed)))
    info "Concurrent results: Success=$success, Failed=$failed, Rate=${success_rate}%"

    if [ "$success_rate" -ge 80 ]; then
        return 0
    else
        return 1
    fi
}

# Large file + concurrent requests test
test_large_file_concurrent() {
    local proxy_addr=${1:-"127.0.0.1:11080"}
    local file_size=${2:-10000000}  # 10MB
    local concurrent_reqs=${3:-20}

    info "Testing large file download + $concurrent_reqs concurrent requests..."

    # Start large file download
    local bigfile_log="$LOG_DIR/bigfile.log"
    timeout 180 curl -s --socks5 "$proxy_addr" \
        "https://speed.cloudflare.com/__down?bytes=$file_size" \
        -o "$LOG_DIR/bigfile.bin" \
        -w "HTTP:%{http_code},Size:%{size_download}" \
        > "$bigfile_log" 2>&1 &
    local bigfile_pid=$!

    # Wait for download to start
    sleep 2

    # Launch concurrent requests
    local success=0
    local failed=0
    for i in $(seq 1 "$concurrent_reqs"); do
        (
            if timeout 15 curl -s --socks5 "$proxy_addr" \
                "https://www.baidu.com?test=$i" \
                -o /dev/null -w "%{http_code}" 2>/dev/null | \
                grep -q "200\|301\|302"; then
                echo "OK" > "$LOG_DIR/parallel_$i.result"
            fi
        ) &
    done

    # Wait for all to complete
    wait "$bigfile_pid" 2>/dev/null || true
    wait

    # Count results
    for i in $(seq 1 "$concurrent_reqs"); do
        if [ -f "$LOG_DIR/parallel_$i.result" ]; then
            success=$((success + 1))
            rm -f "$LOG_DIR/parallel_$i.result"
        else
            failed=$((failed + 1))
        fi
    done

    local success_rate=$((success * 100 / (success + failed)))
    info "Large file + concurrent: Success=$success, Failed=$failed, Rate=${success_rate}%"

    if [ -f "$LOG_DIR/bigfile.bin" ]; then
        local bigfile_size=$(stat -c%s "$LOG_DIR/bigfile.bin" 2>/dev/null || stat -f%z "$LOG_DIR/bigfile.bin" 2>/dev/null || echo "0")
        info "Large file size: $bigfile_size bytes"
    fi

    if [ "$success_rate" -ge 70 ]; then
        return 0
    else
        return 1
    fi
}

# Save test results
save_results() {
    local test_name=$1
    local status=$2  # "PASS" or "FAIL"
    local result_file="$RESULTS_DIR/result_$(date +%Y%m%d_%H%M%S)_${test_name}.txt"

    cat > "$result_file" << EOF
Test: $test_name
Status: $status
Timestamp: $(date)

Server log (last 20 lines):
$(tail -20 "$LOG_DIR/server.log" 2>/dev/null || echo "N/A")

Client log (last 20 lines):
$(tail -20 "$LOG_DIR/client.log" 2>/dev/null || echo "N/A")
EOF

    echo "$result_file"
}
