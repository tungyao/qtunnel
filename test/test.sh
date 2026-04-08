#!/bin/bash
# Unified test script for qtunnel
# Supports: single, concurrent, and large-file + concurrent modes

set -e

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Setup
setup_paths

# Configuration
SERVER_PORT=18443
SOCKS_PORT=11080
TEST_MODE="${1:-all}"  # single, concurrent, large-file, all

# Cleanup on exit
trap 'cleanup_all "$SERVER_PID" "$CLIENT_PID"' EXIT

# Functions for each test mode
test_mode_single() {
    info "====== MODE: Single Request Test ======"
    build_project || return 1
    generate_certs || return 1

    SERVER_PID=$(start_server "$SERVER_PORT") || return 1
    CLIENT_PID=$(start_client "127.0.0.1:$SERVER_PORT" "$SOCKS_PORT") || return 1

    health_check "127.0.0.1:$SOCKS_PORT" 5 || return 1
    test_single_request "127.0.0.1:$SOCKS_PORT" "https://www.baidu.com" || return 1

    local result_file=$(save_results "single" "PASS")
    info "Results saved to: $result_file"
    return 0
}

test_mode_concurrent() {
    info "====== MODE: Concurrent Requests Test (20 parallel) ======"
    build_project || return 1
    generate_certs || return 1

    SERVER_PID=$(start_server "$SERVER_PORT") || return 1
    CLIENT_PID=$(start_client "127.0.0.1:$SERVER_PORT" "$SOCKS_PORT") || return 1

    health_check "127.0.0.1:$SOCKS_PORT" 5 || return 1
    test_concurrent_requests "127.0.0.1:$SOCKS_PORT" 20 "https://www.baidu.com" || return 1

    local result_file=$(save_results "concurrent" "PASS")
    info "Results saved to: $result_file"
    return 0
}

test_mode_large_file() {
    info "====== MODE: Large File + Concurrent Test ======"
    build_project || return 1
    generate_certs || return 1

    SERVER_PID=$(start_server "$SERVER_PORT") || return 1
    CLIENT_PID=$(start_client "127.0.0.1:$SERVER_PORT" "$SOCKS_PORT") || return 1

    health_check "127.0.0.1:$SOCKS_PORT" 5 || return 1
    test_large_file_concurrent "127.0.0.1:$SOCKS_PORT" 10000000 20 || return 1

    local result_file=$(save_results "large-file-concurrent" "PASS")
    info "Results saved to: $result_file"
    return 0
}

test_mode_all() {
    info "====== RUNNING ALL TESTS ======"
    echo ""

    # Test 1: Single request
    info "Test 1/3: Single Request"
    if test_mode_single; then
        info "✓ Single request test PASSED"
    else
        error "✗ Single request test FAILED"
        return 1
    fi
    echo ""

    # Clean up before next test
    cleanup_all "$SERVER_PID" "$CLIENT_PID"
    sleep 1

    # Test 2: Concurrent requests
    info "Test 2/3: Concurrent Requests"
    if test_mode_concurrent; then
        info "✓ Concurrent test PASSED"
    else
        error "✗ Concurrent test FAILED"
        return 1
    fi
    echo ""

    # Clean up before next test
    cleanup_all "$SERVER_PID" "$CLIENT_PID"
    sleep 1

    # Test 3: Large file + concurrent
    info "Test 3/3: Large File + Concurrent"
    if test_mode_large_file; then
        info "✓ Large file + concurrent test PASSED"
    else
        error "✗ Large file + concurrent test FAILED"
        return 1
    fi

    info "====== ALL TESTS PASSED ======"
    return 0
}

# Display usage
show_usage() {
    cat << EOF
Usage: $0 [MODE]

Modes:
  single       - Test single sequential request
  concurrent   - Test 20 concurrent requests
  large-file   - Test large file download + 20 concurrent requests
  all          - Run all tests (default)

Examples:
  $0 single
  $0 concurrent
  $0 large-file
  $0
  $0 all

EOF
}

# Main
if [ "$TEST_MODE" = "help" ] || [ "$TEST_MODE" = "-h" ] || [ "$TEST_MODE" = "--help" ]; then
    show_usage
    exit 0
fi

case "$TEST_MODE" in
    single)
        test_mode_single || exit 1
        ;;
    concurrent)
        test_mode_concurrent || exit 1
        ;;
    large-file)
        test_mode_large_file || exit 1
        ;;
    all)
        test_mode_all || exit 1
        ;;
    *)
        error "Unknown test mode: $TEST_MODE"
        show_usage
        exit 1
        ;;
esac

info "Test completed successfully"
exit 0
