#!/bin/bash
# Verify that test scripts properly clean up processes

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Testing Process Cleanup ==="
echo ""

# Helper function to count qtunnel processes
count_qtunnel_processes() {
    pgrep -f "qtunnel_server|qtunnel_client" 2>/dev/null | wc -l
}

echo "Initial qtunnel processes: $(count_qtunnel_processes)"
echo ""

# Test each mode and verify cleanup
for mode in single concurrent large-file; do
    echo "Testing mode: $mode"
    echo "Before: $(count_qtunnel_processes) processes"

    # Run test with timeout to prevent hanging
    timeout 60 bash "$SCRIPT_DIR/test.sh" "$mode" > /tmp/test_$mode.log 2>&1 || {
        echo "⚠ Test timed out or failed (this might be due to network)"
    }

    # Wait a moment for cleanup
    sleep 2

    # Check if processes were cleaned up
    after_count=$(count_qtunnel_processes)
    echo "After: $after_count processes"

    if [ "$after_count" -eq 0 ]; then
        echo "✓ Cleanup successful"
    else
        echo "✗ WARNING: Processes not cleaned up!"
        pgrep -f "qtunnel_server|qtunnel_client" 2>/dev/null | xargs -r ps -o pid,cmd
    fi

    echo ""
done

# Final check
echo "Final qtunnel processes: $(count_qtunnel_processes)"
echo ""

# Kill any remaining processes
remaining=$(count_qtunnel_processes)
if [ "$remaining" -gt 0 ]; then
    echo "Killing remaining processes..."
    pkill -f "qtunnel_server|qtunnel_client" || true
    sleep 1
    echo "Remaining processes: $(count_qtunnel_processes)"
fi
