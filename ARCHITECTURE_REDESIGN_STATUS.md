# Architecture Redesign Status - Per-Request H2 Tunnels

## Summary
Restructuring qtunnel client to create independent H2 CONNECT streams per HTTP request instead of per-socket connection.

## Status: 60% Structural, 10% Functional

### ✅ Completed (Structural Foundation)

1. **New Data Structures** - All defined and compiling:
   - `LocalConnection` - owns socket + stream queue
   - `HttpRequestBoundary` - HTTP request parsing helper  
   - Modified `LocalStream` - can own socket (SOCKS5) OR be owned by LocalConnection (HTTP)
   - Modified `PendingTunnel` - supports both SOCKS5 (`sock`) and HTTP (`conn`) paths

2. **New Methods Declared** - All signatures added to ClientRuntime:
   - `drain_pending_conn_close()`
   - `pump_local_connection(conn)`
   - `flush_local_connection(conn, error)`
   - `close_local_connection(conn)`
   - `try_parse_next_request(conn)`

3. **Helper Functions** - Full implementation:
   - `parse_http_boundary()` - Detects HTTP request boundaries (method, headers, body length, keep-alive)

4. **Build Status**: ✅ Compiles successfully

### ⚠️ In Progress (Functional Implementation)

#### Stubs Created (need full implementation):
1. `drain_pending_conn_close()` - Basic socket close, needs connection cleanup
2. `pump_local_connection(conn)` - Should recv() and route to appropriate stream
3. `flush_local_connection(conn, error)` - Should enforce HTTP/1.1 pipelining order
4. `close_local_connection(conn)` - Should clean up all streams in queue
5. `try_parse_next_request(conn)` - Should parse HTTP, create LocalStream, enqueue PendingTunnel

#### Core Changes Pending (to make system functional):
1. **`process_pending_tunnels()`** - Update to use `pt.conn` for HTTP paths
2. **`on_stream_close()`** - Dequeue from connection instead of closing socket
3. **`handle_stream_open()`** - Set `conn->is_connect_mode = true` for CONNECT
4. **`accept_one()`** - Create LocalConnection for HTTP (keep SOCKS5 as-is)
5. **`accept_and_pump_loop()`** - Switch to using `connections_` map instead of `socket_to_stream`

### ❌ Not Yet Implemented

- Full `pump_local_connection()` logic (recv, buffer management, byte routing)
- Full `flush_local_connection()` logic (pipelining order enforcement)
- Full `try_parse_next_request()` logic (HTTP request parsing flow)
- Integration with accept_and_pump_loop

## How to Test Current State

```bash
cd /root/server/qtunnel
cmake --build build -j$(nproc)
# Should build successfully with warnings about unused functions (expected)
```

## Next Steps (Implementation Order)

1. Implement `pump_local_connection()` - recv() from socket, buffer to recv_buf, route bytes
2. Implement `try_parse_next_request()` - Use parse_http_boundary(), create LocalStream
3. Implement `flush_local_connection()` - Queue-head only approach for pipelining
4. Implement `close_local_connection()` - Clean shutdown of all streams
5. Implement `drain_pending_conn_close()` - IO thread → pump thread connection cleanup
6. Update `process_pending_tunnels()` - Handle conn parameter
7. Update `on_stream_close()` - Dequeue logic + closed connection detection
8. Update `handle_stream_open()` - Set is_connect_mode for CONNECT requests
9. Update `accept_one()` - Create LocalConnection for HTTP
10. Update `accept_and_pump_loop()` - Use connections_ map
11. Test with real Chrome browser stress test

## Architecture Guarantees

- SOCKS5 path: Unchanged, uses existing pump_local_socket/flush_local_socket
- HTTP CONNECT: One socket → One H2 CONNECT (after 200, opaque TLS)
- HTTP Forward: One socket → Multiple sequential H2 CONNECTs (per HTTP request)
- Pipelining: Responses sent in request order (HTTP/1.1 requirement)
- Thread safety: Pump thread owns connections_, io thread owns streams_

## Key Design Decisions

1. Keep `sock` in `LocalStream` for backward compat with SOCKS5
2. Add `conn` to `LocalStream` for HTTP paths only
3. LocalConnection mutex protects all dynamic state
4. PendingTunnel can be SOCKS5-style (sock only) or HTTP-style (conn only)
5. No breaking changes to existing nghttp2 callback signatures
