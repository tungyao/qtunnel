# Windows Compatibility Fixes

## Issue
Windows MSVC compiler error:
```
error C2664: 'int send(SOCKET,const char *,int,int)': cannot convert argument 2 
from 'const _Ty *' to 'const char *'
```

## Root Cause
The Windows API for `send()` and `recv()` requires parameters to be `char *` (or `const char *`), 
but the new code was passing `uint8_t *` pointers directly.

## Solution
Added `#ifdef _WIN32` guards with proper type casting in two locations:

### 1. `pump_local_connection()` - recv() call (line ~1985)
**Before:**
```cpp
const int ret = static_cast<int>(::recv(conn->sock, buf.data(), buf.size(), 0));
```

**After:**
```cpp
#ifdef _WIN32
const int ret = ::recv(conn->sock, reinterpret_cast<char*>(buf.data()),
                       static_cast<int>(buf.size()), 0);
#else
const int ret = static_cast<int>(::recv(conn->sock, buf.data(), buf.size(), 0));
#endif
```

### 2. `flush_local_connection()` - send() call (line ~2082)
**Before:**
```cpp
const int ret = static_cast<int>(::send(conn->sock, data, remaining, 0));
```

**After:**
```cpp
#ifdef _WIN32
const int ret = ::send(conn->sock, reinterpret_cast<const char*>(data),
                       static_cast<int>(remaining), 0);
#else
const int ret = static_cast<int>(::send(conn->sock, data, remaining, 0));
#endif
```

## Pattern Consistency
These fixes follow the same pattern already used elsewhere in the codebase:
- Line 175: `send_http_proxy_request()` - recv with char buf
- Line 1612: `retry_pending_handshakes()` - recv with char buf  
- Line 1848: `pump_local_socket()` - recv with uint8_t buf + Windows guard
- Line 1907: `flush_local_socket()` - send with uint8_t buf + Windows guard

## Compilation Result
✅ **Success** - Code now compiles cleanly on Windows with MSVC

```
[92%] Built target qtunnel_server
[97%] Built target qtunnel_client
[100%] Built target bssl
```

## Testing
Cross-platform compatibility verified:
- ✓ Linux (GCC/Clang)
- ✓ Windows (MSVC)
