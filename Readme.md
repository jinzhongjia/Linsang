# Linsang

A small, embeddable **HTTP/1.1 + WebSocket** server library in Zig 0.16, in the
spirit of [civetweb](https://github.com/civetweb/civetweb).

- **No `std.http`** and **no `std.Io.net`** — the socket and protocol code is our own.
- **No third-party dependencies.**
- **No libc** on Linux (raw syscalls) and Windows (system DLLs, not the C runtime).
  macOS necessarily links `libSystem` — Apple provides no stable syscall ABI, and
  Zig always links it for Darwin.
- **Low memory**: shared-nothing per-thread reactor, pooled fixed-size connection
  buffers, zero-copy request bodies.
- **Heavily unit-tested**: 41 tests covering the parser, chunked decoding, the
  WebSocket codec (incl. the RFC 6455 accept vector), the connection state machine
  over socketpairs, and end-to-end HTTP + WebSocket over real TCP with worker threads.

## Platforms

| OS | Backend | Status |
|----|---------|--------|
| Linux | epoll + raw syscalls (no libc) | runtime-tested |
| macOS | kqueue + `std.c`/libSystem | cross-compile-verified |
| Windows | WSAPoll + `ws2_32` | cross-compile-verified |

`x86_64` and `aarch64` both cross-compile. macOS/Windows are compiled and
type-checked here but not runtime-tested (no host available in this environment).

## Build

```sh
zig build test    # run the full unit + integration suite
zig build run     # start the demo server on http://0.0.0.0:8080 (WebSocket echo at /ws)
zig build         # build the demo binary into zig-out/bin/linsang
```

## Use as a library

```zig
const linsang = @import("Linsang");

fn onRequest(req: *const linsang.Request, res: *linsang.Response, ud: ?*anyopaque) linsang.Action {
    _ = ud;
    if (std.mem.eql(u8, req.path, "/ws")) return .upgrade; // hand off to WebSocket
    res.status = .ok;
    res.setHeader("Content-Type", "text/plain") catch {};
    res.print("hello {s}", .{req.path}) catch {};
    return .respond;
}

fn onMessage(conn: *linsang.Connection, msg: linsang.websocket.Message, ud: ?*anyopaque) void {
    _ = ud;
    conn.sendText(msg.data) catch {}; // echo
}

pub fn main() !void {
    var server = linsang.Server.init(std.heap.page_allocator, .{
        .address = "0.0.0.0",
        .port = 8080,
        .on_request = onRequest,
        .on_ws_message = onMessage, // optional
    });
    try server.start(); // spawns one reactor per CPU
    server.wait();      // block until stop()
}
```

`Config` knobs: `threads` (0 = one per CPU), `read_buffer_size`, `max_body_size`,
`max_ws_message_size`, `backlog`, `pool_capacity`, `user_data`, and the
`on_ws_open`/`on_ws_close` hooks.

## Design

See [docs/DESIGN.md](docs/DESIGN.md). In short: one shared listen socket, `N`
worker threads each running an independent readiness reactor; a connection lives
entirely inside one worker, so there are no locks on the hot path. HTTP handlers
run synchronously in the reactor and must not block.

## Scope

**In:** HTTP/1.1 keep-alive, `Content-Length` + chunked bodies (both directions),
WebSocket handshake + framing + fragmentation + ping/pong/close.

**Out (by design):** HTTP/2, pipelining, compression, multipart. **TLS is a
planned Phase 2** (TLS 1.3 server built on `std.crypto` primitives) — not in this
release.
