# Linsang

A small, embeddable **HTTP/1.1 + WebSocket** server library in Zig 0.16, in the
spirit of [civetweb](https://github.com/civetweb/civetweb).

- **No `std.http`** — the HTTP + WebSocket protocol code is our own.
- Networking uses **`std.Io.net`** on the **`std.Io` runtime** (one fiber per
  connection), so we don't hand-roll per-OS socket code.
- **No third-party dependencies.**
- **No libc** where the OS allows: Linux (Evented → io_uring) and Windows
  (Threaded → `kernel32`/`ws2_32`, not the C runtime). macOS necessarily links
  `libSystem` (Evented → Dispatch/GCD; Apple provides no stable syscall ABI).
- **Low memory**: bounded per-connection buffers, zero-copy `Content-Length`
  bodies. Each connection carries a (lazily-committed) fiber stack.
- **Heavily unit-tested**: parser, chunked decoding, WebSocket codec (incl. the
  RFC 6455 accept vector), and end-to-end HTTP + WebSocket over real TCP.

> **Status:** migrating the networking layer to `std.Io.net` + `std.Io.Evented`.
> `http.zig` and `websocket.zig` (protocol code) are stable; `connection.zig` and
> `server.zig` are being rewritten around `std.Io.net` (the previous hand-rolled
> socket/poller/reactor is being removed). See [docs/DESIGN.md](docs/DESIGN.md).

## Concurrency runtime

The library takes an `io: std.Io` and threads it through. Callers choose:

- **`std.Io.Evented`** (recommended) — fiber-based event loop:
  Linux → **io_uring**, \*BSD → kqueue, macOS → **Dispatch/GCD**,
  **Windows → not available**.
- **`std.Io.Threaded`** — thread-pool blocking; the **required fallback on Windows**.

A blocking `read`/`write` suspends the connection's fiber, not the OS thread, so
many connections share a small thread pool. Fibers are supported on `x86_64`,
`aarch64`, `riscv64`.

## Platforms

| OS | Runtime | Status |
|----|---------|--------|
| Linux | `std.Io.Evented` → io_uring (no libc) | runtime-tested |
| macOS | `std.Io.Evented` → Dispatch/GCD (libSystem) | cross-compile-verified |
| Windows | `std.Io.Threaded` (`ws2_32`, no CRT) | cross-compile-verified |

`x86_64` and `aarch64` both cross-compile. macOS/Windows are compiled and
type-checked but not runtime-tested (no host available in this environment).

## Build

```sh
zig build test    # run the full unit + integration suite
zig build run     # start the demo server on http://0.0.0.0:8080 (WebSocket echo at /ws)
zig build         # build the demo binary into zig-out/bin/linsang
```

## Use as a library

The API threads a `std.Io` instance through the server (final shape lands with
the migration):

```zig
const std = @import("std");
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
    const gpa = std.heap.page_allocator;

    var evented: std.Io.Evented = undefined;
    try evented.init(gpa, .{}); // Threaded on Windows
    defer evented.deinit();
    const io = evented.io();

    var server = linsang.Server.init(gpa, .{
        .address = "0.0.0.0",
        .port = 8080,
        .on_request = onRequest,
        .on_ws_message = onMessage, // optional
    });
    try server.run(io); // accept loop + one fiber per connection
}
```

`Config` knobs: `read_buffer_size`, `max_body_size`, `max_ws_message_size`,
`backlog`, `user_data`, and the `on_ws_open`/`on_ws_close` hooks.

## Design

See [docs/DESIGN.md](docs/DESIGN.md). In short: `IpAddress.listen(io)` → accept
loop → one fiber per connection via `std.Io.Group`. A connection lives entirely
inside its fiber, so there are no locks on the hot path. Handlers run in the fiber
and may block on `io` operations, but must not make foreign OS-blocking calls.

## Scope

**In:** HTTP/1.1 keep-alive, `Content-Length` + chunked bodies (both directions),
WebSocket handshake + framing + fragmentation + ping/pong/close.

**Out (by design):** HTTP/2, pipelining, compression, multipart. **TLS is a
planned Phase 2** (TLS 1.3 over a transport seam on `Stream`, built on
`std.crypto` primitives) — not in this release.
