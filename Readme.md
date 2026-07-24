# Linsang

A small, embeddable **HTTP/1.1 + WebSocket** server library in Zig 0.16, in the
spirit of [civetweb](https://github.com/civetweb/civetweb).

- **No `std.http`** — the HTTP + WebSocket protocol code is our own.
- Networking uses **`std.Io.net`** on the **`std.Io` runtime** (one task per
  connection; a fiber under Evented), so we don't hand-roll per-OS socket code.
- **No third-party dependencies.**
- **No libc** where the OS allows: Linux (Evented → io_uring) and Windows
  (Threaded → `kernel32`/`ws2_32`, not the C runtime). macOS necessarily links
  `libSystem` (Evented → Dispatch/GCD; Apple provides no stable syscall ABI).
- **Low memory**: bounded per-connection buffers, zero-copy `Content-Length`
  bodies. Each connection carries a (lazily-committed) fiber stack.
- **TLS 1.2 + 1.3 server support**, with ALPN restricted to `http/1.1`.
- **Heavily unit-tested**: parser, chunked decoding, WebSocket codec (incl. the
  RFC 6455 accept vector), and end-to-end HTTP, WebSocket, TLS 1.2, and TLS 1.3
  over real TCP.

> **Status:** the networking layer now uses `std.Io.net`; the previous
> socket/poller/reactor has been removed. Zig 0.16.0's Evented network vtable is
> not implemented yet, so the runnable demo and tests currently use
> `std.Io.Threaded`.

## Concurrency runtime

The library takes an `io: std.Io` and threads it through. Callers choose:

- **`std.Io.Evented`** (target once its network vtable is implemented) —
  fiber-based event loop:
  Linux → **io_uring**, \*BSD → kqueue, macOS → **Dispatch/GCD**,
  **Windows → not available**.
- **`std.Io.Threaded`** — thread-pool blocking; the **required fallback on Windows**.

A blocking `read`/`write` suspends the connection's fiber, not the OS thread, so
many connections share a small thread pool. Fibers are supported on `x86_64`,
`aarch64`, `riscv64`.

## Platforms

| OS | Runtime | Status |
|----|---------|--------|
| Linux | `std.Io.Threaded` currently; Evented target | runtime-tested |
| macOS | `std.Io.Threaded` currently; Evented target | cross-compile-verified |
| Windows | `std.Io.Threaded` (`ws2_32`, no CRT) | cross-compile-verified |

`x86_64` and `aarch64` both cross-compile. macOS/Windows are compiled and
type-checked but not runtime-tested (no host available in this environment).

## Build

```sh
zig build test    # run the full unit + integration suite
zig build run     # start the demo server on http://0.0.0.0:8080 (WebSocket echo at /ws)
zig build         # build the demo binary into zig-out/bin/linsang
```

The normal test suite also runs 10,000 deterministic random parser inputs.
CI repeats it and cross-compiles the full five-target matrix.

## Use as a library

The API threads a `std.Io` instance through the server:

```zig
const std = @import("std");
const linsang = @import("Linsang");

fn onRequest(req: *const linsang.Request, res: *linsang.Response, ud: ?*anyopaque) linsang.Action {
    _ = ud;
    if (std.mem.eql(u8, req.path, "/ws")) return .upgrade; // hand off to WebSocket
    if (std.mem.eql(u8, req.path, "/stream")) {
        res.setHeader("Content-Type", "text/plain") catch {};
        return .{ .stream = streamBody };
    }
    res.status = .ok;
    res.setHeader("Content-Type", "text/plain") catch {};
    res.print("hello {s}", .{req.path}) catch {};
    return .respond;
}

fn streamBody(_: *const linsang.Request, conn: *linsang.Connection, _: ?*anyopaque) !void {
    try conn.writeChunk("first\n");
    try conn.writeChunk("second\n");
} // the final chunk is written automatically

fn onMessage(conn: *linsang.Connection, msg: linsang.websocket.Message, ud: ?*anyopaque) void {
    _ = ud;
    conn.sendText(msg.data) catch {}; // echo
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var auth = try linsang.tls.CertKeyPair.fromFilePath(
        gpa,
        io,
        std.Io.Dir.cwd(),
        "cert.pem",
        "key.pem",
    );
    defer auth.deinit(gpa);

    var server = linsang.Server.init(gpa, .{
        .address = "0.0.0.0",
        .port = 8443,
        .tls = .{ .auth = &auth }, // omit for plaintext
        .on_request = onRequest,
        .on_ws_message = onMessage, // optional
    });
    try server.run(io); // accept loop + one std.Io task per connection
}
```

`Config` knobs: `tls`, `read_buffer_size`, `max_body_size`, `max_ws_message_size`,
`request_timeout`, `keep_alive_timeout`, `write_timeout`, `backlog`, `max_connections`,
`user_data`, and the `on_ws_open`/`on_ws_close` hooks. Set a timeout to `null`
to disable it. `max_connections` defaults to 128; excess accepted connections
receive 503 on plaintext listeners, or are closed before TLS negotiation, so
Threaded cannot grow its worker pool without bound.

For managed lifetimes, `server.start(io)` returns a `Running` handle.
`running.stop()` stops accepting, cancels active connections, and waits for
their cleanup.

## Design

See [docs/DESIGN.md](docs/DESIGN.md). In short: `IpAddress.listen(io)` → accept
loop → one task per connection via `std.Io.Group`. A connection lives entirely
inside its task, so there are no locks on the hot path. Under Evented the task is
a fiber; under Threaded it uses the runtime's thread pool.

## Scope

**In:** HTTP/1.1 keep-alive, buffered and streaming responses, `Content-Length`
+ chunked bodies (both directions), WebSocket handshake + framing +
fragmentation + ping/pong/close, and TLS 1.2/1.3 server transport.

**Out (by design):** HTTP/2, pipelining, compression, multipart, TLS client
mode, TLS session resumption, and mTLS. TLS advertises only `http/1.1` through
ALPN.
