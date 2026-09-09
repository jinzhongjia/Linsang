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
  over real TCP. TLS is also checked against curl and OpenSSL with RSA and ECDSA
  certificates.

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

Listener startup and I/O/deadline races use required `std.Io.concurrent`, not
opportunistic `async`, which is allowed to run inline when its worker limit is
reached. Correctness therefore does not require an unlimited async pool.

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
zig build test              # run the full unit + integration suite
zig build fuzz --fuzz=100K  # bounded HTTP/static/WebSocket/TLS parser fuzzing
zig build interop           # curl/OpenSSL × RSA/ECDSA × TLS 1.2/1.3
zig build run               # start the demo server on http://0.0.0.0:8080
zig build                   # build the demo binary into zig-out/bin/linsang
```

The normal test suite also runs 10,000 deterministic random parser inputs and
the fuzz seed corpora. Omit the `=100K` limit for continuous fuzzing. CI runs
the normal, fuzz, and TLS interoperability suites, then cross-compiles the full
five-target matrix.

## Use as a library

The API threads a `std.Io` instance through the server:

```zig
const std = @import("std");
const linsang = @import("Linsang");

const App = struct {
    files: linsang.StaticFiles,
};

fn onRequest(req: *const linsang.Request, res: *linsang.Response, ud: ?*anyopaque) linsang.Action {
    const app: *const App = @ptrCast(@alignCast(ud.?));
    if (std.mem.eql(u8, req.path, "/ws")) return .upgrade; // hand off to WebSocket
    if (std.mem.startsWith(u8, req.path, "/assets/"))
        return .{ .files = app.files };
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

    var public = try std.Io.Dir.cwd().openDir(io, "public", .{});
    defer public.close(io);
    var app: App = .{ .files = .{ .dir = public } };

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
        .user_data = &app,
    });
    try server.run(io); // accept loop + one std.Io task per connection
}
```

`CertKeyPair` verifies that the private key matches the leaf certificate while
loading, before the server starts accepting TLS connections.
TLS readers may wrap immutable ciphertext. `Connection.next()` decrypts into
bounded connection-owned storage rather than modifying the reader's input;
its returned slice remains valid until the next read or next call.

`Config` knobs: `tls`, `read_buffer_size`, `max_body_size`, `max_ws_message_size`,
`request_timeout`, `keep_alive_timeout`, `write_timeout`, `backlog`, `max_connections`,
`user_data`, and the `on_ws_open`/`on_ws_close` hooks. Set a timeout to `null`
to disable it. `max_connections` defaults to 128; excess accepted connections
receive 503 on plaintext listeners, or are closed before TLS negotiation, so
Threaded cannot grow its worker pool without bound.

The `.files` action serves GET/HEAD below its opened directory. Directory URLs
ending in `/` resolve to `index.html`; responses include a weak metadata ETag,
support `If-None-Match`, and support one byte range per request. Its optional
`on_complete(user_data)` runs exactly once after the response stops using the
directory; directory ownership remains with the caller.
`StaticFiles.canonical_path` optionally supplies an already-decoded relative
resource path. It is still checked for traversal and forbidden bytes but is
not percent-decoded again. Keep the slice alive through `on_complete`.

For server-initiated WebSocket traffic, call `conn.peer()` inside
`on_ws_open` and store the returned owned `WebSocketPeer`, not `*Connection`.
Clone it when transferring ownership to another task and `deinit` every owned
handle. `sendText`/`sendBinary` flush immediately, serialize concurrent frames,
and return `error.Closed` or `error.Canceled` when disconnect races a send.

`conn.req` remains valid during `on_ws_open`, including when the first
WebSocket frame arrived with the upgrade request. Copy any authorization or
route identity needed later; request slices expire when the callback returns.
From connection callbacks, `conn.setWebSocketDeadline(deadline)` installs an
absolute application deadline that also bounds control-frame processing and
reads/writes. Clear it with `null` after authentication to resume
`Config.ws_idle_timeout`. Mutate it through the setter, not the backing field.

For managed lifetimes, `try server.start(io)` binds synchronously and returns a
`Running` handle. `running.address.getPort()` is therefore non-zero before the
caller launches a dependent client when configured with port zero.
`running.stop()` stops accepting, cancels active connections, and waits for
their cleanup.

## Design

See [docs/DESIGN.md](docs/DESIGN.md). In short: `IpAddress.listen(io)` → accept
loop → one task per connection via `std.Io.Group`. Ordinary connection state
lives entirely inside its task; the optional outbound WebSocket handle uses one
`std.Io.Mutex` to serialize frames. Under Evented the task is a fiber; under
Threaded it uses the runtime's thread pool.

## Scope

**In:** HTTP/1.1 keep-alive, buffered and streaming responses, `Content-Length`
+ chunked bodies (both directions), bounded-memory static file GET/HEAD with
`index.html`, Range, and ETag, WebSocket handshake + framing + fragmentation +
ping/pong/close + task-safe outbound peers, and TLS 1.2/1.3 server transport.

**Out (by design):** HTTP/2, pipelining, compression, multipart, TLS client
mode, TLS session resumption, and mTLS. TLS advertises only `http/1.1` through
ALPN.
