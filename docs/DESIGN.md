# Linsang — Design

A small, embeddable HTTP/1.1 + WebSocket server library in Zig 0.16, in the
spirit of civetweb. No `std.http`, no third-party deps, no libc where the OS
permits it, low memory, heavy unit tests.

## Status: `std.Io.net` migration landed

Networking now uses **`std.Io.net`** and accepts a **`std.Io` runtime**.
The hand-rolled `socket.zig`, `poller.zig`, and reactor have been removed;
`http.zig` and `websocket.zig` remain pure protocol code.

Zig 0.16.0's Evented implementations currently expose unavailable network
vtable entries, so the runnable demo and tests use `std.Io.Threaded`.
`std.Io.Evented` remains the fiber-per-connection target once stdlib networking
support lands; no temporary socket backend is kept in this library.

Why the change: `std.Io.net` is stdlib-tested on all three platforms, which
removes the hand-rolled Winsock/kqueue backends we could not run-verify here, and
lets connection handlers be written as straight-line blocking-style code instead
of a state machine. Trade-off accepted below (fiber stacks, Windows fallback).

## Constraints & platform reality

- **No `std.http`**: we own the HTTP + WebSocket protocol code (`http.zig`,
  `websocket.zig`). This is unchanged.
- **`std.Io.net` IS used** for the socket layer (listen/accept/read/write) and
  address parsing. It is not `std.http`, and using it means we no longer hand-roll
  three per-OS socket backends.
- **No third-party dependencies.**
- **No libc** where the OS allows:
  - **Linux** — Evented maps to **io_uring** (`std.Io.Uring`), raw syscalls, no libc.
  - **Windows** — no Evented available (see below) → `std.Io.Threaded`, which uses
    `kernel32`/`ws2_32` system DLLs, not the C runtime.
  - **macOS** — Evented maps to **Dispatch (GCD)**, part of `libSystem`. macOS
    forces `libSystem` regardless (Apple gives no stable syscall ABI), so this is
    unavoidable, not a choice.

## Concurrency target: fiber per connection on the std.Io runtime

The library accepts an `io: std.Io` and threads it through. Callers choose the
implementation:

- **`std.Io.Evented`** (target once networking is implemented) — an event-loop runtime that multiplexes
  fibers over the OS's async facility. Per-OS mapping in 0.16:
  - Linux → **io_uring** (`Uring`)
  - *BSD → `Kqueue`
  - macOS/iOS/… → **Dispatch / GCD**
  - **Windows → not available** (`Evented == void`)
- **`std.Io.Threaded`** — thread-pool blocking runtime. The **required fallback on
  Windows**; also usable anywhere for simple deployments.

`fiber.supported` covers `x86_64`, `aarch64`, `riscv64`.

Model: the server calls `IpAddress.listen(io, …)` then loops on `Server.accept(io)`;
each accepted `Stream` is handed to a fiber via `std.Io.Group.async(io, handleConn, …)`.
A connection lives entirely inside its fiber, so there is **no shared mutable
state and no locks** on the hot path. With Evented, a `read`/`write` that would
block **suspends the fiber** (not the OS thread), so thousands of connections
share a small thread pool.

Handlers run inside the connection fiber. They may freely perform `io`-based
operations (those suspend the fiber); they must **not** make foreign OS-blocking
calls that would stall the underlying worker thread.

## Networking (`std.Io.net`)

- Address: `IpAddress.parse(text, port)` / `.loopback(port)` / `.unspecified(port)`.
- Listen/accept: `IpAddress.listen(io, options) → Server`, `Server.accept(io) → Stream`.
- Per connection: read via a small helper over `io.vtable.netRead(handle, &.{buf})`
  (0 = EOF) into a fixed buffer so the existing incremental parser sees a
  contiguous slice; write the serialized response via `Stream.writer(io, buf)`
  (`writeAll` + `flush`). `Stream.close(io)` / `Stream.shutdown(io, how)`.

## Connection handling: straight-line, no state machine

Because fiber reads block-suspend, each connection is a simple loop instead of a
reactor state machine:

```
read into rbuf until parseHead → done | 431-on-overflow | fail-status
read body (Content-Length slice, or decode chunked in place)
dispatch handler → build response → write + flush
if keep-alive: reset and loop, else close
on WebSocket upgrade: switch to a frame-read loop
```

This reuses `http.zig` (`parseHead`, `decodeChunked`, `Response`) and
`websocket.zig` (`checkUpgrade`, `parseFrame`, `writeFrame`, `Assembler`)
verbatim.

## Memory

- Fixed per-connection read buffer (default 8 KiB); headers over it → 431.
- Bodies: `Content-Length` bodies are a zero-copy slice of the read buffer;
  chunked is decoded in place. Buffered up to `max_body_size` (default 1 MiB) → 413.
- Response buffered, then written (`Content-Length`). Streaming responses are a
  later enhancement (`// ponytail:`).
- **Per-connection cost now also includes a fiber stack** (lazily committed).
  This is heavier than the previous state-machine-per-connection but was accepted
  in exchange for stdlib-tested networking and simpler code. Keep buffers bounded
  and avoid deep recursion in handlers to keep stacks small.
- Long-lived allocation via a caller-provided allocator (`std.heap.page_allocator`
  in the demo; the Evented runtime also needs a backing allocator).

## HTTP/1.1

Incremental request parser (request-line, headers, `Content-Length` + chunked),
keep-alive (honor `Connection: close`), response builder (`Content-Length`).
Out of scope (YAGNI): HTTP/2, pipelining, compression, multipart, 100-continue.
Static file serving = optional example handler, not core.

## WebSocket (RFC 6455)

Upgrade handshake (`Sec-WebSocket-Accept` = base64(SHA-1(key+GUID))), frame
parse/build, client-mask handling, text/binary + fragmentation reassembly
(bounded), ping/pong/close. Protocol violations → close.

## Error handling (trust boundary — never simplified away)

All socket input is untrusted: parse error → 400, header too big → 431, body too
big → 413, bad method/version → 501/505, malformed WS → protocol-error close. No
panics on bad input; a failed connection just ends its fiber and closes.

## Module layout (target)

| File | Responsibility |
|---|---|
| `src/root.zig` | public API surface (re-exports) + test aggregator |
| `src/main.zig` | demo server: builds an `Evented` `io` and runs the server |
| `src/http.zig` | `Method`, `Status`, `Request`, `Response`, incremental parser, chunked decoder *(unchanged)* |
| `src/websocket.zig` | RFC 6455 handshake + frame codec + `Assembler` *(unchanged)* |
| `src/connection.zig` | straight-line per-connection handler + `Config`/handler API |
| `src/server.zig` | `Server`: `std.Io.net` listen + accept loop + fiber-per-connection |

Removed by the migration: `src/socket.zig`, `src/poller.zig`.

## TLS (Phase 2 — separate spec)

Not in this phase. Phase 2 introduces a transport seam over the `Stream` (a plain
passthrough plus a TLS 1.3 record layer built on `std.crypto` primitives) so the
connection loop is agnostic to whether bytes are encrypted.

## Build & test

Linux is runtime-tested here with Threaded (`zig build test`). macOS and Windows
are cross-compile-checked (`zig build -Dtarget=…`) but not runtime-verified in
this environment. `zig build test` runs the whole suite.
