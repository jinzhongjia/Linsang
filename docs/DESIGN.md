# Linsang — Design

A small, embeddable HTTP/1.1 + WebSocket server library in Zig 0.16, in the
spirit of civetweb. No `std.http`, no third-party deps, no libc where the OS
permits it, low memory, heavy unit tests.

## Constraints & platform reality

- **No libc**: honored on **Linux** (raw syscalls via `std.os.linux`) and
  **Windows** (system DLLs `ws2_32`/`kernel32`/`ntdll`, not the C runtime).
  **macOS forces `libSystem`** — Apple gives no stable syscall ABI and Zig
  always links it for Darwin. That is unavoidable, not a choice.
- **No `std.http`** and **no `std.Io.net`**: we own the socket and protocol code.
  In Zig 0.16 the old `std.posix.socket/bind/listen/accept` wrappers were
  removed and `std.posix.poll` is `@compileError` on Windows, so the socket +
  readiness layers are per-OS regardless.

## Concurrency: shared-nothing per-thread reactor

- `N` worker threads (default = CPU count).
- Portable model: **one shared listen socket**, every worker's poller watches it
  and workers race to `accept` (thread-safe at the OS level). After accept a
  connection lives entirely inside one worker → no shared mutable state, no locks
  on the hot path.
- `SO_REUSEPORT` + `EPOLLEXCLUSIVE` (per-thread listen sockets) are a Linux-only
  optimization for later; not needed for correctness.

## Readiness poller (per-OS, one interface)

`Poller` = `{ init, deinit, add(fd,ev), mod(fd,ev), remove(fd), wait(timeout) -> []Event }`.
- Linux → `epoll` (raw syscalls, no libc)
- macOS → `kqueue` (via `std.c`/libSystem)
- Windows → `WSAPoll` (via `ws2_32`)

The reactor loop on top is platform-agnostic.

## Memory

- Fixed per-connection read buffer (default 8 KiB); headers over it → 431.
- Connection structs pooled per-worker (free list) → no per-request alloc churn.
- Bodies buffered up to `max_body_size` (default 1 MiB) → 413 beyond.
  Streaming bodies is a later enhancement (marked `// ponytail:`).
- Long-lived allocation via `std.heap.page_allocator` (mmap, no libc).

## HTTP/1.1 v1

Incremental request parser (request-line, headers, Content-Length + chunked),
keep-alive (honor `Connection: close`), response builder (Content-Length or
chunked). Out of scope (YAGNI): HTTP/2, pipelining, compression, multipart,
100-continue. Static file serving = optional example handler, not core.

## WebSocket v1 (RFC 6455)

Upgrade handshake (`Sec-WebSocket-Accept` = base64(SHA-1(key+GUID))), frame
parse/build, client-mask handling, text/binary + fragmentation reassembly
(bounded), ping/pong/close. Protocol violations → close.

## Error handling (trust boundary — never simplified away)

All socket input is untrusted: parse error → 400, header too big → 431, body too
big → 413, bad method/version → 501/505, malformed WS → protocol-error close. No
panics on bad input; failed connections are freed back to the pool.

## Module layout

| File | Responsibility |
|---|---|
| `src/root.zig` | public API surface (re-exports) + test aggregator |
| `src/main.zig` | demo standalone server (`zig build run`) |
| `src/socket.zig` | per-OS socket ops (comptime switch on `builtin.os.tag`) |
| `src/poller.zig` | per-OS readiness poller behind one interface |
| `src/http.zig` | `Method`, `Request`, `Response`, incremental parser |
| `src/websocket.zig` | RFC 6455 handshake + framing |
| `src/connection.zig` | per-connection state machine |
| `src/server.zig` | config, worker threads, accept + reactor loop |

## TLS (Phase 2 — separate spec)

Not in this phase. Phase 1 does IO directly on the fd (no one-impl abstraction).
Phase 2 introduces a transport seam then, when a plain + TLS record layer both
exist, using `std.crypto` primitives to build a TLS 1.3 server.

## Build & test order

Linux-first (compiles + runs + tests here). mac/Windows backends are
cross-compile-checked (`zig build -Dtarget=...`) but not runtime-verified in this
environment. `zig build test` runs the whole suite.
