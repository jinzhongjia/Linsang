# AGENTS.md — Linsang

Guidance for AI agents working in this repo. Read `docs/DESIGN.md` for the full
design; this file is the working brief.

## What this is

A small embeddable **HTTP/1.1 + WebSocket** server library in **Zig 0.16**, in the
spirit of civetweb. Plaintext phase. TLS 1.3 is Phase 2 (not started).

## Status: `std.Io.net` migration landed (read this first)

The networking layer now uses **`std.Io.net`** driven by the **`std.Io`
runtime**.

- **Keep**: `http.zig`, `websocket.zig` (pure protocol code — reused verbatim).
- **Removed**: `socket.zig` and `poller.zig` (hand-rolled per-OS sockets +
  readiness poller).
- `connection.zig` and `server.zig` use straight-line handlers and
  `std.Io.Group`, with no reactor state machine.
- Zig 0.16.0's Evented network vtable is not implemented yet, so the runnable
  demo and tests currently use `std.Io.Threaded`. Evented remains the target
  once stdlib support lands.

## Hard constraints (do not violate)

- **No `std.http`** — we own the HTTP + WebSocket protocol code.
- **`std.Io.net` IS allowed and used** for sockets + address parsing (it is not
  `std.http`). Do not re-hand-roll per-OS socket backends.
- **No third-party dependencies.**
- **No libc** where the OS allows: Linux (Evented → io_uring, raw syscalls) and
  Windows (Threaded → `kernel32`/`ws2_32`, not the C runtime). **macOS is the
  exception**: Evented → Dispatch/GCD which is `libSystem`, and macOS forces
  `libSystem` regardless — accepted, not a bug.
- **Low memory**: bounded per-connection buffers, zero-copy `Content-Length`
  bodies. NOTE: each connection now also carries a fiber stack (lazily committed) —
  heavier than the old state machine, accepted for stdlib-tested networking. Keep
  buffers bounded and handler stacks shallow.
- **Heavy unit tests**: every non-trivial function keeps a runnable test.

## Commands

```sh
zig build test                 # full suite (must stay green)
zig test src/root.zig          # same, but prints the N/M pass count
zig build run                  # demo server on :8080
zig build -Dtarget=<t>         # cross-compile check (see targets below)
```

Cross-compile matrix that must keep compiling:
`x86_64-linux aarch64-linux x86_64-macos aarch64-macos x86_64-windows`.

## Architecture (target)

The library takes an `io: std.Io` and threads it through. Callers pick the runtime:

- **`std.Io.Evented`** (target once networking is implemented): Linux → **io_uring**, *BSD → kqueue,
  macOS → **Dispatch/GCD**, **Windows → not available (`void`)**.
- **`std.Io.Threaded`**: thread-pool blocking; the **required Windows fallback**.

`fiber.supported` = `x86_64`, `aarch64`, `riscv64`.

Flow: `IpAddress.listen(io)` → loop `Server.accept(io)` → per `Stream`,
`std.Io.Group.async(io, handleConn, …)`. Each connection lives in its own fiber
(no locks). Blocking `read`/`write` suspends the fiber, not the thread. Handlers
run in the fiber; they may block on `io` ops but must not make foreign OS-blocking
calls.

Module map (target, all under `src/`):

| File | Role |
|---|---|
| `root.zig` | public API re-exports + test aggregator |
| `main.zig` | demo: build an `Evented` `io`, run the server |
| `http.zig` | `Method`/`Status`/`Request`/`Response` + parser + chunked decoder *(unchanged)* |
| `websocket.zig` | RFC 6455 handshake + frame codec + `Assembler` *(unchanged)* |
| `connection.zig` | straight-line per-connection handler + `Config`/handler API |
| `server.zig` | `std.Io.net` listen + accept loop + fiber-per-connection |

## std.Io.net / runtime facts (0.16, verified)

- `IpAddress.parse/loopback/unspecified`, `.listen(io, options) → Server`,
  `Server.accept(io) → Stream`.
- `Stream.reader(io, buf) / .writer(io, buf) / .close(io) / .shutdown(io, how)`;
  `Stream.socket.handle` is the raw fd/SOCKET.
- Raw read for the incremental parser: `io.vtable.netRead(io.userdata, handle, &.{buf})`
  → bytes (0 = EOF). Simple writes: `Stream.writer` → `interface.writeAll` + `flush`.
- Runtime: `std.Io.Evented.init(backing_allocator, .{ .thread_limit = … })`,
  `ev.io()`, `ev.deinit()`. Spawn work with `std.Io.Group` (`g.async(io, fn, args)`,
  `g.wait(io)` / `g.cancel(io)`), or `io.async` / `io.concurrent`.
- `Server.AcceptOptions` is `void` on posix, a struct on Windows — handle both.

## Zig 0.16 gotchas still relevant

- `std.ArrayList(T)` is unmanaged: init with `.empty`, methods take the allocator.
- Raw Linux syscalls (in `http.zig`/tests only now) return `usize`; convert with
  `std.os.linux.errno(rc)` → `linux.E` (no `E.init`).
- Reader/Writer are `std.Io.Reader`/`Io.Writer` with a `.interface` field; pass
  `&x.interface`. Pass real buffers.

### Obsolete gotchas (were for the removed hand-rolled layer)

These no longer apply once `socket.zig`/`poller.zig` are gone; kept as history:
hand-declared `ws2_32` externs, `SOCKET`/`invalid_handle` sentinel, `std.posix`
socket wrappers being removed, `std.c.kevent` non-null lists, kqueue per-filter
event coalescing. `std.Io.net` handles all of this now.

## Conventions

- **Test aggregation**: `root.zig` has `test { _ = module; … }` per file. New file
  `src/foo.zig` → add `pub const foo = @import("foo.zig");` and `_ = foo;`.
- **`// ponytail:` comments** mark deliberate simplifications with their upgrade
  path. Respect them.
- **Platform status**: Linux is runtime-tested with Threaded. macOS and Windows
  are cross-compile-verified only. Linux-only tests guard with
  `if (builtin.os.tag != .linux) return error.SkipZigTest`.

## Scope

**In**: keep-alive, `Content-Length` + chunked (both directions), WebSocket
handshake/framing/fragmentation/ping-pong-close.
**Out**: HTTP/2, pipelining, compression, multipart, streaming response bodies.
**Phase 2**: TLS 1.3 over a transport seam on `Stream`, built on `std.crypto`.

## Guardrails

- Treat all socket input as untrusted (parse error → 400, oversize → 413/431, bad
  WS → protocol-close). Never panic on bad input.
- Keep `zig build test` green and all cross-targets compiling before finishing.
- Don't commit unless asked.
