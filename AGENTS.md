# AGENTS.md — Linsang

Guidance for AI agents working in this repo. Read `docs/DESIGN.md` for the full
design; this file is the working brief.

## What this is

A small embeddable **HTTP/1.1 + WebSocket** server library in **Zig 0.16**, in the
spirit of civetweb. Phase 1 (plaintext) is done. TLS 1.3 is Phase 2 (not started).

## Hard constraints (do not violate)

- **No `std.http`** and **no `std.Io.net`** — we own the socket + protocol code.
- **No third-party dependencies.**
- **No libc** on Linux (raw `std.os.linux` syscalls) and Windows (`ws2_32`/`kernel32`,
  not the C runtime). **macOS is the exception**: `libSystem` is mandatory (Apple has
  no stable syscall ABI, Zig always links it) — that's accepted, not a bug to fix.
- **Low memory**: fixed per-connection buffers, pooled connections, zero-copy bodies.
- **Heavy unit tests**: every non-trivial function keeps a runnable test. Don't add
  logic without a test.

## Commands

```sh
zig build test                 # full suite (must stay green)
zig test src/root.zig          # same, but prints the N/M pass count
zig build run                  # demo server on :8080
zig build -Dtarget=<t>         # cross-compile check (see targets below)
```

Cross-compile matrix that must keep compiling:
`x86_64-linux aarch64-linux x86_64-macos aarch64-macos x86_64-windows`.

## Architecture

Shared-nothing per-thread reactor: one shared listen socket, `N` worker threads
(default = CPU count), each running its own readiness poller. A connection lives
entirely inside one worker → **no locks on the hot path**. Handlers run
synchronously inside the reactor and **must not block**.

Module map (all under `src/`):

| File | Role |
|---|---|
| `root.zig` | public API re-exports + test aggregator |
| `main.zig` | demo server (`zig build run`) |
| `socket.zig` | per-OS TCP ops behind one interface |
| `poller.zig` | per-OS readiness poller behind one interface |
| `http.zig` | `Method`/`Status`/`Request`/`Response` + incremental parser + chunked decoder |
| `websocket.zig` | RFC 6455 handshake + frame codec + `Assembler` |
| `connection.zig` | per-connection state machine + `Config`/handler API + `Pool` |
| `server.zig` | `Server`: threads + accept + reactor loop |

## Conventions

- **Test aggregation**: `root.zig` has `test { _ = module; ... }` for every file.
  When you add `src/foo.zig`, add `pub const foo = @import("foo.zig");` and `_ = foo;`
  or its tests won't run.
- **Per-OS dispatch**: `socket.zig`/`poller.zig` pick a backend at comptime
  (`const impl = switch (builtin.os.tag) {...}`; `const Poller = switch ...`). Keep the
  public surface OS-agnostic; put OS specifics in the backend struct.
- **`// ponytail:` comments** mark deliberate simplifications with their upgrade path.
  Respect them; don't "fix" a documented shortcut without reason.
- **Platform status**: Linux is runtime-tested. macOS (kqueue/`std.c`) and Windows
  (WSAPoll/`ws2_32`) are **cross-compile-verified only** — no host to run them here.
  Linux-only tests guard with `if (builtin.os.tag != .linux) return error.SkipZigTest`.

## Zig 0.16 gotchas already hit (save yourself the round-trips)

- `std.posix.socket/bind/listen/accept` are **removed**; only `poll`/`setsockopt`
  survive. `std.posix.poll` is `@compileError` on Windows.
- Raw Linux syscalls return `usize`; convert with **`std.os.linux.errno(rc)`** →
  `linux.E` (there is no `E.init`). For libc backends use `std.posix.errno(rc)`
  (returns `.SUCCESS` unless `rc == -1`).
- epoll constants live under `std.os.linux.EPOLL.{IN,OUT,ERR,HUP,RDHUP,CTL_ADD,...}`.
- **std provides NO Winsock function bindings** — declare `extern "ws2_32"` yourself
  (see `socket.zig`'s `win` struct). `SOCKET` is `usize`; use `socket.invalid_handle`,
  never `-1`, for the sentinel (Handle is unsigned on Windows).
- `std.once` does **not** exist — use an atomic guard.
- `std.c.kevent`'s changelist/eventlist are non-optional `[*]Kevent`; pass a dummy
  non-null pointer (e.g. `&self.raw`) even when the count is 0.
- `std.ArrayList(T)` is unmanaged: init with `.empty`, methods take the allocator.
- kqueue emits one event **per filter**; `poller.zig` coalesces to one `Event` per fd
  so the reactor can close an fd without a stale second event (use-after-free).

## Scope

**In**: keep-alive, `Content-Length` + chunked (both directions), WebSocket
handshake/framing/fragmentation/ping-pong-close.
**Out**: HTTP/2, pipelining, compression, multipart, streaming response bodies.
**Phase 2**: TLS 1.3 server on `std.crypto` primitives — introduce a transport seam
in `connection.zig` then (Phase 1 does IO directly on the fd).

## Guardrails

- Treat all socket input as untrusted (parse error → 400, oversize → 413/431, bad
  WS → protocol-close). Never panic on bad input.
- Keep `zig build test` green and all cross-targets compiling before finishing.
- Don't commit unless asked.
