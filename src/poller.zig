//! Readiness poller — the per-OS heart of the reactor. One interface, per-OS
//! backend; the reactor loop on top is platform-agnostic.
//!
//!   - Linux:   epoll (raw syscalls, no libc)
//!   - Darwin:  kqueue (std.c / libSystem)
//!   - Windows: WSAPoll (hand-declared ws2_32 externs)
//!
//! Each fd registers a caller-chosen `usize` token (typically a `*Connection`),
//! echoed back on events. `wait` returns AT MOST ONE event per fd (kqueue's
//! per-filter events are coalesced) so the reactor can safely close an fd
//! without a stale second event pointing at freed memory.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const socket = @import("socket.zig");

const Handle = socket.Handle;
const is_darwin = builtin.os.tag.isDarwin();

pub const max_events = 256;

pub const Interest = struct {
    read: bool = false,
    write: bool = false,
};

pub const Event = struct {
    token: usize,
    readable: bool,
    writable: bool,
    /// Peer hung up or the fd errored — the reactor should close it.
    closed: bool,
};

pub const Poller = switch (builtin.os.tag) {
    .linux => EpollPoller,
    .windows => WsaPoller,
    else => if (is_darwin) KqueuePoller else @compileError("poller: unsupported OS"),
};

// ---------------------------------------------------------------------------
// Linux: epoll
// ---------------------------------------------------------------------------

const linux = std.os.linux;

const EpollPoller = struct {
    epfd: i32,
    raw: [max_events]linux.epoll_event = undefined,
    decoded: [max_events]Event = undefined,

    pub fn init(gpa: Allocator) !EpollPoller {
        _ = gpa;
        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        return switch (linux.errno(rc)) {
            .SUCCESS => .{ .epfd = @intCast(rc) },
            else => error.Unexpected,
        };
    }

    pub fn deinit(self: *EpollPoller) void {
        _ = linux.close(self.epfd);
    }

    pub fn add(self: *EpollPoller, fd: Handle, interest: Interest, token: usize) !void {
        return self.ctl(linux.EPOLL.CTL_ADD, fd, interest, token);
    }

    pub fn mod(self: *EpollPoller, fd: Handle, interest: Interest, token: usize) !void {
        return self.ctl(linux.EPOLL.CTL_MOD, fd, interest, token);
    }

    pub fn remove(self: *EpollPoller, fd: Handle) void {
        _ = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_DEL, fd, null);
    }

    fn ctl(self: *EpollPoller, op: u32, fd: Handle, interest: Interest, token: usize) !void {
        var events: u32 = linux.EPOLL.RDHUP;
        if (interest.read) events |= linux.EPOLL.IN;
        if (interest.write) events |= linux.EPOLL.OUT;
        var ev = linux.epoll_event{ .events = events, .data = .{ .ptr = token } };
        return switch (linux.errno(linux.epoll_ctl(self.epfd, op, fd, &ev))) {
            .SUCCESS => {},
            else => error.Unexpected,
        };
    }

    pub fn wait(self: *EpollPoller, timeout_ms: i32) ![]const Event {
        const n = while (true) {
            const rc = linux.epoll_wait(self.epfd, &self.raw, max_events, timeout_ms);
            switch (linux.errno(rc)) {
                .SUCCESS => break rc,
                .INTR => continue,
                else => return error.Unexpected,
            }
        };
        for (self.raw[0..n], 0..) |ev, i| {
            const e = ev.events;
            self.decoded[i] = .{
                .token = ev.data.ptr,
                .readable = (e & linux.EPOLL.IN) != 0,
                .writable = (e & linux.EPOLL.OUT) != 0,
                .closed = (e & (linux.EPOLL.ERR | linux.EPOLL.HUP)) != 0,
            };
        }
        return self.decoded[0..n];
    }
};

// ---------------------------------------------------------------------------
// Darwin: kqueue
// ---------------------------------------------------------------------------

const KqueuePoller = struct {
    const c = std.c;

    kq: i32,
    raw: [max_events]c.Kevent = undefined,
    decoded: [max_events]Event = undefined,

    pub fn init(gpa: Allocator) !KqueuePoller {
        _ = gpa;
        const rc = c.kqueue();
        if (std.posix.errno(rc) != .SUCCESS) return error.Unexpected;
        return .{ .kq = rc };
    }

    pub fn deinit(self: *KqueuePoller) void {
        _ = c.close(self.kq);
    }

    pub fn add(self: *KqueuePoller, fd: Handle, interest: Interest, token: usize) !void {
        return self.applyBoth(fd, interest, token);
    }

    pub fn mod(self: *KqueuePoller, fd: Handle, interest: Interest, token: usize) !void {
        return self.applyBoth(fd, interest, token);
    }

    pub fn remove(self: *KqueuePoller, fd: Handle) void {
        self.applyBoth(fd, .{ .read = false, .write = false }, 0) catch {};
    }

    fn applyBoth(self: *KqueuePoller, fd: Handle, interest: Interest, token: usize) !void {
        try self.one(fd, c.EVFILT.READ, interest.read, token);
        try self.one(fd, c.EVFILT.WRITE, interest.write, token);
    }

    fn one(self: *KqueuePoller, fd: Handle, filter: i16, want: bool, token: usize) !void {
        var ev = c.Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = if (want) c.EV.ADD | c.EV.ENABLE else c.EV.DELETE,
            .fflags = 0,
            .data = 0,
            .udata = token,
        };
        // A DELETE of an unregistered filter returns ENOENT — that's fine.
        // eventlist must be non-null even with nevents=0, so reuse `raw`.
        const rc = c.kevent(self.kq, @ptrCast(&ev), 1, &self.raw, 0, null);
        switch (std.posix.errno(rc)) {
            .SUCCESS, .NOENT => {},
            else => return error.Unexpected,
        }
    }

    pub fn wait(self: *KqueuePoller, timeout_ms: i32) ![]const Event {
        var ts: c.timespec = undefined;
        const ts_ptr: ?*const c.timespec = if (timeout_ms < 0) null else blk: {
            ts = .{ .sec = @divTrunc(timeout_ms, 1000), .nsec = @rem(timeout_ms, 1000) * std.time.ns_per_ms };
            break :blk &ts;
        };
        const n = while (true) {
            // changelist must be non-null even with nchanges=0.
            const rc = c.kevent(self.kq, &self.raw, 0, &self.raw, max_events, ts_ptr);
            switch (std.posix.errno(rc)) {
                .SUCCESS => break @as(usize, @intCast(rc)),
                .INTR => continue,
                else => return error.Unexpected,
            }
        };
        // Coalesce per-filter events (a fd may appear as both READ and WRITE).
        var ndec: usize = 0;
        outer: for (self.raw[0..n]) |ev| {
            const readable = ev.filter == c.EVFILT.READ;
            const writable = ev.filter == c.EVFILT.WRITE;
            const closed = (ev.flags & (c.EV.EOF | c.EV.ERROR)) != 0;
            for (self.decoded[0..ndec]) |*d| {
                if (d.token == ev.udata) {
                    d.readable = d.readable or readable;
                    d.writable = d.writable or writable;
                    d.closed = d.closed or closed;
                    continue :outer;
                }
            }
            self.decoded[ndec] = .{ .token = ev.udata, .readable = readable, .writable = writable, .closed = closed };
            ndec += 1;
        }
        return self.decoded[0..ndec];
    }
};

// ---------------------------------------------------------------------------
// Windows: WSAPoll
// ---------------------------------------------------------------------------

const WsaPoller = struct {
    const win = socket.win;

    gpa: Allocator,
    fds: std.ArrayList(win.WSAPOLLFD) = .empty,
    tokens: std.ArrayList(usize) = .empty,
    decoded: [max_events]Event = undefined,

    pub fn init(gpa: Allocator) !WsaPoller {
        win.ensureStarted();
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *WsaPoller) void {
        self.fds.deinit(self.gpa);
        self.tokens.deinit(self.gpa);
    }

    fn eventsMask(interest: Interest) c_short {
        var m: c_short = 0;
        if (interest.read) m |= win.POLLRDNORM;
        if (interest.write) m |= win.POLLWRNORM;
        return m;
    }

    fn indexOf(self: *WsaPoller, fd: Handle) ?usize {
        for (self.fds.items, 0..) |p, i| if (p.fd == fd) return i;
        return null;
    }

    pub fn add(self: *WsaPoller, fd: Handle, interest: Interest, token: usize) !void {
        try self.fds.append(self.gpa, .{ .fd = fd, .events = eventsMask(interest), .revents = 0 });
        try self.tokens.append(self.gpa, token);
    }

    pub fn mod(self: *WsaPoller, fd: Handle, interest: Interest, token: usize) !void {
        const i = self.indexOf(fd) orelse return self.add(fd, interest, token);
        self.fds.items[i].events = eventsMask(interest);
        self.tokens.items[i] = token;
    }

    pub fn remove(self: *WsaPoller, fd: Handle) void {
        const i = self.indexOf(fd) orelse return;
        _ = self.fds.swapRemove(i);
        _ = self.tokens.swapRemove(i);
    }

    pub fn wait(self: *WsaPoller, timeout_ms: i32) ![]const Event {
        if (self.fds.items.len == 0) return self.decoded[0..0];
        const rc = win.WSAPoll(self.fds.items.ptr, @intCast(self.fds.items.len), timeout_ms);
        if (rc < 0) return error.Unexpected;
        var ndec: usize = 0;
        for (self.fds.items, 0..) |*p, i| {
            const re = p.revents;
            p.revents = 0;
            if (re == 0 or ndec == max_events) continue;
            self.decoded[ndec] = .{
                .token = self.tokens.items[i],
                .readable = (re & win.POLLRDNORM) != 0,
                .writable = (re & win.POLLWRNORM) != 0,
                .closed = (re & (win.POLLERR | win.POLLHUP | win.POLLNVAL)) != 0,
            };
            ndec += 1;
        }
        return self.decoded[0..ndec];
    }
};

// ===========================================================================
// Tests (Linux epoll — the runtime-verified backend)
// ===========================================================================

const testing = std.testing;

test "poller reports readability with the registered token" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var p = try Poller.init(testing.allocator);
    defer p.deinit();

    const listener = try socket.listen(try socket.Address.parse("127.0.0.1", 0), 8);
    defer socket.close(listener);
    const port = try socket.boundPort(listener);

    try p.add(listener, .{ .read = true }, 0xA15);
    const client = try socket.connectBlocking(try socket.Address.parse("127.0.0.1", port));
    defer socket.close(client);

    {
        const evs = try p.wait(1000);
        try testing.expect(evs.len >= 1);
        try testing.expectEqual(@as(usize, 0xA15), evs[0].token);
        try testing.expect(evs[0].readable);
    }

    const server_fd = (try socket.accept(listener)).?;
    defer socket.close(server_fd);

    p.remove(listener);
    try p.add(server_fd, .{ .read = true }, 0x5E54);
    _ = try socket.send(client, "ping");

    const evs = try p.wait(1000);
    try testing.expect(evs.len >= 1);
    try testing.expectEqual(@as(usize, 0x5E54), evs[0].token);
    try testing.expect(evs[0].readable);
}

test "wait with no activity times out empty" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var p = try Poller.init(testing.allocator);
    defer p.deinit();
    const evs = try p.wait(0);
    try testing.expectEqual(@as(usize, 0), evs.len);
}
