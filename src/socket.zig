//! Per-OS TCP socket operations behind one interface.
//!
//! Zig 0.16 removed the cross-platform `std.posix.socket/bind/listen/accept`
//! wrappers, so each OS gets its own backend:
//!   - Linux:   raw syscalls via `std.os.linux` (no libc)
//!   - Darwin:  `std.c` / libSystem (mandatory on Apple platforms)
//!   - Windows: hand-declared `ws2_32` externs (std ships none)
//!
//! Constants (`AF`, `SOCK`, `SO`, ...) are still cross-platform via `std.posix`.
//! Linux is runtime-tested here; macOS/Windows are cross-compile-verified.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const is_darwin = builtin.os.tag.isDarwin();

pub const Handle = switch (builtin.os.tag) {
    .windows => win.SOCKET,
    else => posix.fd_t,
};

/// Sentinel for "no socket".
pub const invalid_handle: Handle = switch (builtin.os.tag) {
    .windows => win.INVALID_SOCKET,
    else => -1,
};

pub const Error = error{
    AddressInUse,
    AddressInvalid,
    PermissionDenied,
    SystemResources,
    ConnectionReset,
    Unexpected,
};

pub const IoError = error{ WouldBlock, ConnectionReset, SystemResources, Unexpected };

const impl = switch (builtin.os.tag) {
    .linux => LinuxImpl,
    .windows => WindowsImpl,
    else => if (is_darwin) DarwinImpl else @compileError("unsupported OS"),
};

// ---------------------------------------------------------------------------
// Address (shared)
// ---------------------------------------------------------------------------

pub const Address = union(enum) {
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,

    pub const ParseError = error{InvalidAddress};

    /// Parse a host literal + port: dotted IPv4, plus "::"/"::1".
    // ponytail: full IPv6 literal parsing only when someone binds to one.
    pub fn parse(host: []const u8, port: u16) ParseError!Address {
        if (parseIp4(host)) |octets| {
            return .{ .in = .{
                .port = std.mem.nativeToBig(u16, port),
                .addr = @bitCast(octets),
            } };
        }
        if (std.mem.eql(u8, host, "::") or std.mem.eql(u8, host, "::0"))
            return v6(std.mem.zeroes([16]u8), port);
        if (std.mem.eql(u8, host, "::1")) {
            var a = std.mem.zeroes([16]u8);
            a[15] = 1;
            return v6(a, port);
        }
        return error.InvalidAddress;
    }

    fn v6(addr: [16]u8, port: u16) Address {
        return .{ .in6 = .{
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = 0,
            .addr = addr,
            .scope_id = 0,
        } };
    }

    pub fn family(self: Address) u32 {
        return switch (self) {
            .in => posix.AF.INET,
            .in6 => posix.AF.INET6,
        };
    }

    fn ptr(self: *const Address) *const posix.sockaddr {
        return switch (self.*) {
            .in => |*a| @ptrCast(a),
            .in6 => |*a| @ptrCast(a),
        };
    }

    fn len(self: Address) posix.socklen_t {
        return switch (self) {
            .in => @sizeOf(posix.sockaddr.in),
            .in6 => @sizeOf(posix.sockaddr.in6),
        };
    }
};

fn parseIp4(host: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, host, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        const n = std.fmt.parseInt(u16, part, 10) catch return null;
        if (n > 255) return null;
        out[i] = @intCast(n);
    }
    if (i != 4) return null;
    return out;
}

// ---------------------------------------------------------------------------
// Public operations (delegate to the per-OS backend)
// ---------------------------------------------------------------------------

/// Create a non-blocking TCP socket, set SO_REUSEADDR, bind, and listen.
pub fn listen(addr: Address, backlog: u31) Error!Handle {
    return impl.listen(addr, backlog);
}

/// Accept one pending connection (non-blocking). Returns null if none is ready.
pub fn accept(listener: Handle) IoError!?Handle {
    return impl.accept(listener);
}

/// Read into `buf`. Returns 0 on orderly peer shutdown.
pub fn recv(fd: Handle, buf: []u8) IoError!usize {
    return impl.recv(fd, buf);
}

/// Write `buf`. Returns the number of bytes written (may be short).
pub fn send(fd: Handle, buf: []const u8) IoError!usize {
    return impl.send(fd, buf);
}

pub fn close(fd: Handle) void {
    impl.close(fd);
}

/// Local port bound to `fd` (host order). Useful after binding to port 0.
pub fn boundPort(fd: Handle) Error!u16 {
    return impl.boundPort(fd);
}

/// Blocking connect — for test clients only, never on the server hot path.
pub fn connectBlocking(addr: Address) Error!Handle {
    return impl.connectBlocking(addr);
}

// ---------------------------------------------------------------------------
// Linux backend (raw syscalls, no libc)
// ---------------------------------------------------------------------------

const LinuxImpl = struct {
    const linux = std.os.linux;

    fn listen(addr: Address, backlog: u31) Error!Handle {
        const fd = try sock(addr.family());
        errdefer LinuxImpl.close(fd);
        const one: u32 = 1;
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(u32));
        switch (linux.errno(linux.bind(fd, addr.ptr(), addr.len()))) {
            .SUCCESS => {},
            .ADDRINUSE => return error.AddressInUse,
            .ACCES => return error.PermissionDenied,
            .ADDRNOTAVAIL, .INVAL, .AFNOSUPPORT => return error.AddressInvalid,
            else => return error.Unexpected,
        }
        switch (linux.errno(linux.listen(fd, backlog))) {
            .SUCCESS => {},
            .ADDRINUSE => return error.AddressInUse,
            else => return error.Unexpected,
        }
        return fd;
    }

    fn sock(family: u32) Error!Handle {
        const flags: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        const rc = linux.socket(family, flags, 0);
        return switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .ACCES => error.PermissionDenied,
            .MFILE, .NFILE, .NOBUFS, .NOMEM => error.SystemResources,
            else => error.Unexpected,
        };
    }

    fn accept(listener: Handle) IoError!?Handle {
        while (true) {
            const rc = linux.accept4(listener, null, null, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC);
            switch (linux.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .AGAIN => return null,
                .INTR => continue,
                .CONNABORTED => return null,
                .MFILE, .NFILE, .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.Unexpected,
            }
        }
    }

    fn recv(fd: Handle, buf: []u8) IoError!usize {
        while (true) {
            const rc = linux.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .AGAIN => return error.WouldBlock,
                .INTR => continue,
                .CONNRESET => return error.ConnectionReset,
                .NOMEM => return error.SystemResources,
                else => return error.Unexpected,
            }
        }
    }

    fn send(fd: Handle, buf: []const u8) IoError!usize {
        while (true) {
            const rc = linux.sendto(fd, buf.ptr, buf.len, linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .AGAIN => return error.WouldBlock,
                .INTR => continue,
                .PIPE, .CONNRESET => return error.ConnectionReset,
                .NOMEM, .NOBUFS => return error.SystemResources,
                else => return error.Unexpected,
            }
        }
    }

    fn close(fd: Handle) void {
        _ = linux.close(fd);
    }

    fn boundPort(fd: Handle) Error!u16 {
        var storage: posix.sockaddr.in6 = undefined;
        var slen: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
        switch (linux.errno(linux.getsockname(fd, @ptrCast(&storage), &slen))) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }
        return std.mem.bigToNative(u16, storage.port);
    }

    fn connectBlocking(addr: Address) Error!Handle {
        const rc = linux.socket(addr.family(), posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        const fd: Handle = switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => return error.Unexpected,
        };
        errdefer LinuxImpl.close(fd);
        while (true) {
            switch (linux.errno(linux.connect(fd, addr.ptr(), addr.len()))) {
                .SUCCESS => return fd,
                .INTR => continue,
                .CONNREFUSED => return error.ConnectionReset,
                .ADDRNOTAVAIL, .AFNOSUPPORT => return error.AddressInvalid,
                else => return error.Unexpected,
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Darwin backend (std.c / libSystem)
// ---------------------------------------------------------------------------

const DarwinImpl = struct {
    const c = std.c;

    fn setFlags(fd: Handle) void {
        const nb: c_int = @bitCast(posix.O{ .NONBLOCK = true });
        _ = c.fcntl(fd, posix.F.SETFL, nb);
        _ = c.fcntl(fd, posix.F.SETFD, @as(c_int, 1)); // FD_CLOEXEC
        const one: c_int = 1;
        _ = c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.NOSIGPIPE, &one, @sizeOf(c_int));
    }

    fn listen(addr: Address, backlog: u31) Error!Handle {
        const rc = c.socket(@intCast(addr.family()), posix.SOCK.STREAM, 0);
        if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
        const fd: Handle = rc;
        errdefer DarwinImpl.close(fd);
        setFlags(fd);
        const one: c_int = 1;
        _ = c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one, @sizeOf(c_int));
        switch (posix.errno(c.bind(fd, addr.ptr(), addr.len()))) {
            .SUCCESS => {},
            .ADDRINUSE => return error.AddressInUse,
            .ACCES => return error.PermissionDenied,
            else => return error.AddressInvalid,
        }
        if (posix.errno(c.listen(fd, backlog)) != .SUCCESS) return error.Unexpected;
        return fd;
    }

    fn accept(listener: Handle) IoError!?Handle {
        while (true) {
            const rc = c.accept(listener, null, null);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    setFlags(rc);
                    return rc;
                },
                .AGAIN => return null,
                .INTR => continue,
                .CONNABORTED => return null,
                .MFILE, .NFILE, .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.Unexpected,
            }
        }
    }

    fn recv(fd: Handle, buf: []u8) IoError!usize {
        while (true) {
            const rc = c.recv(fd, buf.ptr, buf.len, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .AGAIN => return error.WouldBlock,
                .INTR => continue,
                .CONNRESET => return error.ConnectionReset,
                else => return error.Unexpected,
            }
        }
    }

    fn send(fd: Handle, buf: []const u8) IoError!usize {
        while (true) {
            const rc = c.send(fd, buf.ptr, buf.len, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .AGAIN => return error.WouldBlock,
                .INTR => continue,
                .PIPE, .CONNRESET => return error.ConnectionReset,
                else => return error.Unexpected,
            }
        }
    }

    fn close(fd: Handle) void {
        _ = c.close(fd);
    }

    fn boundPort(fd: Handle) Error!u16 {
        var storage: posix.sockaddr.in6 = undefined;
        var slen: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
        if (posix.errno(c.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.Unexpected;
        return std.mem.bigToNative(u16, storage.port);
    }

    fn connectBlocking(addr: Address) Error!Handle {
        const rc = c.socket(@intCast(addr.family()), posix.SOCK.STREAM, 0);
        if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
        const fd: Handle = rc;
        errdefer DarwinImpl.close(fd);
        while (true) {
            switch (posix.errno(c.connect(fd, addr.ptr(), addr.len()))) {
                .SUCCESS => return fd,
                .INTR => continue,
                .CONNREFUSED => return error.ConnectionReset,
                else => return error.Unexpected,
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Windows backend (ws2_32) — cross-compile-verified, not runtime-tested here
// ---------------------------------------------------------------------------

pub const win = struct {
    pub const SOCKET = usize;
    pub const INVALID_SOCKET: SOCKET = ~@as(usize, 0);
    const SOCKET_ERROR: c_int = -1;

    pub const WSAEWOULDBLOCK: c_int = 10035;
    pub const WSAECONNRESET: c_int = 10054;
    pub const WSAECONNABORTED: c_int = 10053;
    pub const WSAEADDRINUSE: c_int = 10048;
    pub const WSAEINTR: c_int = 10004;
    pub const FIONBIO: c_long = @bitCast(@as(c_ulong, 0x8004667E));

    const WSADATA = extern struct {
        wVersion: u16,
        wHighVersion: u16,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: ?[*]u8,
        szDescription: [257]u8,
        szSystemStatus: [129]u8,
    };

    pub extern "ws2_32" fn WSAStartup(v: u16, d: *WSADATA) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
    pub extern "ws2_32" fn socket(af: c_int, ty: c_int, protocol: c_int) callconv(.winapi) SOCKET;
    pub extern "ws2_32" fn bind(s: SOCKET, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn listen(s: SOCKET, backlog: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn accept(s: SOCKET, addr: ?*anyopaque, addrlen: ?*c_int) callconv(.winapi) SOCKET;
    pub extern "ws2_32" fn recv(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn send(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
    pub extern "ws2_32" fn setsockopt(s: SOCKET, level: c_int, optname: c_int, optval: [*]const u8, optlen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn connect(s: SOCKET, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getsockname(s: SOCKET, name: *anyopaque, namelen: *c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn ioctlsocket(s: SOCKET, cmd: c_long, argp: *c_ulong) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAPoll(fds: [*]WSAPOLLFD, nfds: c_ulong, timeout: c_int) callconv(.winapi) c_int;

    pub const WSAPOLLFD = extern struct {
        fd: SOCKET,
        events: c_short,
        revents: c_short,
    };
    pub const POLLRDNORM: c_short = 0x0100;
    pub const POLLWRNORM: c_short = 0x0010;
    pub const POLLERR: c_short = 0x0001;
    pub const POLLHUP: c_short = 0x0002;
    pub const POLLNVAL: c_short = 0x0004;

    // WSAStartup is refcounted and thread-safe; calling it more than once is
    // harmless, so a plain atomic guard (no strict once) is enough.
    var wsa_done = std.atomic.Value(bool).init(false);
    pub fn ensureStarted() void {
        if (wsa_done.load(.acquire)) return;
        var data: WSADATA = undefined;
        _ = WSAStartup(0x0202, &data); // request Winsock 2.2
        wsa_done.store(true, .release);
    }
};

const WindowsImpl = struct {
    fn setNonBlock(fd: Handle) void {
        var yes: c_ulong = 1;
        _ = win.ioctlsocket(fd, win.FIONBIO, &yes);
    }

    fn newSocket(family: u32) Error!Handle {
        win.ensureStarted();
        const s = win.socket(@intCast(family), posix.SOCK.STREAM, 0);
        if (s == win.INVALID_SOCKET) return error.Unexpected;
        return s;
    }

    fn listen(addr: Address, backlog: u31) Error!Handle {
        const fd = try newSocket(addr.family());
        errdefer WindowsImpl.close(fd);
        setNonBlock(fd);
        const one: c_int = 1;
        _ = win.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(c_int));
        if (win.bind(fd, addr.ptr(), @intCast(addr.len())) != 0) {
            return if (win.WSAGetLastError() == win.WSAEADDRINUSE) error.AddressInUse else error.AddressInvalid;
        }
        if (win.listen(fd, backlog) != 0) return error.Unexpected;
        return fd;
    }

    fn accept(listener: Handle) IoError!?Handle {
        const s = win.accept(listener, null, null);
        if (s == win.INVALID_SOCKET) {
            return switch (win.WSAGetLastError()) {
                win.WSAEWOULDBLOCK => null,
                win.WSAECONNRESET, win.WSAECONNABORTED => null,
                else => error.Unexpected,
            };
        }
        setNonBlock(s);
        return s;
    }

    fn recv(fd: Handle, buf: []u8) IoError!usize {
        const rc = win.recv(fd, buf.ptr, @intCast(buf.len), 0);
        if (rc >= 0) return @intCast(rc);
        return switch (win.WSAGetLastError()) {
            win.WSAEWOULDBLOCK => error.WouldBlock,
            win.WSAECONNRESET, win.WSAECONNABORTED => error.ConnectionReset,
            else => error.Unexpected,
        };
    }

    fn send(fd: Handle, buf: []const u8) IoError!usize {
        const rc = win.send(fd, buf.ptr, @intCast(buf.len), 0);
        if (rc >= 0) return @intCast(rc);
        return switch (win.WSAGetLastError()) {
            win.WSAEWOULDBLOCK => error.WouldBlock,
            win.WSAECONNRESET, win.WSAECONNABORTED => error.ConnectionReset,
            else => error.Unexpected,
        };
    }

    fn close(fd: Handle) void {
        _ = win.closesocket(fd);
    }

    fn boundPort(fd: Handle) Error!u16 {
        var storage: posix.sockaddr.in6 = undefined;
        var slen: c_int = @sizeOf(posix.sockaddr.in6);
        if (win.getsockname(fd, @ptrCast(&storage), &slen) != 0) return error.Unexpected;
        return std.mem.bigToNative(u16, storage.port);
    }

    fn connectBlocking(addr: Address) Error!Handle {
        const fd = try newSocket(addr.family());
        errdefer WindowsImpl.close(fd);
        // newSocket set non-blocking; make it blocking for the test client.
        var no: c_ulong = 0;
        _ = win.ioctlsocket(fd, win.FIONBIO, &no);
        if (win.connect(fd, addr.ptr(), @intCast(addr.len())) != 0) return error.ConnectionReset;
        return fd;
    }
};

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "parseIp4 valid and invalid" {
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, parseIp4("127.0.0.1").?);
    try testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIp4("0.0.0.0").?);
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, parseIp4("255.255.255.255").?);
    try testing.expect(parseIp4("256.0.0.1") == null);
    try testing.expect(parseIp4("1.2.3") == null);
    try testing.expect(parseIp4("1.2.3.4.5") == null);
    try testing.expect(parseIp4("1.2.3.") == null);
    try testing.expect(parseIp4("a.b.c.d") == null);
    try testing.expect(parseIp4("") == null);
}

test "Address.parse builds sockaddr" {
    const a = try Address.parse("127.0.0.1", 8080);
    try testing.expect(a == .in);
    try testing.expectEqual(std.mem.nativeToBig(u16, 8080), a.in.port);
    try testing.expectEqual(posix.AF.INET, a.family());

    const v6a = try Address.parse("::1", 443);
    try testing.expect(v6a == .in6);
    try testing.expectEqual(posix.AF.INET6, v6a.family());

    try testing.expectError(error.InvalidAddress, Address.parse("nope", 1));
}

test "listen/accept/send/recv loopback round-trip" {
    const listener = try listen(try Address.parse("127.0.0.1", 0), 8);
    defer close(listener);
    const port = try boundPort(listener);
    try testing.expect(port != 0);

    const client = try connectBlocking(try Address.parse("127.0.0.1", port));
    defer close(client);

    var server_fd: Handle = undefined;
    var tries: usize = 0;
    while (true) : (tries += 1) {
        if (try accept(listener)) |fd| {
            server_fd = fd;
            break;
        }
        try testing.expect(tries < 100000);
    }
    defer close(server_fd);

    _ = try send(client, "hello");
    var buf: [16]u8 = undefined;
    var got: usize = 0;
    while (got == 0) {
        got = recv(server_fd, &buf) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => return e,
        };
    }
    try testing.expectEqualStrings("hello", buf[0..got]);
}
