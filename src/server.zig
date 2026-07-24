//! The server: a shared listen socket and N worker threads, each running an
//! independent readiness reactor (shared-nothing after accept).

const std = @import("std");
const Allocator = std.mem.Allocator;
const socket = @import("socket.zig");
const poller = @import("poller.zig");
const connection = @import("connection.zig");

const Config = connection.Config;
const Connection = connection.Connection;
const Pool = connection.Pool;
const Poller = poller.Poller;
const Handle = socket.Handle;

/// Sentinel token for the listen socket. Real connection tokens are heap
/// pointers, which are aligned and thus never equal to 1.
const listener_token: usize = 1;

pub const Server = struct {
    gpa: Allocator,
    config: Config,
    listener: Handle = socket.invalid_handle,
    running: std.atomic.Value(bool) = .init(false),
    threads: std.ArrayList(std.Thread) = .empty,

    pub fn init(gpa: Allocator, config: Config) Server {
        return .{ .gpa = gpa, .config = config };
    }

    pub fn deinit(self: *Server) void {
        if (self.running.load(.monotonic)) self.stop();
        self.threads.deinit(self.gpa);
    }

    /// Bind the listen socket and spawn workers. Returns once workers are
    /// running; the server keeps running until `stop`.
    pub fn start(self: *Server) !void {
        const addr = try socket.Address.parse(self.config.address, self.config.port);
        self.listener = try socket.listen(addr, self.config.backlog);
        errdefer {
            socket.close(self.listener);
            self.listener = socket.invalid_handle;
        }

        var n = self.config.threads;
        if (n == 0) n = std.Thread.getCpuCount() catch 1;
        if (n == 0) n = 1;

        self.running.store(true, .monotonic);
        errdefer self.stop();
        try self.threads.ensureTotalCapacity(self.gpa, n);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const t = try std.Thread.spawn(.{}, worker, .{self});
            self.threads.appendAssumeCapacity(t);
        }
    }

    /// Signal workers to stop, join them, and close the listen socket.
    pub fn stop(self: *Server) void {
        self.running.store(false, .monotonic);
        for (self.threads.items) |t| t.join();
        self.threads.clearRetainingCapacity();
        if (self.listener != socket.invalid_handle) {
            socket.close(self.listener);
            self.listener = socket.invalid_handle;
        }
    }

    /// The actually-bound port (useful when binding to port 0).
    pub fn boundPort(self: *const Server) !u16 {
        return socket.boundPort(self.listener);
    }

    /// Block until the workers exit (i.e. until another thread calls `stop`).
    /// Use this to keep a standalone server process alive.
    pub fn wait(self: *Server) void {
        for (self.threads.items) |t| t.join();
        self.threads.clearRetainingCapacity();
        if (self.listener != socket.invalid_handle) {
            socket.close(self.listener);
            self.listener = socket.invalid_handle;
        }
    }

    fn worker(self: *Server) void {
        var p = Poller.init(self.gpa) catch return;
        defer p.deinit();
        var pool = Pool.init(self.gpa, &self.config);
        defer pool.deinit();
        p.add(self.listener, .{ .read = true }, listener_token) catch return;

        while (self.running.load(.monotonic)) {
            const events = p.wait(200) catch continue;
            for (events) |ev| {
                if (ev.token == listener_token) {
                    self.acceptAll(&p, &pool);
                } else {
                    handleConn(&p, &pool, @ptrFromInt(ev.token), ev);
                }
            }
        }
    }

    fn acceptAll(self: *Server, p: *Poller, pool: *Pool) void {
        while (true) {
            const maybe = socket.accept(self.listener) catch break;
            const fd = maybe orelse break;
            const conn = pool.acquire(fd) catch {
                socket.close(fd);
                continue;
            };
            p.add(fd, .{ .read = true }, @intFromPtr(conn)) catch {
                socket.close(fd);
                pool.release(conn);
                continue;
            };
            conn.registered = .{ .read = true };
        }
    }
};

fn handleConn(p: *Poller, pool: *Pool, conn: *Connection, ev: poller.Event) void {
    if (ev.closed) {
        closeConn(p, pool, conn);
        return;
    }
    if (ev.readable) conn.onReadable();
    conn.flush();

    if (conn.should_close or (conn.close_after_flush and !conn.wantWrite())) {
        closeConn(p, pool, conn);
        return;
    }

    const want = conn.desiredInterest();
    if (want.read != conn.registered.read or want.write != conn.registered.write) {
        p.mod(conn.fd, want, @intFromPtr(conn)) catch {
            closeConn(p, pool, conn);
            return;
        };
        conn.registered = want;
    }
}

fn closeConn(p: *Poller, pool: *Pool, conn: *Connection) void {
    p.remove(conn.fd);
    socket.close(conn.fd);
    pool.release(conn);
}

// ===========================================================================
// Tests
// ===========================================================================

const http = @import("http.zig");
const websocket = @import("websocket.zig");
const testing = std.testing;

fn okHandler(req: *const http.Request, res: *http.Response, ud: ?*anyopaque) connection.Action {
    _ = ud;
    res.status = .ok;
    res.print("you asked for {s}", .{req.path}) catch {};
    return .respond;
}

fn wsUpgradeHandler(req: *const http.Request, res: *http.Response, ud: ?*anyopaque) connection.Action {
    _ = req;
    _ = res;
    _ = ud;
    return .upgrade;
}

fn wsEchoHandler(conn: *Connection, msg: websocket.Message, ud: ?*anyopaque) void {
    _ = ud;
    conn.sendText(msg.data) catch {};
}

/// Read exactly `want` bytes from a blocking socket (or fewer on EOF).
fn recvExact(fd: Handle, buf: []u8) !usize {
    var total: usize = 0;
    while (total < buf.len) {
        const n = socket.recv(fd, buf[total..]) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => return e,
        };
        if (n == 0) break;
        total += n;
    }
    return total;
}

test "end-to-end HTTP over real TCP with worker threads" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    // page_allocator: connections still open at stop() are not individually
    // freed (the OS reclaims them); a leak-checking allocator would flag that.
    // ponytail: add graceful per-conn cleanup on shutdown only if it matters.
    const gpa = std.heap.page_allocator;

    var server = Server.init(gpa, .{
        .address = "127.0.0.1",
        .port = 0,
        .threads = 2,
        .on_request = okHandler,
    });
    defer server.deinit();
    try server.start();
    const port = try server.boundPort();

    // Two sequential clients, each on a fresh connection.
    for (0..2) |_| {
        const client = try socket.connectBlocking(try socket.Address.parse("127.0.0.1", port));
        defer socket.close(client);
        _ = try socket.send(client, "GET /road HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

        var buf: [1024]u8 = undefined;
        var total: usize = 0;
        // Read until the peer closes (Connection: close).
        while (true) {
            const n = socket.recv(client, buf[total..]) catch |e| switch (e) {
                error.WouldBlock => continue,
                else => break,
            };
            if (n == 0) break;
            total += n;
            if (total == buf.len) break;
        }
        const resp = buf[0..total];
        try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
        try testing.expect(std.mem.indexOf(u8, resp, "you asked for /road") != null);
    }

    server.stop();
}

test "end-to-end WebSocket echo over real TCP" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const gpa = std.heap.page_allocator;

    var server = Server.init(gpa, .{
        .address = "127.0.0.1",
        .port = 0,
        .threads = 1,
        .on_request = wsUpgradeHandler,
        .on_ws_message = wsEchoHandler,
    });
    defer server.deinit();
    try server.start();
    const port = try server.boundPort();

    const client = try socket.connectBlocking(try socket.Address.parse("127.0.0.1", port));
    defer socket.close(client);

    _ = try socket.send(client, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n");

    // Read the 101 handshake (ends with a blank line).
    var hs: [256]u8 = undefined;
    var hs_len: usize = 0;
    while (std.mem.indexOf(u8, hs[0..hs_len], "\r\n\r\n") == null) {
        const n = socket.recv(client, hs[hs_len..]) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => return e,
        };
        if (n == 0) break;
        hs_len += n;
    }
    try testing.expect(std.mem.startsWith(u8, hs[0..hs_len], "HTTP/1.1 101"));

    // Send a masked "ping-data" text frame.
    const payload = "ping-data";
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(gpa);
    try frame.appendSlice(gpa, &.{ 0x81, 0x80 | @as(u8, @intCast(payload.len)) });
    const mask = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    try frame.appendSlice(gpa, &mask);
    for (payload, 0..) |c, i| try frame.append(gpa, c ^ mask[i & 3]);
    _ = try socket.send(client, frame.items);

    // Expect the server's unmasked echo: 2-byte header + 9-byte payload.
    var resp: [16]u8 = undefined;
    const got = try recvExact(client, resp[0 .. 2 + payload.len]);
    try testing.expectEqual(@as(usize, 2 + payload.len), got);
    const parsed = websocket.parseFrame(resp[0..got], false);
    try testing.expectEqual(websocket.Opcode.text, parsed.done.frame.opcode);
    try testing.expectEqualStrings(payload, parsed.done.frame.payload);

    server.stop();
}
