//! Per-connection state machine driven by the reactor, plus the user-facing
//! config and handler API, plus a per-worker connection pool.
//!
//! A connection lives entirely inside one worker thread, so nothing here needs
//! locking. Handlers run synchronously inside the reactor and must not block.

const std = @import("std");
const Allocator = std.mem.Allocator;
const socket = @import("socket.zig");
const poller = @import("poller.zig");
const http = @import("http.zig");
const websocket = @import("websocket.zig");

const Handle = socket.Handle;
const Interest = poller.Interest;

/// What a request handler decided to do.
pub const Action = enum {
    /// A normal HTTP response has been written into `res`.
    respond,
    /// Upgrade this connection to WebSocket (must be a valid upgrade request).
    upgrade,
};

pub const Config = struct {
    address: []const u8 = "0.0.0.0",
    port: u16 = 8080,
    /// Worker threads; 0 = one per CPU.
    threads: usize = 0,
    backlog: u31 = 128,
    /// Fixed per-connection read buffer. Caps request head + buffered body/frame.
    read_buffer_size: usize = 8 * 1024,
    max_body_size: usize = 1 << 20,
    max_ws_message_size: usize = 1 << 20,
    /// Retained free connections per worker before extra ones are freed.
    pool_capacity: usize = 256,

    /// Called once per fully-received request. Fill `res` and return `.respond`,
    /// or return `.upgrade` to switch to WebSocket.
    on_request: *const fn (req: *const http.Request, res: *http.Response, ud: ?*anyopaque) Action,
    on_ws_open: ?*const fn (conn: *Connection, ud: ?*anyopaque) void = null,
    on_ws_message: ?*const fn (conn: *Connection, msg: websocket.Message, ud: ?*anyopaque) void = null,
    on_ws_close: ?*const fn (conn: *Connection, ud: ?*anyopaque) void = null,
    user_data: ?*anyopaque = null,
};

pub const Connection = struct {
    fd: Handle,
    gpa: Allocator,
    cfg: *const Config,

    read_buf: []u8,
    read_len: usize = 0,
    write_buf: std.ArrayList(u8) = .empty,
    write_sent: usize = 0,

    req: http.Request = .{},
    res: http.Response,
    ws_asm: websocket.Assembler,

    proto: enum { http, ws } = .http,
    /// Currently registered epoll interest (avoids redundant epoll_ctl).
    registered: Interest = .{},
    /// Close immediately (fatal error / peer gone).
    should_close: bool = false,
    /// Close once the write buffer has fully drained.
    close_after_flush: bool = false,

    fn create(gpa: Allocator, cfg: *const Config) !*Connection {
        const self = try gpa.create(Connection);
        errdefer gpa.destroy(self);
        const buf = try gpa.alloc(u8, cfg.read_buffer_size);
        self.* = .{
            .fd = socket.invalid_handle,
            .gpa = gpa,
            .cfg = cfg,
            .read_buf = buf,
            .res = http.Response.init(gpa),
            .ws_asm = websocket.Assembler.init(gpa, cfg.max_ws_message_size),
        };
        return self;
    }

    fn destroy(self: *Connection) void {
        const gpa = self.gpa;
        self.write_buf.deinit(gpa);
        self.res.deinit();
        self.ws_asm.deinit();
        gpa.free(self.read_buf);
        gpa.destroy(self);
    }

    /// Prepare a pooled connection for a freshly accepted fd.
    fn rearm(self: *Connection, fd: Handle) void {
        self.fd = fd;
        self.read_len = 0;
        self.write_buf.clearRetainingCapacity();
        self.write_sent = 0;
        self.req.reset();
        self.res.reset();
        self.ws_asm.reset();
        self.proto = .http;
        self.registered = .{};
        self.should_close = false;
        self.close_after_flush = false;
    }

    pub fn desiredInterest(self: *const Connection) Interest {
        return .{ .read = true, .write = self.wantWrite() };
    }

    pub fn wantWrite(self: *const Connection) bool {
        return self.write_sent < self.write_buf.items.len;
    }

    // --- reactor entry points -------------------------------------------------

    /// Read all currently-available bytes, then process them.
    pub fn onReadable(self: *Connection) void {
        while (self.read_len < self.read_buf.len) {
            const n = socket.recv(self.fd, self.read_buf[self.read_len..]) catch |e| switch (e) {
                error.WouldBlock => break,
                else => {
                    self.should_close = true;
                    return;
                },
            };
            if (n == 0) {
                // Peer half-closed: process what we have, then close.
                self.close_after_flush = true;
                break;
            }
            self.read_len += n;
        }
        self.process();
    }

    /// Send as much of the write buffer as the socket accepts.
    pub fn flush(self: *Connection) void {
        while (self.write_sent < self.write_buf.items.len) {
            const n = socket.send(self.fd, self.write_buf.items[self.write_sent..]) catch |e| switch (e) {
                error.WouldBlock => return,
                else => {
                    self.should_close = true;
                    return;
                },
            };
            if (n == 0) {
                self.should_close = true;
                return;
            }
            self.write_sent += n;
        }
        self.write_buf.clearRetainingCapacity();
        self.write_sent = 0;
    }

    // --- processing -----------------------------------------------------------

    fn process(self: *Connection) void {
        switch (self.proto) {
            .http => self.processHttp(),
            .ws => self.processWs(),
        }
    }

    fn processHttp(self: *Connection) void {
        while (self.read_len > 0 and !self.should_close and !self.close_after_flush) {
            var head_len: usize = undefined;
            switch (http.parseHead(&self.req, self.read_buf[0..self.read_len])) {
                .need_more => {
                    if (self.read_len == self.read_buf.len)
                        self.sendError(.request_header_fields_too_large);
                    return;
                },
                .fail => |st| {
                    self.sendError(st);
                    return;
                },
                .done => |n| head_len = n,
            }

            var body: []const u8 = "";
            var total: usize = head_len;
            if (self.req.chunked) {
                const region = self.read_buf[head_len..self.read_len];
                switch (http.decodeChunked(region, region)) {
                    .need_more => {
                        if (self.read_len == self.read_buf.len) self.sendError(.payload_too_large);
                        return;
                    },
                    .fail => |st| {
                        self.sendError(st);
                        return;
                    },
                    .done => |d| {
                        body = region[0..d.body_len];
                        total = head_len + d.consumed;
                    },
                }
            } else if (self.req.content_length) |cl| {
                if (cl > self.cfg.max_body_size) {
                    self.sendError(.payload_too_large);
                    return;
                }
                const need = head_len + @as(usize, @intCast(cl));
                if (self.read_len < need) {
                    if (self.read_len == self.read_buf.len) self.sendError(.payload_too_large);
                    return;
                }
                body = self.read_buf[head_len..need];
                total = need;
            }
            self.req.body = body;

            self.dispatch();
            self.consume(total);

            if (self.proto == .ws) {
                // Any bytes after the handshake are WebSocket frames.
                self.processWs();
                return;
            }
            if (self.should_close or self.close_after_flush or !self.req.keep_alive) {
                self.close_after_flush = true;
                return;
            }
            self.req.reset();
        }
    }

    fn dispatch(self: *Connection) void {
        self.res.reset();
        const action = self.cfg.on_request(&self.req, &self.res, self.cfg.user_data);
        switch (action) {
            .respond => {
                const keep_alive = self.req.keep_alive and !self.should_close;
                self.res.serialize(&self.write_buf, self.gpa, keep_alive) catch {
                    self.should_close = true;
                };
            },
            .upgrade => self.tryUpgrade(),
        }
    }

    fn tryUpgrade(self: *Connection) void {
        switch (websocket.checkUpgrade(&self.req)) {
            .yes => |key| {
                websocket.writeAccept(&self.write_buf, self.gpa, key) catch {
                    self.should_close = true;
                    return;
                };
                self.proto = .ws;
                self.ws_asm.reset();
                if (self.cfg.on_ws_open) |cb| cb(self, self.cfg.user_data);
            },
            .version_mismatch => {
                self.res.reset();
                self.res.status = .upgrade_required;
                self.res.setHeader("Sec-WebSocket-Version", "13") catch {};
                self.res.serialize(&self.write_buf, self.gpa, false) catch {};
                self.close_after_flush = true;
            },
            .no => self.sendError(.bad_request),
        }
    }

    fn processWs(self: *Connection) void {
        while (self.read_len > 0 and !self.should_close and !self.close_after_flush) {
            switch (websocket.parseFrame(self.read_buf[0..self.read_len], true)) {
                .need_more => {
                    if (self.read_len == self.read_buf.len) self.wsClose(.message_too_big, "");
                    return;
                },
                .fail => |code| {
                    self.wsClose(code, "");
                    return;
                },
                .done => |d| {
                    self.handleFrame(d.frame);
                    self.consume(d.consumed);
                },
            }
        }
    }

    fn handleFrame(self: *Connection, frame: websocket.Frame) void {
        if (frame.opcode.isControl()) {
            switch (frame.opcode) {
                .ping => websocket.writePong(&self.write_buf, self.gpa, frame.payload) catch {
                    self.should_close = true;
                },
                .pong => {},
                .close => {
                    websocket.writeClose(&self.write_buf, self.gpa, .normal, "") catch {};
                    self.close_after_flush = true;
                    if (self.cfg.on_ws_close) |cb| cb(self, self.cfg.user_data);
                },
                else => {},
            }
            return;
        }
        switch (self.ws_asm.push(frame)) {
            .incomplete => {},
            .fail => |code| self.wsClose(code, ""),
            .message => |msg| {
                if (self.cfg.on_ws_message) |cb| cb(self, msg, self.cfg.user_data);
            },
        }
    }

    /// Drop `n` consumed bytes off the front of the read buffer.
    fn consume(self: *Connection, n: usize) void {
        const remaining = self.read_len - n;
        if (remaining > 0)
            std.mem.copyForwards(u8, self.read_buf[0..remaining], self.read_buf[n..self.read_len]);
        self.read_len = remaining;
    }

    fn sendError(self: *Connection, status: http.Status) void {
        self.res.reset();
        self.res.status = status;
        self.res.serialize(&self.write_buf, self.gpa, false) catch {
            self.should_close = true;
            return;
        };
        self.close_after_flush = true;
    }

    // --- public WebSocket API (call from handlers) ----------------------------

    pub fn sendText(self: *Connection, data: []const u8) !void {
        try websocket.writeFrame(&self.write_buf, self.gpa, .text, data, true);
    }

    pub fn sendBinary(self: *Connection, data: []const u8) !void {
        try websocket.writeFrame(&self.write_buf, self.gpa, .binary, data, true);
    }

    pub fn wsClose(self: *Connection, code: websocket.CloseCode, reason: []const u8) void {
        websocket.writeClose(&self.write_buf, self.gpa, code, reason) catch {};
        self.close_after_flush = true;
    }
};

/// Per-worker connection pool (free list). No locking — one per thread.
pub const Pool = struct {
    gpa: Allocator,
    cfg: *const Config,
    free: std.ArrayList(*Connection) = .empty,

    pub fn init(gpa: Allocator, cfg: *const Config) Pool {
        return .{ .gpa = gpa, .cfg = cfg };
    }

    pub fn deinit(self: *Pool) void {
        for (self.free.items) |c| c.destroy();
        self.free.deinit(self.gpa);
    }

    pub fn acquire(self: *Pool, fd: Handle) !*Connection {
        const conn = if (self.free.pop()) |c| c else try Connection.create(self.gpa, self.cfg);
        conn.rearm(fd);
        return conn;
    }

    pub fn release(self: *Pool, conn: *Connection) void {
        if (self.free.items.len < self.cfg.pool_capacity) {
            self.free.append(self.gpa, conn) catch conn.destroy();
        } else {
            conn.destroy();
        }
    }
};

// ===========================================================================
// Tests — drive a connection over a real socketpair, no threads.
// ===========================================================================

const testing = std.testing;

fn tSetNonBlock(fd: i32) void {
    const flags: u32 = @bitCast(std.os.linux.O{ .NONBLOCK = true });
    _ = std.os.linux.fcntl(fd, std.os.linux.F.SETFL, flags);
}

/// A blocking client fd + a non-blocking "server" fd, connected. The server
/// side must be non-blocking so `onReadable`'s drain loop terminates.
fn tPair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.SocketPair;
    tSetNonBlock(fds[0]);
    return fds;
}

fn helloHandler(req: *const http.Request, res: *http.Response, ud: ?*anyopaque) Action {
    _ = ud;
    res.status = .ok;
    res.setHeader("Content-Type", "text/plain") catch {};
    res.print("path={s}", .{req.path}) catch {};
    return .respond;
}

fn echoWsHandler(req: *const http.Request, res: *http.Response, ud: ?*anyopaque) Action {
    _ = req;
    _ = res;
    _ = ud;
    return .upgrade;
}

fn echoWsMessage(conn: *Connection, msg: websocket.Message, ud: ?*anyopaque) void {
    _ = ud;
    conn.sendText(msg.data) catch {};
}

test "http request/response over socketpair" {
    var cfg: Config = .{ .on_request = helloHandler };
    var pool = Pool.init(testing.allocator, &cfg);
    defer pool.deinit();

    const fds = try tPair();
    defer socket.close(fds[1]);

    const conn = try pool.acquire(fds[0]);
    defer {
        socket.close(conn.fd);
        pool.release(conn);
    }

    // Client writes a request.
    const request = "GET /abc HTTP/1.1\r\nHost: x\r\n\r\n";
    _ = try socket.send(fds[1], request);

    conn.onReadable();
    conn.flush();

    var buf: [512]u8 = undefined;
    const got = try socket.recv(fds[1], &buf);
    try testing.expect(std.mem.startsWith(u8, buf[0..got], "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, buf[0..got], "path=/abc") != null);
    try testing.expect(std.mem.indexOf(u8, buf[0..got], "Connection: keep-alive") != null);
    try testing.expect(!conn.close_after_flush); // keep-alive stays open
}

test "keep-alive: two requests on one connection" {
    var cfg: Config = .{ .on_request = helloHandler };
    var pool = Pool.init(testing.allocator, &cfg);
    defer pool.deinit();

    const fds = try tPair();
    defer socket.close(fds[1]);
    const conn = try pool.acquire(fds[0]);
    defer {
        socket.close(conn.fd);
        pool.release(conn);
    }

    _ = try socket.send(fds[1], "GET /one HTTP/1.1\r\n\r\n");
    conn.onReadable();
    conn.flush();
    var buf: [512]u8 = undefined;
    var got = try socket.recv(fds[1], &buf);
    try testing.expect(std.mem.indexOf(u8, buf[0..got], "path=/one") != null);

    _ = try socket.send(fds[1], "GET /two HTTP/1.1\r\n\r\n");
    conn.onReadable();
    conn.flush();
    got = try socket.recv(fds[1], &buf);
    try testing.expect(std.mem.indexOf(u8, buf[0..got], "path=/two") != null);
}

test "malformed request -> 400 and close" {
    var cfg: Config = .{ .on_request = helloHandler };
    var pool = Pool.init(testing.allocator, &cfg);
    defer pool.deinit();

    const fds = try tPair();
    defer socket.close(fds[1]);
    const conn = try pool.acquire(fds[0]);
    defer {
        socket.close(conn.fd);
        pool.release(conn);
    }

    _ = try socket.send(fds[1], "GET / HTTP/2.0\r\n\r\n");
    conn.onReadable();
    conn.flush();
    var buf: [512]u8 = undefined;
    const got = try socket.recv(fds[1], &buf);
    try testing.expect(std.mem.startsWith(u8, buf[0..got], "HTTP/1.1 505"));
    try testing.expect(conn.close_after_flush);
}

test "websocket upgrade + echo over socketpair" {
    var cfg: Config = .{
        .on_request = echoWsHandler,
        .on_ws_message = echoWsMessage,
    };
    var pool = Pool.init(testing.allocator, &cfg);
    defer pool.deinit();

    const fds = try tPair();
    defer socket.close(fds[1]);
    const conn = try pool.acquire(fds[0]);
    defer {
        socket.close(conn.fd);
        pool.release(conn);
    }

    const handshake = "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    _ = try socket.send(fds[1], handshake);
    conn.onReadable();
    conn.flush();

    var buf: [512]u8 = undefined;
    var got = try socket.recv(fds[1], &buf);
    try testing.expect(std.mem.startsWith(u8, buf[0..got], "HTTP/1.1 101"));
    try testing.expect(std.mem.indexOf(u8, buf[0..got], "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);
    try testing.expectEqual(@as(@TypeOf(conn.proto), .ws), conn.proto);

    // Client sends a masked text frame "Hi".
    var frame = [_]u8{ 0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'H' ^ 0x01, 'i' ^ 0x02 };
    _ = try socket.send(fds[1], &frame);
    conn.onReadable();
    conn.flush();

    got = try socket.recv(fds[1], &buf);
    // Server echoes unmasked text frame "Hi".
    try testing.expectEqual(@as(u8, 0x81), buf[0]);
    try testing.expectEqual(@as(u8, 2), buf[1]);
    try testing.expectEqualStrings("Hi", buf[2..got]);
}
