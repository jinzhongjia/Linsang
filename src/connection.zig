//! Straight-line HTTP/WebSocket connection handling on `std.Io.net`.

const std = @import("std");
const http = @import("http.zig");
const websocket = @import("websocket.zig");

const Allocator = std.mem.Allocator;
const Stream = std.Io.net.Stream;

pub const Action = enum { respond, upgrade };

pub const Config = struct {
    address: []const u8 = "0.0.0.0",
    port: u16 = 8080,
    backlog: u31 = 128,
    max_connections: usize = 128,
    /// Maximum request-head size and initial per-connection allocation.
    read_buffer_size: usize = 8 * 1024,
    max_body_size: usize = 1 << 20,
    max_ws_message_size: usize = 1 << 20,
    /// Overall deadline for one HTTP request, preventing slowloris clients.
    request_timeout: ?std.Io.Duration = .fromSeconds(15),
    /// How long an idle HTTP keep-alive connection waits for its next request.
    keep_alive_timeout: ?std.Io.Duration = .fromSeconds(60),
    /// Maximum time allowed to flush one HTTP response or WebSocket frame.
    write_timeout: ?std.Io.Duration = .fromSeconds(30),

    on_request: *const fn (*const http.Request, *http.Response, ?*anyopaque) Action,
    on_ws_open: ?*const fn (*Connection, ?*anyopaque) void = null,
    on_ws_message: ?*const fn (*Connection, websocket.Message, ?*anyopaque) void = null,
    on_ws_close: ?*const fn (*Connection, ?*anyopaque) void = null,
    user_data: ?*anyopaque = null,
};

pub const Connection = struct {
    io: std.Io,
    stream: Stream,
    gpa: Allocator,
    cfg: *const Config,
    read_buf: []u8,
    read_len: usize = 0,
    write_buf: std.ArrayList(u8) = .empty,
    req: http.Request = .{},
    res: http.Response,
    ws_asm: websocket.Assembler,
    requests_served: usize = 0,
    closing: bool = false,
    close_notified: bool = false,

    fn init(io: std.Io, stream: Stream, gpa: Allocator, cfg: *const Config) !Connection {
        if (cfg.read_buffer_size < 4) return error.InvalidConfiguration;
        return .{
            .io = io,
            .stream = stream,
            .gpa = gpa,
            .cfg = cfg,
            .read_buf = try gpa.alloc(u8, cfg.read_buffer_size),
            .res = http.Response.init(gpa),
            .ws_asm = websocket.Assembler.init(gpa, cfg.max_ws_message_size),
        };
    }

    fn deinit(self: *Connection) void {
        self.ws_asm.deinit();
        self.res.deinit();
        self.write_buf.deinit(self.gpa);
        self.gpa.free(self.read_buf);
    }

    fn run(self: *Connection) !void {
        while (true) switch (try self.readRequest()) {
            .eof => return,
            .timeout => {
                try self.sendError(.request_timeout);
                return;
            },
            .fail => |status| {
                try self.sendError(status);
                return;
            },
            .ready => |consumed| {
                self.res.reset();
                switch (self.cfg.on_request(&self.req, &self.res, self.cfg.user_data)) {
                    .respond => {
                        const keep_alive = self.req.keep_alive;
                        if (self.req.method == .HEAD)
                            try self.res.serializeHead(&self.write_buf, self.gpa, keep_alive)
                        else
                            try self.res.serialize(&self.write_buf, self.gpa, keep_alive);
                        self.consume(consumed);
                        try self.flush();
                        self.requests_served += 1;
                        if (!keep_alive) return;
                    },
                    .upgrade => {
                        if (!try self.upgrade(consumed)) return;
                        return self.runWebSocket();
                    },
                }
            },
        };
    }

    const ReadResult = union(enum) {
        eof,
        timeout,
        ready: usize,
        fail: http.Status,
    };

    fn readRequest(self: *Connection) !ReadResult {
        self.req.reset();
        if (self.requests_served > 0 and self.read_len == 0) {
            const more = self.readMore(
                self.cfg.read_buffer_size,
                durationTimeout(self.cfg.keep_alive_timeout),
            ) catch |err| switch (err) {
                error.Timeout => return .eof,
                else => return err,
            };
            if (!more) return .eof;
        }
        const request_deadline =
            durationTimeout(self.cfg.request_timeout).toDeadline(self.io);
        const head_len = while (true) switch (http.parseHead(&self.req, self.read_buf[0..self.read_len])) {
            .done => |n| break n,
            .fail => |status| return .{ .fail = status },
            .need_more => {
                if (self.read_len >= self.cfg.read_buffer_size)
                    return .{ .fail = .request_header_fields_too_large };
                const more = self.readMore(
                    self.cfg.read_buffer_size,
                    request_deadline,
                ) catch |err| switch (err) {
                    error.Timeout => return .timeout,
                    else => return err,
                };
                if (!more)
                    return if (self.read_len == 0) .eof else .{ .fail = .bad_request };
            },
        };
        if (head_len > self.cfg.read_buffer_size)
            return .{ .fail = .request_header_fields_too_large };

        if (self.req.content_length) |content_length| {
            if (content_length > self.cfg.max_body_size or content_length > std.math.maxInt(usize))
                return .{ .fail = .payload_too_large };
        }
        if (self.req.expect_continue and
            (self.req.chunked or (self.req.content_length orelse 0) > 0))
        {
            try self.write_buf.appendSlice(self.gpa, "HTTP/1.1 100 Continue\r\n\r\n");
            try self.flush();
        }

        var consumed = head_len;
        if (self.req.content_length) |content_length| {
            const body_len: usize = @intCast(content_length);
            const needed = std.math.add(usize, head_len, body_len) catch
                return .{ .fail = .payload_too_large };
            try self.ensureCapacity(needed, self.httpBufferLimit());
            while (self.read_len < needed) {
                const more = self.readMore(needed, request_deadline) catch |err| switch (err) {
                    error.Timeout => return .timeout,
                    else => return err,
                };
                if (!more) return .{ .fail = .bad_request };
            }
            self.req.body = self.read_buf[head_len..needed];
            consumed = needed;
        } else if (self.req.chunked) {
            var decoded: std.ArrayList(u8) = .empty;
            defer decoded.deinit(self.gpa);
            while (true) {
                const raw = self.read_buf[head_len..self.read_len];
                try decoded.resize(self.gpa, raw.len);
                switch (http.decodeChunked(raw, decoded.items)) {
                    .done => |done| {
                        if (done.body_len > self.cfg.max_body_size)
                            return .{ .fail = .payload_too_large };
                        @memcpy(self.read_buf[head_len..][0..done.body_len], decoded.items[0..done.body_len]);
                        self.req.body = self.read_buf[head_len..][0..done.body_len];
                        consumed = head_len + done.consumed;
                        break;
                    },
                    .fail => |status| return .{ .fail = status },
                    .need_more => {
                        const limit = self.httpBufferLimit();
                        if (self.read_len == limit) return .{ .fail = .payload_too_large };
                        try self.grow(limit);
                        const more = self.readMore(limit, request_deadline) catch |err| switch (err) {
                            error.Timeout => return .timeout,
                            else => return err,
                        };
                        if (!more) return .{ .fail = .bad_request };
                    },
                }
            }
        }
        return .{ .ready = consumed };
    }

    fn upgrade(self: *Connection, consumed: usize) !bool {
        switch (websocket.checkUpgrade(&self.req)) {
            .yes => |key| {
                try websocket.writeAccept(&self.write_buf, self.gpa, key);
                self.consume(consumed);
                self.ws_asm.reset();
                if (self.cfg.on_ws_open) |callback| callback(self, self.cfg.user_data);
                try self.flush();
                return true;
            },
            .version_mismatch => {
                self.res.status = .upgrade_required;
                try self.res.setHeader("Sec-WebSocket-Version", "13");
                try self.res.serialize(&self.write_buf, self.gpa, false);
                try self.flush();
                return false;
            },
            .no => {
                try self.sendError(.bad_request);
                return false;
            },
        }
    }

    fn runWebSocket(self: *Connection) !void {
        defer self.notifyClose();
        while (!self.closing) {
            switch (websocket.parseFrame(self.read_buf[0..self.read_len], true)) {
                .done => |done| {
                    self.handleFrame(done.frame);
                    self.consume(done.consumed);
                    try self.flush();
                },
                .fail => |code| {
                    self.wsClose(code, "");
                    try self.flush();
                },
                .need_more => {
                    const limit = self.wsBufferLimit();
                    if (self.read_len == limit) {
                        self.wsClose(.message_too_big, "");
                        try self.flush();
                        return;
                    }
                    try self.grow(limit);
                    if (!try self.readMore(limit, .none)) return;
                },
            }
        }
    }

    fn handleFrame(self: *Connection, frame: websocket.Frame) void {
        if (frame.opcode.isControl()) {
            switch (frame.opcode) {
                .ping => websocket.writePong(&self.write_buf, self.gpa, frame.payload) catch
                    self.wsClose(.internal_error, ""),
                .pong => {},
                .close => {
                    if (closePayloadError(frame.payload)) |code| {
                        self.wsClose(code, "");
                        return;
                    }
                    websocket.writeFrame(
                        &self.write_buf,
                        self.gpa,
                        .close,
                        frame.payload,
                        true,
                    ) catch {
                        self.wsClose(.internal_error, "");
                        return;
                    };
                    self.closing = true;
                },
                else => unreachable,
            }
            return;
        }
        switch (self.ws_asm.push(frame)) {
            .incomplete => {},
            .fail => |code| self.wsClose(code, ""),
            .message => |message| {
                if (message.opcode == .text and !std.unicode.utf8ValidateSlice(message.data)) {
                    self.wsClose(.invalid_payload, "");
                    return;
                }
                if (self.cfg.on_ws_message) |callback|
                    callback(self, message, self.cfg.user_data);
            },
        }
    }

    fn readMore(self: *Connection, limit: usize, timeout: std.Io.Timeout) !bool {
        const end = @min(limit, self.read_buf.len);
        std.debug.assert(self.read_len < end);
        const n = try timedRead(
            self.io,
            self.stream.socket.handle,
            self.read_buf[self.read_len..end],
            timeout,
        );
        self.read_len += n;
        return n != 0;
    }

    fn ensureCapacity(self: *Connection, needed: usize, limit: usize) !void {
        if (needed > limit) return error.RequestTooLarge;
        if (needed > self.read_buf.len)
            self.read_buf = try self.gpa.realloc(self.read_buf, needed);
    }

    fn grow(self: *Connection, limit: usize) !void {
        if (self.read_buf.len >= limit) return;
        const doubled = std.math.mul(usize, self.read_buf.len, 2) catch limit;
        self.read_buf = try self.gpa.realloc(self.read_buf, @min(doubled, limit));
    }

    fn httpBufferLimit(self: *const Connection) usize {
        return std.math.add(
            usize,
            self.cfg.read_buffer_size,
            self.cfg.max_body_size,
        ) catch std.math.maxInt(usize);
    }

    fn wsBufferLimit(self: *const Connection) usize {
        const frame_limit = std.math.add(usize, self.cfg.max_ws_message_size, 14) catch
            std.math.maxInt(usize);
        return @max(self.cfg.read_buffer_size, frame_limit);
    }

    fn flush(self: *Connection) !void {
        if (self.write_buf.items.len == 0) return;
        try timedWrite(
            self.io,
            self.stream,
            self.write_buf.items,
            durationTimeout(self.cfg.write_timeout),
        );
        self.write_buf.clearRetainingCapacity();
    }

    fn consume(self: *Connection, n: usize) void {
        const remaining = self.read_len - n;
        std.mem.copyForwards(u8, self.read_buf[0..remaining], self.read_buf[n..self.read_len]);
        self.read_len = remaining;
    }

    fn sendError(self: *Connection, status: http.Status) !void {
        self.res.reset();
        self.res.status = status;
        try self.res.serialize(&self.write_buf, self.gpa, false);
        try self.flush();
    }

    fn notifyClose(self: *Connection) void {
        if (self.close_notified) return;
        self.close_notified = true;
        if (self.cfg.on_ws_close) |callback| callback(self, self.cfg.user_data);
    }

    pub fn sendText(self: *Connection, data: []const u8) !void {
        try websocket.writeText(&self.write_buf, self.gpa, data);
    }

    pub fn sendBinary(self: *Connection, data: []const u8) !void {
        try websocket.writeFrame(&self.write_buf, self.gpa, .binary, data, true);
    }

    pub fn wsClose(self: *Connection, code: websocket.CloseCode, reason: []const u8) void {
        websocket.writeClose(&self.write_buf, self.gpa, code, reason) catch {};
        self.closing = true;
    }
};

fn closePayloadError(payload: []const u8) ?websocket.CloseCode {
    if (payload.len == 0) return null;
    if (payload.len == 1) return .protocol_error;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (!validCloseCode(code)) return .protocol_error;
    if (!std.unicode.utf8ValidateSlice(payload[2..])) return .invalid_payload;
    return null;
}

fn validCloseCode(code: u16) bool {
    return switch (code) {
        1000...1003, 1007...1014, 3000...4999 => true,
        else => false,
    };
}

fn durationTimeout(duration: ?std.Io.Duration) std.Io.Timeout {
    return if (duration) |value| .{ .duration = .{
        .clock = .awake,
        .raw = value,
    } } else .none;
}

const ReadRace = union(enum) {
    io: anyerror!usize,
    timeout: std.Io.Cancelable!void,
};

fn timedRead(
    io: std.Io,
    socket_handle: std.Io.net.Socket.Handle,
    buffer: []u8,
    timeout: std.Io.Timeout,
) !usize {
    if (timeout == .none) return rawRead(io, socket_handle, buffer);
    var results: [2]ReadRace = undefined;
    var select = std.Io.Select(ReadRace).init(io, &results);
    select.async(.io, rawRead, .{ io, socket_handle, buffer });
    select.async(.timeout, waitTimeout, .{ io, timeout });
    defer select.cancelDiscard();
    return switch (try select.await()) {
        .io => |result| try result,
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    };
}

fn rawRead(io: std.Io, socket_handle: std.Io.net.Socket.Handle, buffer: []u8) !usize {
    var buffers = [1][]u8{buffer};
    return io.vtable.netRead(io.userdata, socket_handle, &buffers);
}

const WriteRace = union(enum) {
    io: anyerror!void,
    timeout: std.Io.Cancelable!void,
};

fn timedWrite(
    io: std.Io,
    stream: Stream,
    bytes: []const u8,
    timeout: std.Io.Timeout,
) !void {
    if (timeout == .none) return rawWrite(io, stream, bytes);
    var results: [2]WriteRace = undefined;
    var select = std.Io.Select(WriteRace).init(io, &results);
    select.async(.io, rawWrite, .{ io, stream, bytes });
    select.async(.timeout, waitTimeout, .{ io, timeout });
    defer select.cancelDiscard();
    switch (try select.await()) {
        .io => |result| try result,
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    }
}

fn rawWrite(io: std.Io, stream: Stream, bytes: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn waitTimeout(io: std.Io, timeout: std.Io.Timeout) std.Io.Cancelable!void {
    try timeout.sleep(io);
}

pub fn handle(io: std.Io, stream: Stream, gpa: Allocator, cfg: *const Config) !void {
    defer stream.close(io);
    var connection = try Connection.init(io, stream, gpa, cfg);
    defer connection.deinit();
    try connection.run();
}

// The decoder writes in place, so partial chunked input needs a scratch output.
// ponytail: replace it with a stateful decoder only if chunked-body memory matters.

const testing = std.testing;

fn helloHandler(req: *const http.Request, res: *http.Response, _: ?*anyopaque) Action {
    res.print("path={s}", .{req.path}) catch {};
    return .respond;
}

fn bodyHandler(req: *const http.Request, res: *http.Response, _: ?*anyopaque) Action {
    res.write(req.body) catch {};
    return .respond;
}

fn upgradeHandler(_: *const http.Request, _: *http.Response, _: ?*anyopaque) Action {
    return .upgrade;
}

fn echoHandler(conn: *Connection, message: websocket.Message, _: ?*anyopaque) void {
    conn.sendText(message.data) catch {};
}

fn runTestConnection(io: std.Io, stream: Stream, cfg: *const Config) std.Io.Cancelable!void {
    handle(io, stream, testing.allocator, cfg) catch |err| {
        if (err == error.Canceled) return error.Canceled;
    };
}

fn writeTest(stream: Stream, io: std.Io, bytes: []const u8) !void {
    var buffer: [256]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn readUntil(stream: Stream, io: std.Io, buffer: []u8, needle: []const u8) ![]u8 {
    var len: usize = 0;
    while (std.mem.indexOf(u8, buffer[0..len], needle) == null) {
        var parts = [1][]u8{buffer[len..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &parts);
        if (n == 0) break;
        len += n;
    }
    return buffer[0..len];
}

fn readExact(stream: Stream, io: std.Io, buffer: []u8) !void {
    var len: usize = 0;
    while (len < buffer.len) {
        var parts = [1][]u8{buffer[len..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &parts);
        if (n == 0) return error.EndOfStream;
        len += n;
    }
}

fn tcpPair(io: std.Io) ![2]Stream {
    const bind_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind_address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const peer_address: std.Io.net.IpAddress = .{
        .ip4 = .loopback(listener.socket.address.getPort()),
    };
    const client = try peer_address.connect(io, .{ .mode = .stream });
    errdefer client.close(io);
    return .{ client, try listener.accept(io) };
}

test "HTTP keep-alive and parse error over std.Io.net" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try tcpPair(io);
    const client = streams[0];
    defer client.close(io);
    const server = streams[1];
    var cfg: Config = .{ .on_request = helloHandler };
    var group: std.Io.Group = .init;
    group.async(io, runTestConnection, .{ io, server, &cfg });

    try writeTest(client, io, "GET /one HTTP/1.1\r\nHost: x\r\n\r\n");
    var response: [512]u8 = undefined;
    const first = try readUntil(client, io, &response, "path=/one");
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, first, "Connection: keep-alive") != null);

    try writeTest(client, io, "GET / HTTP/2.0\r\n\r\n");
    const second = try readUntil(client, io, &response, "Connection: close\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 505"));
    try group.await(io);
}

test "chunked body may arrive in pieces" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try tcpPair(io);
    const client = streams[0];
    defer client.close(io);
    const server = streams[1];
    var cfg: Config = .{
        .read_buffer_size = 128,
        .max_body_size = 32,
        .on_request = bodyHandler,
    };
    var group: std.Io.Group = .init;
    group.async(io, runTestConnection, .{ io, server, &cfg });

    try writeTest(client, io, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWi");
    try writeTest(client, io, "ki\r\n5\r\npedia\r\n0\r\n\r\n");
    var response: [512]u8 = undefined;
    const complete = try readUntil(client, io, &response, "Wikipedia");
    try testing.expect(std.mem.endsWith(u8, complete, "Wikipedia"));
    try group.await(io);
}

test "Expect continue and HEAD response semantics" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try tcpPair(io);
    const client = streams[0];
    defer client.close(io);
    const server = streams[1];
    var cfg: Config = .{ .on_request = bodyHandler };
    var group: std.Io.Group = .init;
    group.async(io, runTestConnection, .{ io, server, &cfg });

    try writeTest(client, io, "POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n");
    var response: [512]u8 = undefined;
    const interim = try readUntil(client, io, &response, "\r\n\r\n");
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", interim);
    try writeTest(client, io, "abc");
    const posted = try readUntil(client, io, &response, "abc");
    try testing.expect(std.mem.endsWith(u8, posted, "abc"));

    try writeTest(client, io, "HEAD / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    const head = try readUntil(client, io, &response, "\r\n\r\n");
    try testing.expect(std.mem.indexOf(u8, head, "Content-Length: 0\r\n") != null);
    var byte: [1]u8 = undefined;
    var parts = [1][]u8{&byte};
    try testing.expectEqual(
        @as(usize, 0),
        try io.vtable.netRead(io.userdata, client.socket.handle, &parts),
    );
    try group.await(io);
}

test "partial request times out with 408" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try tcpPair(io);
    const client = streams[0];
    defer client.close(io);
    const server = streams[1];
    var cfg: Config = .{
        .request_timeout = .fromMilliseconds(20),
        .on_request = helloHandler,
    };
    var group: std.Io.Group = .init;
    group.async(io, runTestConnection, .{ io, server, &cfg });

    try writeTest(client, io, "GET /slow");
    var response: [256]u8 = undefined;
    const complete = try readUntil(client, io, &response, "\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, complete, "HTTP/1.1 408"));
    try group.await(io);
}

test "idle keep-alive closes and WebSocket close payloads are validated" {
    try testing.expectEqual(websocket.CloseCode.protocol_error, closePayloadError(&.{0}));
    try testing.expectEqual(
        websocket.CloseCode.protocol_error,
        closePayloadError(&.{ 0x03, 0xed }),
    );
    try testing.expectEqual(
        websocket.CloseCode.invalid_payload,
        closePayloadError(&.{ 0x03, 0xe8, 0xff }),
    );
    try testing.expect(closePayloadError(&.{ 0x03, 0xe8, 'b', 'y', 'e' }) == null);

    if (@import("builtin").os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try tcpPair(io);
    const client = streams[0];
    defer client.close(io);
    const server = streams[1];
    var cfg: Config = .{
        .keep_alive_timeout = .fromMilliseconds(20),
        .on_request = helloHandler,
    };
    var group: std.Io.Group = .init;
    group.async(io, runTestConnection, .{ io, server, &cfg });

    try writeTest(client, io, "GET /idle HTTP/1.1\r\nHost: x\r\n\r\n");
    var response: [256]u8 = undefined;
    _ = try readUntil(client, io, &response, "path=/idle");
    var byte: [1]u8 = undefined;
    var parts = [1][]u8{&byte};
    try testing.expectEqual(
        @as(usize, 0),
        try io.vtable.netRead(io.userdata, client.socket.handle, &parts),
    );
    try group.await(io);
}

test "WebSocket upgrade and echo over std.Io.net" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try tcpPair(io);
    const client = streams[0];
    defer client.close(io);
    const server = streams[1];
    var cfg: Config = .{ .on_request = upgradeHandler, .on_ws_message = echoHandler };
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    group.async(io, runTestConnection, .{ io, server, &cfg });

    try writeTest(client, io, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n");
    var handshake: [256]u8 = undefined;
    const accepted = try readUntil(client, io, &handshake, "\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, accepted, "HTTP/1.1 101"));

    try writeTest(client, io, &.{ 0x81, 0x82, 1, 2, 3, 4, 'H' ^ 1, 'i' ^ 2 });
    var echoed: [4]u8 = undefined;
    try readExact(client, io, &echoed);
    try testing.expectEqualSlices(u8, &.{ 0x81, 2, 'H', 'i' }, &echoed);

    try writeTest(client, io, &.{ 0x81, 0x81, 1, 2, 3, 4, 0xff ^ 1 });
    var closed: [4]u8 = undefined;
    try readExact(client, io, &closed);
    try testing.expectEqualSlices(u8, &.{ 0x88, 2, 0x03, 0xef }, &closed);
}
