//! Straight-line HTTP/WebSocket connection handling on `std.Io.net`.

const std = @import("std");
const http = @import("http.zig");
const tls = @import("tls/root.zig");
const websocket = @import("websocket.zig");

const Allocator = std.mem.Allocator;
const Stream = std.Io.net.Stream;

/// Produces a streamed response body. Returning completes the body.
pub const StreamHandler = *const fn (*const http.Request, *Connection, ?*anyopaque) anyerror!void;

/// Serves regular files below an already-opened directory. Symbolic links and
/// path traversal are rejected.
pub const StaticFiles = struct {
    dir: std.Io.Dir,
};

pub const Action = union(enum) {
    respond,
    stream: StreamHandler,
    files: StaticFiles,
    upgrade,
};

pub const TlsConfig = struct {
    auth: *tls.CertKeyPair,
    cipher_suites: []const tls.CipherSuite = tls.cipher_suites.secure,
};

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
    /// How long an idle WebSocket connection may stay silent. Set null only
    /// when the application has its own liveness policy.
    ws_idle_timeout: ?std.Io.Duration = .fromSeconds(60),
    /// Maximum time allowed to flush one HTTP response or WebSocket frame.
    write_timeout: ?std.Io.Duration = .fromSeconds(30),
    tls: ?TlsConfig = null,

    on_request: *const fn (*const http.Request, *http.Response, ?*anyopaque) Action,
    on_ws_open: ?*const fn (*Connection, ?*anyopaque) void = null,
    on_ws_message: ?*const fn (*Connection, websocket.Message, ?*anyopaque) void = null,
    on_ws_close: ?*const fn (*Connection, ?*anyopaque) void = null,
    user_data: ?*anyopaque = null,
};

/// Owned, thread-safe handle for server-initiated WebSocket messages.
/// Call `deinit` when the handle is no longer needed; use `clone` when
/// transferring ownership to another task.
pub const WebSocketPeer = struct {
    state: *State,

    pub const SendError = error{ Closed, Canceled, InvalidUtf8 };

    pub fn clone(self: WebSocketPeer) WebSocketPeer {
        self.state.retain();
        return self;
    }

    pub fn deinit(self: *WebSocketPeer) void {
        const state = self.state;
        self.* = undefined;
        state.release();
    }

    pub fn sendText(self: WebSocketPeer, data: []const u8) SendError!void {
        if (!std.unicode.utf8ValidateSlice(data)) return error.InvalidUtf8;
        try self.sendFrame(.text, data);
    }

    pub fn sendBinary(self: WebSocketPeer, data: []const u8) SendError!void {
        try self.sendFrame(.binary, data);
    }

    fn sendFrame(self: WebSocketPeer, opcode: websocket.Opcode, data: []const u8) SendError!void {
        const state = self.state;
        try state.mutex.lock(state.io);
        defer state.mutex.unlock(state.io);
        const connection = state.connection orelse return error.Closed;

        var header_buffer: [10]u8 = undefined;
        const header = websocket.frameHeader(&header_buffer, opcode, data.len, true);
        timedWrite(
            connection,
            header,
            durationTimeout(connection.cfg.write_timeout),
        ) catch |err| return state.writeFailed(connection, err);
        if (data.len > 0)
            timedWrite(
                connection,
                data,
                durationTimeout(connection.cfg.write_timeout),
            ) catch |err| return state.writeFailed(connection, err);
    }

    const State = struct {
        gpa: Allocator,
        io: std.Io,
        refs: std.atomic.Value(usize) = .init(1),
        mutex: std.Io.Mutex = .init,
        connection: ?*Connection,

        fn retain(self: *State) void {
            const previous = self.refs.fetchAdd(1, .monotonic);
            std.debug.assert(previous > 0 and previous < std.math.maxInt(usize));
        }

        fn release(self: *State) void {
            if (self.refs.fetchSub(1, .release) != 1) return;
            _ = self.refs.load(.acquire);
            self.gpa.destroy(self);
        }

        fn writeFailed(self: *State, connection: *Connection, err: anyerror) SendError {
            self.connection = null;
            connection.stream.shutdown(self.io, .both) catch {};
            return if (err == error.Canceled) error.Canceled else error.Closed;
        }
    };
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
    stream_framing: enum { none, chunked, close_delimited } = .none,
    tls_connection: ?*tls.Connection = null,
    ws_peer_state: ?*WebSocketPeer.State = null,

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
        self.closePeer();
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
                    .respond => if (!try self.bufferedResponse(consumed)) return,
                    .stream => |callback| {
                        if (!try self.streamResponse(consumed, callback)) return;
                    },
                    .files => |files| {
                        if (!try self.staticResponse(consumed, files)) return;
                    },
                    .upgrade => {
                        if (!try self.upgrade(consumed)) return;
                        return self.runWebSocket();
                    },
                }
            },
        };
    }

    fn bufferedResponse(self: *Connection, consumed: usize) !bool {
        const keep_alive = self.req.keep_alive;
        if (self.req.method == .HEAD)
            try self.res.serializeHead(&self.write_buf, self.gpa, keep_alive)
        else
            try self.res.serialize(&self.write_buf, self.gpa, keep_alive);
        self.consume(consumed);
        try self.flush();
        self.requests_served += 1;
        return keep_alive;
    }

    fn staticResponse(self: *Connection, consumed: usize, files: StaticFiles) !bool {
        if (self.req.method != .GET and self.req.method != .HEAD) {
            self.res.status = .method_not_allowed;
            try self.res.setHeader("Allow", "GET, HEAD");
            return self.bufferedResponse(consumed);
        }

        const raw_path = self.req.path;
        if (raw_path.len == 0 or raw_path[0] != '/') {
            self.res.status = .not_found;
            return self.bufferedResponse(consumed);
        }
        const encoded_path = raw_path[1..];
        const path_buffer = try self.gpa.alloc(u8, encoded_path.len + static_index.len);
        defer self.gpa.free(path_buffer);
        const path = decodeStaticPath(path_buffer, encoded_path) orelse {
            self.res.status = .not_found;
            return self.bufferedResponse(consumed);
        };

        var file = openStaticFile(self.io, files.dir, path) catch |err| {
            if (err == error.Canceled) return err;
            self.res.status = staticErrorStatus(err);
            return self.bufferedResponse(consumed);
        };
        defer file.close(self.io);
        const stat = file.stat(self.io) catch |err| {
            if (err == error.Canceled) return err;
            self.res.status = staticErrorStatus(err);
            return self.bufferedResponse(consumed);
        };
        if (stat.kind != .file) {
            self.res.status = .not_found;
            return self.bufferedResponse(consumed);
        }

        var etag_buffer: [96]u8 = undefined;
        const etag = staticEtag(&etag_buffer, stat);
        try self.res.setHeader("ETag", etag);
        try self.res.setHeader("Accept-Ranges", "bytes");
        if (self.req.header("if-none-match")) |value| {
            if (etagListMatches(value, etag)) {
                self.res.status = .not_modified;
                const keep_alive = self.req.keep_alive;
                try self.res.serializeKnownLength(
                    &self.write_buf,
                    self.gpa,
                    keep_alive,
                    stat.size,
                );
                self.consume(consumed);
                try self.flush();
                self.requests_served += 1;
                return keep_alive;
            }
        }

        var body_start: u64 = 0;
        var body_end = stat.size;
        if (self.req.method == .GET and
            self.req.header("range") != null and
            self.req.header("if-range") == null)
        {
            switch (parseByteRange(self.req.header("range").?, stat.size)) {
                .ignore => {},
                .unsatisfiable => {
                    self.res.status = .range_not_satisfiable;
                    var content_range_buffer: [64]u8 = undefined;
                    const content_range = std.fmt.bufPrint(
                        &content_range_buffer,
                        "bytes */{d}",
                        .{stat.size},
                    ) catch unreachable;
                    try self.res.setHeader("Content-Range", content_range);
                    return self.bufferedResponse(consumed);
                },
                .range => |byte_range| {
                    self.res.status = .partial_content;
                    body_start = byte_range.start;
                    body_end = byte_range.end + 1;
                    var content_range_buffer: [96]u8 = undefined;
                    const content_range = std.fmt.bufPrint(
                        &content_range_buffer,
                        "bytes {d}-{d}/{d}",
                        .{ byte_range.start, byte_range.end, stat.size },
                    ) catch unreachable;
                    try self.res.setHeader("Content-Range", content_range);
                },
            }
        }

        try self.res.setHeader("Content-Type", staticContentType(path));
        try self.res.setHeader("X-Content-Type-Options", "nosniff");
        const keep_alive = self.req.keep_alive;
        try self.res.serializeKnownLength(
            &self.write_buf,
            self.gpa,
            keep_alive,
            body_end - body_start,
        );
        try self.flush();

        if (self.req.method == .GET) {
            var offset = body_start;
            var buffer: [16 * 1024]u8 = undefined;
            while (offset < body_end) {
                const length: usize = @intCast(@min(
                    @as(u64, buffer.len),
                    body_end - offset,
                ));
                var parts = [1][]u8{buffer[0..length]};
                const n = try file.readPositional(self.io, &parts, offset);
                if (n == 0) return error.EndOfStream;
                try timedWrite(
                    self,
                    buffer[0..n],
                    durationTimeout(self.cfg.write_timeout),
                );
                offset += n;
            }
        }

        self.consume(consumed);
        self.requests_served += 1;
        return keep_alive;
    }

    fn streamResponse(self: *Connection, consumed: usize, callback: StreamHandler) !bool {
        const body_allowed = self.req.method != .HEAD and self.res.bodyAllowed();
        const chunked = self.req.minor_version >= 1;
        const keep_alive = self.req.keep_alive and (chunked or !body_allowed);

        try self.res.serializeStream(&self.write_buf, self.gpa, keep_alive, chunked);
        try self.flush();

        if (body_allowed) {
            self.stream_framing = if (chunked) .chunked else .close_delimited;
            defer self.stream_framing = .none;
            try callback(&self.req, self, self.cfg.user_data);
            if (chunked)
                try timedWrite(
                    self,
                    "0\r\n\r\n",
                    durationTimeout(self.cfg.write_timeout),
                );
        }

        self.consume(consumed);
        self.requests_served += 1;
        return keep_alive;
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
                try self.flush();
                const state = try self.gpa.create(WebSocketPeer.State);
                state.* = .{
                    .gpa = self.gpa,
                    .io = self.io,
                    .connection = self,
                };
                self.ws_peer_state = state;
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
        defer self.closePeer();
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
                    const more = self.readMore(
                        limit,
                        durationTimeout(self.cfg.ws_idle_timeout),
                    ) catch |err| switch (err) {
                        error.Timeout => {
                            self.wsClose(.going_away, "");
                            try self.flush();
                            return;
                        },
                        else => return err,
                    };
                    if (!more) return;
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
            self,
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
        if (self.ws_peer_state) |state| {
            try state.mutex.lock(self.io);
            defer state.mutex.unlock(self.io);
            if (state.connection != self) return error.Closed;
            timedWrite(
                self,
                self.write_buf.items,
                durationTimeout(self.cfg.write_timeout),
            ) catch |err| {
                state.connection = null;
                self.stream.shutdown(self.io, .both) catch {};
                return err;
            };
            self.write_buf.clearRetainingCapacity();
            if (self.closing) state.connection = null;
            return;
        }
        try timedWrite(
            self,
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

    fn closePeer(self: *Connection) void {
        const state = self.ws_peer_state orelse return;
        self.ws_peer_state = null;
        state.mutex.lockUncancelable(self.io);
        if (state.connection == self) state.connection = null;
        state.mutex.unlock(self.io);
        self.notifyClose();
        state.release();
    }

    /// Returns an owned outbound handle for this WebSocket connection.
    /// Valid only after upgrade; the caller must eventually call `deinit`.
    pub fn peer(self: *Connection) error{Closed}!WebSocketPeer {
        const state = self.ws_peer_state orelse return error.Closed;
        state.mutex.lockUncancelable(self.io);
        defer state.mutex.unlock(self.io);
        if (state.connection != self) return error.Closed;
        state.retain();
        return .{ .state = state };
    }

    /// Queue a text frame from a WebSocket callback. Use `peer()` when sending
    /// from another task or when the frame must be flushed immediately.
    pub fn sendText(self: *Connection, data: []const u8) !void {
        try websocket.writeText(&self.write_buf, self.gpa, data);
    }

    /// Write and flush one response-body chunk. Only valid inside a `.stream`
    /// callback; an empty chunk is ignored because completion is automatic.
    pub fn writeChunk(self: *Connection, data: []const u8) !void {
        switch (self.stream_framing) {
            .none => return error.NotStreaming,
            .close_delimited => if (data.len > 0)
                try timedWrite(
                    self,
                    data,
                    durationTimeout(self.cfg.write_timeout),
                ),
            .chunked => {
                if (data.len == 0) return;
                var buffer: [2 * @sizeOf(usize) + 2]u8 = undefined;
                const head = std.fmt.bufPrint(&buffer, "{x}\r\n", .{data.len}) catch unreachable;
                const timeout = durationTimeout(self.cfg.write_timeout);
                try timedWrite(self, head, timeout);
                try timedWrite(self, data, timeout);
                try timedWrite(self, "\r\n", timeout);
            },
        }
    }

    /// Queue a binary frame from a WebSocket callback. Use `peer()` when sending
    /// from another task or when the frame must be flushed immediately.
    pub fn sendBinary(self: *Connection, data: []const u8) !void {
        try websocket.writeFrame(&self.write_buf, self.gpa, .binary, data, true);
    }

    pub fn wsClose(self: *Connection, code: websocket.CloseCode, reason: []const u8) void {
        websocket.writeClose(&self.write_buf, self.gpa, code, reason) catch {};
        self.closing = true;
    }
};

const static_index = "index.html";

fn decodeStaticPath(buffer: []u8, encoded: []const u8) ?[]u8 {
    if (buffer.len < encoded.len + static_index.len) return null;
    var read: usize = 0;
    var write: usize = 0;
    while (read < encoded.len) {
        const byte = if (encoded[read] == '%') byte: {
            if (encoded.len - read < 3) return null;
            const value = std.fmt.parseInt(u8, encoded[read + 1 .. read + 3], 16) catch
                return null;
            read += 3;
            break :byte value;
        } else byte: {
            const value = encoded[read];
            read += 1;
            break :byte value;
        };
        if (byte < 0x20 or byte == 0x7f or byte == '\\' or byte == ':')
            return null;
        buffer[write] = byte;
        write += 1;
    }
    if (write == 0 or buffer[write - 1] == '/') {
        @memcpy(buffer[write..][0..static_index.len], static_index);
        write += static_index.len;
    }

    const path = buffer[0..write];
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return null;
        }
    }
    return path;
}

const ByteRange = struct {
    start: u64,
    end: u64,
};

const ByteRangeResult = union(enum) {
    ignore,
    unsatisfiable,
    range: ByteRange,
};

fn parseByteRange(header: []const u8, size: u64) ByteRangeResult {
    const value = std.mem.trim(u8, header, " \t");
    if (value.len < "bytes=".len or
        !std.ascii.eqlIgnoreCase(value[0.."bytes=".len], "bytes="))
    {
        return .ignore;
    }
    const spec = std.mem.trim(u8, value["bytes=".len..], " \t");
    // ponytail: multi-range requires multipart/byteranges; ignore it until a
    // caller actually needs more than resumable downloads and media seeking.
    if (spec.len == 0 or std.mem.indexOfScalar(u8, spec, ',') != null)
        return .ignore;
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return .ignore;
    const first = std.mem.trim(u8, spec[0..dash], " \t");
    const last = std.mem.trim(u8, spec[dash + 1 ..], " \t");
    if (first.len == 0) {
        if (last.len == 0) return .ignore;
        const suffix = std.fmt.parseInt(u64, last, 10) catch return .ignore;
        if (suffix == 0 or size == 0) return .unsatisfiable;
        const length = @min(suffix, size);
        return .{ .range = .{
            .start = size - length,
            .end = size - 1,
        } };
    }

    const start = std.fmt.parseInt(u64, first, 10) catch return .ignore;
    if (start >= size) return .unsatisfiable;
    if (last.len == 0) return .{ .range = .{
        .start = start,
        .end = size - 1,
    } };
    const requested_end = std.fmt.parseInt(u64, last, 10) catch return .ignore;
    if (requested_end < start) return .ignore;
    return .{ .range = .{
        .start = start,
        .end = @min(requested_end, size - 1),
    } };
}

fn staticEtag(buffer: []u8, stat: std.Io.File.Stat) []const u8 {
    // ponytail: metadata makes a cheap weak validator; hash file contents only
    // if callers need a byte-identical validator across timestamp collisions.
    const mtime_bits: u96 = @bitCast(stat.mtime.nanoseconds);
    return std.fmt.bufPrint(buffer, "W/\"{x}-{x}-{x}\"", .{
        stat.inode,
        stat.size,
        mtime_bits,
    }) catch unreachable;
}

fn etagListMatches(header: []const u8, etag: []const u8) bool {
    const current = if (std.mem.startsWith(u8, etag, "W/")) etag[2..] else etag;
    var values = std.mem.splitScalar(u8, header, ',');
    while (values.next()) |raw| {
        const value = std.mem.trim(u8, raw, " \t");
        if (std.mem.eql(u8, value, "*")) return true;
        const candidate = if (std.mem.startsWith(u8, value, "W/")) value[2..] else value;
        if (std.mem.eql(u8, candidate, current)) return true;
    }
    return false;
}

fn openStaticFile(io: std.Io, root: std.Io.Dir, path: []const u8) !std.Io.File {
    var components = std.mem.splitScalar(u8, path, '/');
    var component = components.next() orelse return error.FileNotFound;
    var dir = root;
    var owns_dir = false;
    defer if (owns_dir) dir.close(io);

    while (components.next()) |next| {
        const child = try dir.openDir(io, component, .{
            .follow_symlinks = false,
        });
        if (owns_dir) dir.close(io);
        dir = child;
        owns_dir = true;
        component = next;
    }
    return dir.openFile(io, component, .{
        .allow_directory = false,
        .follow_symlinks = false,
    });
}

fn staticErrorStatus(err: anyerror) http.Status {
    return switch (err) {
        error.FileNotFound,
        error.NotDir,
        error.IsDir,
        error.BadPathName,
        error.NameTooLong,
        => .not_found,
        error.AccessDenied,
        error.PermissionDenied,
        error.SymLinkLoop,
        => .forbidden,
        else => .internal_server_error,
    };
}

fn staticContentType(path: []const u8) []const u8 {
    const extension = std.fs.path.extension(path);
    const types = .{
        .{ ".html", "text/html; charset=utf-8" },
        .{ ".htm", "text/html; charset=utf-8" },
        .{ ".css", "text/css; charset=utf-8" },
        .{ ".js", "text/javascript; charset=utf-8" },
        .{ ".mjs", "text/javascript; charset=utf-8" },
        .{ ".json", "application/json" },
        .{ ".txt", "text/plain; charset=utf-8" },
        .{ ".xml", "application/xml" },
        .{ ".svg", "image/svg+xml" },
        .{ ".png", "image/png" },
        .{ ".jpg", "image/jpeg" },
        .{ ".jpeg", "image/jpeg" },
        .{ ".gif", "image/gif" },
        .{ ".webp", "image/webp" },
        .{ ".ico", "image/x-icon" },
        .{ ".pdf", "application/pdf" },
        .{ ".wasm", "application/wasm" },
        .{ ".woff", "font/woff" },
        .{ ".woff2", "font/woff2" },
    };
    inline for (types) |entry| {
        if (std.ascii.eqlIgnoreCase(extension, entry[0])) return entry[1];
    }
    return "application/octet-stream";
}

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
    connection: *Connection,
    buffer: []u8,
    timeout: std.Io.Timeout,
) !usize {
    if (timeout == .none) return transportRead(connection, buffer);
    var results: [2]ReadRace = undefined;
    var select = std.Io.Select(ReadRace).init(connection.io, &results);
    select.async(.io, transportRead, .{ connection, buffer });
    select.async(.timeout, waitTimeout, .{ connection.io, timeout });
    defer select.cancelDiscard();
    return switch (try select.await()) {
        .io => |result| try result,
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    };
}

fn transportRead(connection: *Connection, buffer: []u8) !usize {
    if (connection.tls_connection) |tls_connection|
        return tls_connection.read(buffer);
    var buffers = [1][]u8{buffer};
    return connection.io.vtable.netRead(
        connection.io.userdata,
        connection.stream.socket.handle,
        &buffers,
    );
}

const WriteRace = union(enum) {
    io: anyerror!void,
    timeout: std.Io.Cancelable!void,
};

fn timedWrite(
    connection: *Connection,
    bytes: []const u8,
    timeout: std.Io.Timeout,
) !void {
    if (timeout == .none) return transportWrite(connection, bytes);
    var results: [2]WriteRace = undefined;
    var select = std.Io.Select(WriteRace).init(connection.io, &results);
    select.async(.io, transportWrite, .{ connection, bytes });
    select.async(.timeout, waitTimeout, .{ connection.io, timeout });
    defer select.cancelDiscard();
    switch (try select.await()) {
        .io => |result| try result,
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    }
}

fn transportWrite(connection: *Connection, bytes: []const u8) !void {
    if (connection.tls_connection) |tls_connection|
        return tls_connection.writeAll(bytes);
    var buffer: [1024]u8 = undefined;
    var writer = connection.stream.writer(connection.io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn waitTimeout(io: std.Io, timeout: std.Io.Timeout) std.Io.Cancelable!void {
    try timeout.sleep(io);
}

const TlsHandshakeRace = union(enum) {
    io: anyerror!tls.Connection,
    timeout: std.Io.Cancelable!void,
};

fn tlsServerWithTimeout(
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    options: tls.ServerOptions,
    timeout: std.Io.Timeout,
) !tls.Connection {
    if (timeout == .none) return tls.server(input, output, options);
    var results: [2]TlsHandshakeRace = undefined;
    var select = std.Io.Select(TlsHandshakeRace).init(io, &results);
    select.async(.io, tls.server, .{ input, output, options });
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

pub fn handle(io: std.Io, stream: Stream, gpa: Allocator, cfg: *const Config) !void {
    defer stream.close(io);
    var connection = try Connection.init(io, stream, gpa, cfg);
    defer connection.deinit();

    if (cfg.tls) |tls_config| {
        var input_buffer: [tls.input_buffer_len]u8 = undefined;
        var output_buffer: [tls.output_buffer_len]u8 = undefined;
        var input = stream.reader(io, &input_buffer);
        var output = stream.writer(io, &output_buffer);
        const rng_source: std.Random.IoSource = .{ .io = io };
        var tls_connection = try tlsServerWithTimeout(
            io,
            &input.interface,
            &output.interface,
            .{
                .rng = rng_source.interface(),
                .auth = tls_config.auth,
                .cipher_suites = tls_config.cipher_suites,
                .alpn_protocols = &.{"http/1.1"},
                .now = std.Io.Clock.real.now(io),
            },
            durationTimeout(cfg.request_timeout),
        );
        connection.tls_connection = &tls_connection;
        defer tls_connection.close() catch {};
        defer connection.closePeer();
        return connection.run();
    }
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

fn streamHandler(_: *const http.Request, _: *http.Response, _: ?*anyopaque) Action {
    return .{ .stream = streamBody };
}

fn streamBody(_: *const http.Request, conn: *Connection, _: ?*anyopaque) !void {
    try conn.writeChunk("Wiki");
    try conn.writeChunk("");
    try conn.writeChunk("pedia");
}

fn staticHandler(_: *const http.Request, _: *http.Response, user_data: ?*anyopaque) Action {
    const files: *const StaticFiles = @ptrCast(@alignCast(user_data.?));
    return .{ .files = files.* };
}

fn staticTestRequest(
    io: std.Io,
    files: *const StaticFiles,
    request: []const u8,
    response: []u8,
    terminator: []const u8,
) ![]u8 {
    const streams = try tcpPair(io);
    const client = streams[0];
    defer client.close(io);
    var cfg: Config = .{
        .on_request = staticHandler,
        .user_data = @constCast(files),
    };
    var server_future = io.async(handle, .{
        io,
        streams[1],
        testing.allocator,
        &cfg,
    });
    defer server_future.cancel(io) catch {};

    try writeTest(client, io, request);
    const complete = try readUntil(client, io, response, terminator);
    try server_future.await(io);
    return complete;
}

fn echoHandler(conn: *Connection, message: websocket.Message, _: ?*anyopaque) void {
    conn.sendText(message.data) catch {};
}

const PeerTestContext = struct {
    peer: ?WebSocketPeer = null,
    ready: std.atomic.Value(bool) = .init(false),
    close_count: std.atomic.Value(usize) = .init(0),
};

fn capturePeer(conn: *Connection, data: ?*anyopaque) void {
    const context: *PeerTestContext = @ptrCast(@alignCast(data.?));
    context.peer = conn.peer() catch return;
    context.ready.store(true, .release);
}

fn countPeerClose(_: *Connection, data: ?*anyopaque) void {
    const context: *PeerTestContext = @ptrCast(@alignCast(data.?));
    _ = context.close_count.fetchAdd(1, .monotonic);
}

fn waitForPeer(io: std.Io, context: *const PeerTestContext) !WebSocketPeer {
    for (0..100) |_| {
        if (context.ready.load(.acquire)) return context.peer.?;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

fn sendOwnedPeerByte(owned_peer: WebSocketPeer, id: u8) WebSocketPeer.SendError!void {
    var peer = owned_peer;
    defer peer.deinit();
    try peer.sendBinary(&.{id});
}

fn sendOwnedPeerPayload(owned_peer: WebSocketPeer, payload: []const u8) WebSocketPeer.SendError!void {
    var peer = owned_peer;
    defer peer.deinit();
    try peer.sendBinary(payload);
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

fn readReaderUntil(reader: *std.Io.Reader, buffer: []u8, needle: []const u8) ![]u8 {
    var needed: usize = 1;
    while (needed <= buffer.len) {
        const available = try reader.peekGreedy(needed);
        if (std.mem.indexOf(u8, available, needle)) |index| {
            const len = index + needle.len;
            @memcpy(buffer[0..len], available[0..len]);
            reader.toss(len);
            return buffer[0..len];
        }
        needed = available.len + 1;
    }
    return error.StreamTooLong;
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

test "static path, range, ETag, and content type helpers" {
    var decoded: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "assets/app.js",
        decodeStaticPath(&decoded, "assets%2Fapp.js").?,
    );
    try testing.expectEqualStrings("index.html", decodeStaticPath(&decoded, "").?);
    try testing.expectEqualStrings(
        "assets/index.html",
        decodeStaticPath(&decoded, "assets/").?,
    );

    const rejected = [_][]const u8{
        "..",
        "assets/../secret",
        "%2e%2e/secret",
        "/etc/passwd",
        "assets//app.js",
        "assets%5capp.js",
        "C:%5csecret",
        "bad%",
        "bad%2",
        "bad%zz",
    };
    for (rejected) |input| {
        try testing.expect(decodeStaticPath(&decoded, input) == null);
    }

    const closed = parseByteRange("bytes=2-5", 10).range;
    try testing.expectEqual(@as(u64, 2), closed.start);
    try testing.expectEqual(@as(u64, 5), closed.end);
    const open = parseByteRange("bytes=7-", 10).range;
    try testing.expectEqual(@as(u64, 7), open.start);
    try testing.expectEqual(@as(u64, 9), open.end);
    const suffix = parseByteRange("bytes=-3", 10).range;
    try testing.expectEqual(@as(u64, 7), suffix.start);
    try testing.expectEqual(@as(u64, 9), suffix.end);
    try testing.expect(parseByteRange("bytes=10-", 10) == .unsatisfiable);
    try testing.expect(parseByteRange("bytes=-0", 10) == .unsatisfiable);
    try testing.expect(parseByteRange("bytes=5-3", 10) == .ignore);
    try testing.expect(parseByteRange("bytes=0-1,4-5", 10) == .ignore);

    try testing.expect(etagListMatches("\"abc\", W/\"def\"", "W/\"def\""));
    try testing.expect(etagListMatches("*", "W/\"def\""));
    try testing.expect(!etagListMatches("\"abc\"", "W/\"def\""));
    try testing.expectEqualStrings("text/html; charset=utf-8", staticContentType("index.HTML"));
    try testing.expectEqualStrings("application/wasm", staticContentType("pkg/module.wasm"));
    try testing.expectEqualStrings("application/octet-stream", staticContentType("data.bin"));
}

fn checkStaticParserInput(input: []const u8) !void {
    var decoded_buffer: [512 + static_index.len]u8 = undefined;
    if (decodeStaticPath(&decoded_buffer, input)) |decoded|
        try testing.expect(decoded.len <= decoded_buffer.len);

    const size = if (input.len >= @sizeOf(u64))
        std.mem.readInt(u64, input[0..@sizeOf(u64)], .little)
    else
        @as(u64, input.len);
    switch (parseByteRange(input, size)) {
        .ignore, .unsatisfiable => {},
        .range => |byte_range| {
            try testing.expect(size > 0);
            try testing.expect(byte_range.start <= byte_range.end);
            try testing.expect(byte_range.end < size);
        },
    }
    _ = etagListMatches(input, "W/\"fuzz\"");
}

fn fuzzStaticParsers(_: void, smith: *std.testing.Smith) !void {
    var bytes: [512]u8 = undefined;
    const len = smith.slice(&bytes);
    try checkStaticParserInput(bytes[0..len]);
}

fn staticSmithSliceCorpus(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

test "static file parsers tolerate arbitrary input" {
    const traversal = staticSmithSliceCorpus("assets/%2e%2e/secret");
    const range = staticSmithSliceCorpus("bytes=18446744073709551615-");
    const etag = staticSmithSliceCorpus("W/\"abc\", *");
    try testing.fuzz({}, fuzzStaticParsers, .{
        .corpus = &.{ &traversal, &range, &etag },
    });
}

test "static files serve GET and HEAD and reject unsafe paths" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "secret.txt",
        .data = "not public",
    });
    var public = try tmp.dir.createDirPathOpen(testing.io, "public/assets", .{});
    try public.writeFile(testing.io, .{
        .sub_path = "app.js",
        .data = "console.log('ok');",
    });
    try public.writeFile(testing.io, .{
        .sub_path = "index.html",
        .data = "<h1>asset index</h1>",
    });
    public.close(testing.io);
    public = try tmp.dir.openDir(testing.io, "public", .{});
    defer public.close(testing.io);
    try public.symLink(testing.io, "../secret.txt", "link.txt", .{});
    try public.symLink(testing.io, "..", "escape", .{ .is_directory = true });

    const files: StaticFiles = .{ .dir = public };
    const cases = [_]struct {
        request: []const u8,
        terminator: []const u8,
        expected: []const u8,
        expected_also: ?[]const u8 = null,
        absent: ?[]const u8 = null,
    }{
        .{
            .request = "GET /assets/app.js HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .terminator = "console.log('ok');",
            .expected = "Content-Type: text/javascript; charset=utf-8\r\n",
        },
        .{
            .request = "HEAD /assets/app.js HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .terminator = "\r\n\r\n",
            .expected = "Content-Length: 18\r\n",
            .absent = "console.log",
        },
        .{
            .request = "GET /assets/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .terminator = "<h1>asset index</h1>",
            .expected = "Content-Type: text/html; charset=utf-8\r\n",
        },
        .{
            .request = "GET /assets/app.js HTTP/1.1\r\nHost: x\r\nRange: bytes=8-10\r\nConnection: close\r\n\r\n",
            .terminator = "log",
            .expected = "HTTP/1.1 206 Partial Content\r\n",
            .expected_also = "Content-Range: bytes 8-10/18\r\n",
        },
        .{
            .request = "GET /assets/app.js HTTP/1.1\r\nHost: x\r\nRange: bytes=99-\r\nConnection: close\r\n\r\n",
            .terminator = "\r\n\r\n",
            .expected = "HTTP/1.1 416 Range Not Satisfiable\r\n",
            .expected_also = "Content-Range: bytes */18\r\n",
            .absent = "console.log",
        },
        .{
            .request = "GET /%2e%2e/secret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .terminator = "\r\n\r\n",
            .expected = "HTTP/1.1 404 Not Found\r\n",
            .absent = "not public",
        },
        .{
            .request = "GET /link.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .terminator = "\r\n\r\n",
            .expected = "HTTP/1.1 403 Forbidden\r\n",
            .absent = "not public",
        },
        .{
            .request = "GET /escape/secret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .terminator = "\r\n\r\n",
            .expected = "HTTP/1.1 404 Not Found\r\n",
            .absent = "not public",
        },
        .{
            .request = "POST /assets/app.js HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .terminator = "\r\n\r\n",
            .expected = "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\n",
        },
    };

    for (cases) |case| {
        var response: [1024]u8 = undefined;
        const complete = try staticTestRequest(
            io,
            &files,
            case.request,
            &response,
            case.terminator,
        );
        try testing.expect(std.mem.indexOf(u8, complete, case.expected) != null);
        if (case.expected_also) |expected|
            try testing.expect(std.mem.indexOf(u8, complete, expected) != null);
        if (case.absent) |absent|
            try testing.expect(std.mem.indexOf(u8, complete, absent) == null);
    }

    var initial_response: [1024]u8 = undefined;
    const initial = try staticTestRequest(
        io,
        &files,
        "GET /assets/app.js HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        &initial_response,
        "console.log('ok');",
    );
    const etag_prefix = "ETag: ";
    const etag_start = (std.mem.indexOf(u8, initial, etag_prefix) orelse
        return error.TestUnexpectedResult) + etag_prefix.len;
    const etag_end = std.mem.indexOfPos(u8, initial, etag_start, "\r\n") orelse
        return error.TestUnexpectedResult;
    const etag = initial[etag_start..etag_end];
    var conditional_request: [256]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &conditional_request,
        "GET /assets/app.js HTTP/1.1\r\nHost: x\r\nIf-None-Match: {s}\r\nConnection: close\r\n\r\n",
        .{etag},
    );
    var conditional_response: [1024]u8 = undefined;
    const not_modified = try staticTestRequest(
        io,
        &files,
        request,
        &conditional_response,
        "\r\n\r\n",
    );
    try testing.expect(std.mem.startsWith(u8, not_modified, "HTTP/1.1 304 Not Modified\r\n"));
    const body_start = (std.mem.indexOf(u8, not_modified, "\r\n\r\n") orelse
        return error.TestUnexpectedResult) + 4;
    try testing.expectEqual(@as(usize, 0), not_modified[body_start..].len);
}

test "TLS 1.2 and 1.3 serve HTTP through the same connection path" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var auth = try tls.CertKeyPair.fromSlice(
        testing.allocator,
        io,
        @embedFile("tls/testdata/server_cert.pem"),
        @embedFile("tls/testdata/server_key.pem"),
    );
    defer auth.deinit(testing.allocator);

    const cases = [_][]const tls.CipherSuite{
        &.{.ECDHE_RSA_WITH_AES_128_GCM_SHA256},
        &.{.AES_128_GCM_SHA256},
    };
    for (cases) |cipher_suites| {
        const streams = try tcpPair(io);
        const client_stream = streams[0];
        defer client_stream.close(io);
        const server_stream = streams[1];
        var cfg: Config = .{
            .on_request = helloHandler,
            .tls = .{
                .auth = &auth,
                .cipher_suites = cipher_suites,
            },
        };
        var server_future = io.async(handle, .{
            io,
            server_stream,
            testing.allocator,
            &cfg,
        });
        defer server_future.cancel(io) catch {};

        const Client = std.crypto.tls.Client;
        var input_buffer: [Client.min_buffer_len]u8 = undefined;
        var output_buffer: [Client.min_buffer_len]u8 = undefined;
        var tls_read_buffer: [Client.min_buffer_len]u8 = undefined;
        var tls_write_buffer: [Client.min_buffer_len]u8 = undefined;
        var input = client_stream.reader(io, &input_buffer);
        var output = client_stream.writer(io, &output_buffer);
        var entropy: [Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        var client = try Client.init(&input.interface, &output.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &tls_read_buffer,
            .write_buffer = &tls_write_buffer,
            .entropy = &entropy,
            .realtime_now = std.Io.Clock.real.now(io),
        });
        try client.writer.writeAll(
            "GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        try client.writer.flush();
        try output.interface.flush();

        var response: [512]u8 = undefined;
        const n = try client.reader.readSliceShort(&response);
        server_future.await(io) catch |server_err| {
            std.debug.print("TLS HTTP server error: {s}\n", .{@errorName(server_err)});
            return server_err;
        };
        try testing.expect(std.mem.startsWith(u8, response[0..n], "HTTP/1.1 200 OK\r\n"));
        try testing.expect(std.mem.indexOf(u8, response[0..n], "path=/secure") != null);
    }

    const streams = try tcpPair(io);
    defer streams[0].close(io);
    var timeout_cfg: Config = .{
        .request_timeout = .fromMilliseconds(20),
        .on_request = helloHandler,
        .tls = .{ .auth = &auth },
    };
    var timeout_future = io.async(handle, .{
        io,
        streams[1],
        testing.allocator,
        &timeout_cfg,
    });
    try testing.expectError(error.Timeout, timeout_future.await(io));
}

test "outbound WebSocket peer writes through TLS while the reader is idle" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var auth = try tls.CertKeyPair.fromSlice(
        testing.allocator,
        io,
        @embedFile("tls/testdata/server_cert.pem"),
        @embedFile("tls/testdata/server_key.pem"),
    );
    defer auth.deinit(testing.allocator);

    const streams = try tcpPair(io);
    const client_stream = streams[0];
    defer client_stream.close(io);
    var context: PeerTestContext = .{};
    defer if (context.peer) |*peer| peer.deinit();
    var cfg: Config = .{
        .ws_idle_timeout = null,
        .on_request = upgradeHandler,
        .on_ws_open = capturePeer,
        .on_ws_close = countPeerClose,
        .user_data = &context,
        .tls = .{
            .auth = &auth,
            .cipher_suites = &.{.AES_128_GCM_SHA256},
        },
    };
    var server_future = io.async(handle, .{
        io,
        streams[1],
        testing.allocator,
        &cfg,
    });
    defer server_future.cancel(io) catch {};

    const Client = std.crypto.tls.Client;
    var input_buffer: [Client.min_buffer_len]u8 = undefined;
    var output_buffer: [Client.min_buffer_len]u8 = undefined;
    var tls_read_buffer: [Client.min_buffer_len]u8 = undefined;
    var tls_write_buffer: [Client.min_buffer_len]u8 = undefined;
    var input = client_stream.reader(io, &input_buffer);
    var output = client_stream.writer(io, &output_buffer);
    var entropy: [Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var client = try Client.init(&input.interface, &output.interface, .{
        .host = .no_verification,
        .ca = .no_verification,
        .read_buffer = &tls_read_buffer,
        .write_buffer = &tls_write_buffer,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
    });
    try client.writer.writeAll("GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n");
    try client.writer.flush();
    try output.interface.flush();

    var handshake: [512]u8 = undefined;
    const accepted = try readReaderUntil(&client.reader, &handshake, "\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, accepted, "HTTP/1.1 101"));
    const peer = try waitForPeer(io, &context);
    try peer.sendText("tls");
    var frame: [5]u8 = undefined;
    try client.reader.readSliceAll(&frame);
    try testing.expectEqualSlices(u8, "\x81\x03tls", &frame);

    try client.end();
    try output.interface.flush();
    try server_future.await(io);
    try testing.expectEqual(@as(usize, 1), context.close_count.load(.monotonic));
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

test "response streaming uses HTTP version framing" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const Case = struct {
        request: []const u8,
        terminator: []const u8,
        expected: []const u8,
    };
    for ([_]Case{
        .{
            .request = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .terminator = "0\r\n\r\n",
            .expected = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" ++
                "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        },
        .{
            .request = "GET / HTTP/1.0\r\n\r\n",
            .terminator = "Wikipedia",
            .expected = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nWikipedia",
        },
    }) |case| {
        const streams = try tcpPair(io);
        const client = streams[0];
        defer client.close(io);
        const server = streams[1];
        var cfg: Config = .{ .on_request = streamHandler };
        var group: std.Io.Group = .init;
        group.async(io, runTestConnection, .{ io, server, &cfg });

        try writeTest(client, io, case.request);
        var response: [256]u8 = undefined;
        const complete = try readUntil(client, io, &response, case.terminator);
        try testing.expectEqualStrings(case.expected, complete);
        try group.await(io);
    }
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

test "idle HTTP and WebSocket connections close and WebSocket close payloads are validated" {
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

    const ws_streams = try tcpPair(io);
    const ws_client = ws_streams[0];
    defer ws_client.close(io);
    var ws_cfg: Config = .{
        .ws_idle_timeout = .fromMilliseconds(20),
        .on_request = upgradeHandler,
    };
    var ws_group: std.Io.Group = .init;
    ws_group.async(io, runTestConnection, .{ io, ws_streams[1], &ws_cfg });
    try writeTest(ws_client, io, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n");
    var handshake: [256]u8 = undefined;
    _ = try readUntil(ws_client, io, &handshake, "\r\n\r\n");
    var close: [4]u8 = undefined;
    try readExact(ws_client, io, &close);
    try testing.expectEqualSlices(u8, &.{ 0x88, 2, 0x03, 0xe9 }, &close);
    try ws_group.await(io);
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

test "outbound WebSocket peer sends immediately, serializes, and closes safely" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try tcpPair(io);
    const client = streams[0];
    defer client.close(io);

    var context: PeerTestContext = .{};
    defer if (context.peer) |*peer| peer.deinit();
    var cfg: Config = .{
        .ws_idle_timeout = null,
        .on_request = upgradeHandler,
        .on_ws_open = capturePeer,
        .on_ws_close = countPeerClose,
        .user_data = &context,
    };
    var server_future = io.async(handle, .{
        io,
        streams[1],
        testing.allocator,
        &cfg,
    });
    defer server_future.cancel(io) catch {};

    try writeTest(client, io, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n");
    var handshake: [256]u8 = undefined;
    const accepted = try readUntil(client, io, &handshake, "\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, accepted, "HTTP/1.1 101"));

    const peer = try waitForPeer(io, &context);
    try peer.sendText("idle");
    var idle_frame: [6]u8 = undefined;
    try readExact(client, io, &idle_frame);
    try testing.expectEqualSlices(u8, "\x81\x04idle", &idle_frame);

    const send_count = 16;
    var sends: [send_count]std.Io.Future(WebSocketPeer.SendError!void) = undefined;
    for (&sends, 0..) |*future, id|
        future.* = io.async(sendOwnedPeerByte, .{ peer.clone(), @as(u8, @intCast(id)) });

    var frames: [send_count * 3]u8 = undefined;
    try readExact(client, io, &frames);
    for (&sends) |*future| try future.await(io);
    var seen = [_]bool{false} ** send_count;
    for (0..send_count) |index| {
        const frame = frames[index * 3 ..][0..3];
        try testing.expectEqualSlices(u8, &.{ 0x82, 1 }, frame[0..2]);
        try testing.expect(frame[2] < send_count);
        try testing.expect(!seen[frame[2]]);
        seen[frame[2]] = true;
    }

    const stress_count = 8;
    var payload: [32 * 1024]u8 = undefined;
    @memset(&payload, 0xa5);
    var stress: [stress_count]std.Io.Future(WebSocketPeer.SendError!void) = undefined;
    for (&stress) |*future|
        future.* = io.async(sendOwnedPeerPayload, .{ peer.clone(), &payload });
    try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    try client.shutdown(io, .both);
    for (&stress) |*future| {
        future.await(io) catch |err| switch (err) {
            error.Closed, error.Canceled => {},
            else => return err,
        };
    }
    try server_future.await(io);
    try testing.expectEqual(@as(usize, 1), context.close_count.load(.monotonic));
    try testing.expectError(error.Closed, peer.sendText("late"));
}
