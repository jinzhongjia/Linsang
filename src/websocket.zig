//! WebSocket (RFC 6455): upgrade handshake, frame codec, and message
//! reassembly. Pure functions over buffers — no sockets here. The connection
//! layer drives this and owns the transport.

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Compute the `Sec-WebSocket-Accept` value: base64(SHA1(key ++ GUID)).
/// `out` receives exactly 28 base64 bytes.
pub fn acceptKey(key: []const u8, out: *[28]u8) void {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update(guid);
    var digest: [20]u8 = undefined;
    sha.final(&digest);
    _ = std.base64.standard.Encoder.encode(out, &digest);
}

pub const Upgrade = union(enum) {
    /// Not a WebSocket upgrade — handle as a normal HTTP request.
    no,
    /// Valid upgrade request; value is the Sec-WebSocket-Key to accept.
    yes: []const u8,
    /// Upgrade attempt with an unsupported version — respond 426.
    version_mismatch,
};

/// Classify a parsed request as a WebSocket upgrade or not.
pub fn checkUpgrade(req: *const http.Request) Upgrade {
    if (req.method != .GET) return .no;
    const upgrade = req.header("upgrade") orelse return .no;
    if (!hasToken(upgrade, "websocket")) return .no;
    const conn = req.header("connection") orelse return .no;
    if (!hasToken(conn, "upgrade")) return .no;
    const key = req.header("sec-websocket-key") orelse return .no;

    const ver = req.header("sec-websocket-version") orelse return .version_mismatch;
    if (!std.mem.eql(u8, std.mem.trim(u8, ver, " \t"), "13")) return .version_mismatch;
    var decoded: [16]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    if ((decoder.calcSizeForSlice(key) catch return .no) != decoded.len) return .no;
    decoder.decode(&decoded, key) catch return .no;
    return .{ .yes = key };
}

/// Write the 101 Switching Protocols handshake response for `key`.
pub fn writeAccept(out: *std.ArrayList(u8), gpa: Allocator, key: []const u8) !void {
    var accept: [28]u8 = undefined;
    acceptKey(key, &accept);
    try out.appendSlice(gpa, "HTTP/1.1 101 Switching Protocols\r\n");
    try out.appendSlice(gpa, "Upgrade: websocket\r\n");
    try out.appendSlice(gpa, "Connection: Upgrade\r\n");
    try out.appendSlice(gpa, "Sec-WebSocket-Accept: ");
    try out.appendSlice(gpa, &accept);
    try out.appendSlice(gpa, "\r\n\r\n");
}

fn hasToken(field: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, field, ',');
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,

    pub fn isControl(self: Opcode) bool {
        return (@intFromEnum(self) & 0x8) != 0;
    }

    pub fn isKnown(self: Opcode) bool {
        return switch (self) {
            .continuation, .text, .binary, .close, .ping, .pong => true,
            _ => false,
        };
    }
};

pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    internal_error = 1011,
    _,
};

pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    /// Unmasked payload, slice into the input buffer.
    payload: []const u8,
};

pub const FrameResult = union(enum) {
    need_more,
    done: struct { frame: Frame, consumed: usize },
    /// Protocol violation — close with this code.
    fail: CloseCode,
};

/// Parse one frame from the front of `buf`, unmasking in place. `require_mask`
/// should be true for a server (clients MUST mask).
pub fn parseFrame(buf: []u8, require_mask: bool) FrameResult {
    if (buf.len < 2) return .need_more;
    const b0 = buf[0];
    const b1 = buf[1];
    if ((b0 & 0x70) != 0) return .{ .fail = .protocol_error }; // RSV must be 0
    const fin = (b0 & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(b0 & 0x0F)));
    if (!opcode.isKnown()) return .{ .fail = .protocol_error };
    const masked = (b1 & 0x80) != 0;
    const len7: u7 = @truncate(b1 & 0x7F);

    var pos: usize = 2;
    var payload_len: u64 = len7;
    if (len7 == 126) {
        if (buf.len < 4) return .need_more;
        payload_len = std.mem.readInt(u16, buf[2..4], .big);
        pos = 4;
    } else if (len7 == 127) {
        if (buf.len < 10) return .need_more;
        payload_len = std.mem.readInt(u64, buf[2..10], .big);
        if ((payload_len >> 63) != 0) return .{ .fail = .protocol_error };
        pos = 10;
    }

    if (opcode.isControl()) {
        if (!fin) return .{ .fail = .protocol_error }; // control must not fragment
        if (payload_len > 125) return .{ .fail = .protocol_error };
    }

    if (require_mask and !masked) return .{ .fail = .protocol_error };
    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (buf.len < pos + 4) return .need_more;
        mask_key = buf[pos..][0..4].*;
        pos += 4;
    }

    if (payload_len > buf.len - pos) return .need_more;
    const plen: usize = @intCast(payload_len);
    const payload = buf[pos .. pos + plen];
    if (masked) {
        for (payload, 0..) |*c, i| c.* ^= mask_key[i & 3];
    }
    return .{ .done = .{ .frame = .{ .fin = fin, .opcode = opcode, .payload = payload }, .consumed = pos + plen } };
}

/// Serialize a server->client frame (never masked) into `out`.
pub fn writeFrame(out: *std.ArrayList(u8), gpa: Allocator, opcode: Opcode, payload: []const u8, fin: bool) !void {
    var hdr: [10]u8 = undefined;
    hdr[0] = (if (fin) @as(u8, 0x80) else 0) | @intFromEnum(opcode);
    var n: usize = 2;
    if (payload.len < 126) {
        hdr[1] = @intCast(payload.len);
    } else if (payload.len <= 0xFFFF) {
        hdr[1] = 126;
        std.mem.writeInt(u16, hdr[2..4], @intCast(payload.len), .big);
        n = 4;
    } else {
        hdr[1] = 127;
        std.mem.writeInt(u64, hdr[2..10], payload.len, .big);
        n = 10;
    }
    try out.appendSlice(gpa, hdr[0..n]);
    try out.appendSlice(gpa, payload);
}

pub fn writeText(out: *std.ArrayList(u8), gpa: Allocator, payload: []const u8) !void {
    if (!std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
    try writeFrame(out, gpa, .text, payload, true);
}

pub fn writeClose(out: *std.ArrayList(u8), gpa: Allocator, code: CloseCode, reason: []const u8) !void {
    var payload: [125]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], @intFromEnum(code), .big);
    const rlen = @min(reason.len, payload.len - 2);
    @memcpy(payload[2 .. 2 + rlen], reason[0..rlen]);
    try writeFrame(out, gpa, .close, payload[0 .. 2 + rlen], true);
}

pub fn writePong(out: *std.ArrayList(u8), gpa: Allocator, payload: []const u8) !void {
    try writeFrame(out, gpa, .pong, payload, true);
}

pub fn writePing(out: *std.ArrayList(u8), gpa: Allocator, payload: []const u8) !void {
    try writeFrame(out, gpa, .ping, payload, true);
}

// ---------------------------------------------------------------------------
// Message reassembly
// ---------------------------------------------------------------------------

pub const Message = struct { opcode: Opcode, data: []const u8 };

/// Reassembles fragmented data frames into whole messages. Control frames are
/// NOT passed through here — the connection handles them out of band.
pub const Assembler = struct {
    gpa: Allocator,
    max_size: usize,
    buf: std.ArrayList(u8) = .empty,
    msg_opcode: Opcode = .continuation,
    active: bool = false,

    pub fn init(gpa: Allocator, max_size: usize) Assembler {
        return .{ .gpa = gpa, .max_size = max_size };
    }

    pub fn deinit(self: *Assembler) void {
        self.buf.deinit(self.gpa);
    }

    /// Drop any in-progress message (keeps allocated capacity).
    pub fn reset(self: *Assembler) void {
        self.buf.clearRetainingCapacity();
        self.active = false;
    }

    pub const PushResult = union(enum) {
        incomplete,
        message: Message,
        fail: CloseCode,
    };

    /// Feed one data frame (text/binary/continuation). Returns a completed
    /// message on the final fragment. The returned slice is valid until the
    /// next `push`.
    pub fn push(self: *Assembler, frame: Frame) PushResult {
        std.debug.assert(!frame.opcode.isControl());
        if (frame.opcode == .continuation) {
            if (!self.active) return .{ .fail = .protocol_error };
        } else {
            if (self.active) return .{ .fail = .protocol_error }; // new message mid-fragment
            self.active = true;
            self.msg_opcode = frame.opcode;
            self.buf.clearRetainingCapacity();
        }
        if (self.buf.items.len + frame.payload.len > self.max_size)
            return .{ .fail = .message_too_big };
        self.buf.appendSlice(self.gpa, frame.payload) catch return .{ .fail = .internal_error };

        if (!frame.fin) return .incomplete;
        self.active = false;
        return .{ .message = .{ .opcode = self.msg_opcode, .data = self.buf.items } };
    }
};

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "acceptKey RFC 6455 vector" {
    var out: [28]u8 = undefined;
    acceptKey("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &out);
}

test "checkUpgrade positive" {
    var req: http.Request = .{};
    const raw = "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try testing.expect(http.parseHead(&req, raw) == .done);
    const u = checkUpgrade(&req);
    try testing.expect(u == .yes);
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", u.yes);
}

test "checkUpgrade negatives" {
    var req: http.Request = .{};
    _ = http.parseHead(&req, "GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expect(checkUpgrade(&req) == .no);

    req.reset();
    _ = http.parseHead(&req, "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: x\r\nSec-WebSocket-Version: 8\r\n\r\n");
    try testing.expect(checkUpgrade(&req) == .version_mismatch);

    req.reset();
    _ = http.parseHead(&req, "POST / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    try testing.expect(checkUpgrade(&req) == .no); // not GET

    req.reset();
    _ = http.parseHead(&req, "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n");
    try testing.expect(checkUpgrade(&req) == .no);
}

test "writeAccept response" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try writeAccept(&out, gpa, "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectEqualStrings(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        out.items,
    );
}

test "parseFrame masked text round-trip" {
    // "Hi" masked with key 0x01020304.
    var buf = [_]u8{ 0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'H' ^ 0x01, 'i' ^ 0x02 };
    const r = parseFrame(&buf, true);
    try testing.expectEqual(buf.len, r.done.consumed);
    try testing.expect(r.done.frame.fin);
    try testing.expectEqual(Opcode.text, r.done.frame.opcode);
    try testing.expectEqualStrings("Hi", r.done.frame.payload);
}

test "parseFrame need_more" {
    var buf = [_]u8{ 0x81, 0x82, 0x01 };
    try testing.expect(parseFrame(&buf, true) == .need_more);
    var b2 = [_]u8{0x81};
    try testing.expect(parseFrame(&b2, true) == .need_more);
}

test "parseFrame rejects unmasked client frame and RSV" {
    var unmasked = [_]u8{ 0x81, 0x02, 'H', 'i' };
    try testing.expectEqual(CloseCode.protocol_error, parseFrame(&unmasked, true).fail);
    var rsv = [_]u8{ 0xC1, 0x80, 0, 0, 0, 0 };
    try testing.expectEqual(CloseCode.protocol_error, parseFrame(&rsv, true).fail);
}

test "parseFrame control frame constraints" {
    // Fragmented control frame (FIN=0, opcode=ping) is illegal.
    var frag_ctrl = [_]u8{ 0x09, 0x80, 0, 0, 0, 0 };
    try testing.expectEqual(CloseCode.protocol_error, parseFrame(&frag_ctrl, true).fail);
}

test "parseFrame 16-bit extended length" {
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, 200);
    defer gpa.free(payload);
    @memset(payload, 'z');
    // Build a masked frame with 16-bit length and decode it.
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(gpa);
    try frame.appendSlice(gpa, &.{ 0x82, 0xFE }); // binary, masked, len=126
    try frame.appendSlice(gpa, &.{ 0x00, 0xC8 }); // 200
    try frame.appendSlice(gpa, &.{ 0, 0, 0, 0 }); // mask key (identity)
    try frame.appendSlice(gpa, payload);
    const r = parseFrame(frame.items, true);
    try testing.expectEqual(@as(usize, 200), r.done.frame.payload.len);
    try testing.expectEqual(Opcode.binary, r.done.frame.opcode);
}

test "writeText validates UTF-8 and round-trips via parse" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try writeText(&out, gpa, "hello");
    try testing.expectEqual(@as(u8, 0x81), out.items[0]);
    try testing.expectEqual(@as(u8, 5), out.items[1]); // unmasked, len 5
    // Server frames are unmasked: parse with require_mask=false.
    const r = parseFrame(out.items, false);
    try testing.expectEqualStrings("hello", r.done.frame.payload);
    try testing.expectError(error.InvalidUtf8, writeText(&out, gpa, &.{0xff}));
}

test "writeClose encodes code + reason" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try writeClose(&out, gpa, .normal, "bye");
    const r = parseFrame(out.items, false);
    try testing.expectEqual(Opcode.close, r.done.frame.opcode);
    try testing.expectEqual(@as(u16, 1000), std.mem.readInt(u16, r.done.frame.payload[0..2], .big));
    try testing.expectEqualStrings("bye", r.done.frame.payload[2..]);
}

test "Assembler reassembles fragments" {
    const gpa = testing.allocator;
    var asm_ = Assembler.init(gpa, 1024);
    defer asm_.deinit();

    try testing.expect(asm_.push(.{ .fin = false, .opcode = .text, .payload = "Hel" }) == .incomplete);
    try testing.expect(asm_.push(.{ .fin = false, .opcode = .continuation, .payload = "lo, " }) == .incomplete);
    const r = asm_.push(.{ .fin = true, .opcode = .continuation, .payload = "world" });
    try testing.expectEqual(Opcode.text, r.message.opcode);
    try testing.expectEqualStrings("Hello, world", r.message.data);
}

test "Assembler rejects protocol errors and oversize" {
    const gpa = testing.allocator;
    var asm_ = Assembler.init(gpa, 4);
    defer asm_.deinit();

    // continuation without a start
    try testing.expectEqual(CloseCode.protocol_error, asm_.push(.{ .fin = true, .opcode = .continuation, .payload = "x" }).fail);
    // oversize
    try testing.expectEqual(CloseCode.message_too_big, asm_.push(.{ .fin = true, .opcode = .text, .payload = "toolong" }).fail);
    // new data frame mid-fragment
    _ = asm_.push(.{ .fin = false, .opcode = .text, .payload = "ab" });
    try testing.expectEqual(CloseCode.protocol_error, asm_.push(.{ .fin = true, .opcode = .text, .payload = "cd" }).fail);
}
