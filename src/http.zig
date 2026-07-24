//! HTTP/1.1 message types + incremental request parser + response builder.
//!
//! The parser is fed a growing byte buffer (the connection's read buffer) and
//! never allocates: parsed field are slices into that buffer, which the caller
//! keeps stable until the request is handled. No `std.http`.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Method
// ---------------------------------------------------------------------------

pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,

    pub fn fromSlice(s: []const u8) ?Method {
        inline for (@typeInfo(Method).@"enum".fields) |f| {
            if (std.mem.eql(u8, s, f.name)) return @enumFromInt(f.value);
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

pub const Status = enum(u16) {
    switching_protocols = 101,
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    request_timeout = 408,
    length_required = 411,
    payload_too_large = 413,
    uri_too_long = 414,
    expectation_failed = 417,
    upgrade_required = 426,
    request_header_fields_too_large = 431,
    internal_server_error = 500,
    not_implemented = 501,
    service_unavailable = 503,
    http_version_not_supported = 505,
    _,

    pub fn phrase(self: Status) []const u8 {
        return switch (self) {
            .switching_protocols => "Switching Protocols",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .no_content => "No Content",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .not_modified => "Not Modified",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .request_timeout => "Request Timeout",
            .length_required => "Length Required",
            .payload_too_large => "Payload Too Large",
            .uri_too_long => "URI Too Long",
            .expectation_failed => "Expectation Failed",
            .upgrade_required => "Upgrade Required",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .service_unavailable => "Service Unavailable",
            .http_version_not_supported => "HTTP Version Not Supported",
            else => "Unknown",
        };
    }
};

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

pub const Header = struct { name: []const u8, value: []const u8 };

pub const max_headers = 64;

pub const Request = struct {
    method: Method = .GET,
    /// Raw request-target ("/path?query").
    target: []const u8 = "",
    path: []const u8 = "",
    query: []const u8 = "",
    /// HTTP/1.<minor_version>.
    minor_version: u8 = 1,
    headers_buf: [max_headers]Header = undefined,
    headers_len: usize = 0,
    content_length: ?u64 = null,
    chunked: bool = false,
    keep_alive: bool = true,
    expect_continue: bool = false,
    /// Fully-received body (slice into the connection buffer, decoded if chunked).
    body: []const u8 = "",

    pub fn reset(self: *Request) void {
        self.* = .{};
    }

    pub fn headers(self: *const Request) []const Header {
        return self.headers_buf[0..self.headers_len];
    }

    /// Case-insensitive lookup; returns the last matching value.
    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        var i: usize = self.headers_len;
        while (i > 0) {
            i -= 1;
            if (std.ascii.eqlIgnoreCase(self.headers_buf[i].name, name))
                return self.headers_buf[i].value;
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Head parser
// ---------------------------------------------------------------------------

pub const HeadResult = union(enum) {
    /// The full head (through the terminating CRLF CRLF) is not yet in `buf`.
    need_more,
    /// Head parsed; the value is its byte length (where the body begins).
    done: usize,
    /// Reject the request with this status and close.
    fail: Status,
};

fn isTokenChar(c: u8) bool {
    return switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'a'...'z', 'A'...'Z' => true,
        else => false,
    };
}

fn isToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!isTokenChar(c)) return false;
    return true;
}

/// Parse request line + headers from the front of `buf`, filling `req`.
pub fn parseHead(req: *Request, buf: []const u8) HeadResult {
    const head_end = (std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return .need_more) + 4;
    var lines = std.mem.splitSequence(u8, buf[0 .. head_end - 2], "\r\n");

    // Request line.
    const request_line = lines.next() orelse return .{ .fail = .bad_request };
    switch (parseRequestLine(req, request_line)) {
        .ok => {},
        .fail => |s| return .{ .fail = s },
    }

    // Headers.
    req.headers_len = 0;
    while (lines.next()) |line| {
        if (line.len == 0) break; // final blank line handled by split bounds
        // Obsolete line folding (continuation) is rejected.
        if (line[0] == ' ' or line[0] == '\t') return .{ .fail = .bad_request };
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return .{ .fail = .bad_request };
        const name = line[0..colon];
        if (!isToken(name)) return .{ .fail = .bad_request };
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (req.headers_len >= max_headers) return .{ .fail = .request_header_fields_too_large };
        req.headers_buf[req.headers_len] = .{ .name = name, .value = value };
        req.headers_len += 1;
    }

    switch (deriveBodyFraming(req)) {
        .ok => {},
        .fail => |s| return .{ .fail = s },
    }
    return .{ .done = head_end };
}

const LineResult = union(enum) { ok, fail: Status };

fn parseRequestLine(req: *Request, line: []const u8) LineResult {
    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse return .{ .fail = .bad_request };
    const method_str = line[0..sp1];
    const rest = line[sp1 + 1 ..];
    const sp2 = std.mem.lastIndexOfScalar(u8, rest, ' ') orelse return .{ .fail = .bad_request };
    const target = rest[0..sp2];
    const version = rest[sp2 + 1 ..];

    if (Method.fromSlice(method_str)) |m| {
        req.method = m;
    } else if (isToken(method_str)) {
        return .{ .fail = .not_implemented };
    } else {
        return .{ .fail = .bad_request };
    }

    if (target.len == 0) return .{ .fail = .bad_request };
    req.target = target;
    if (std.mem.indexOfScalar(u8, target, '?')) |q| {
        req.path = target[0..q];
        req.query = target[q + 1 ..];
    } else {
        req.path = target;
        req.query = "";
    }

    // Version: "HTTP/1.N".
    if (!std.mem.startsWith(u8, version, "HTTP/")) return .{ .fail = .bad_request };
    const ver = version["HTTP/".len..];
    if (ver.len != 3 or ver[1] != '.') return .{ .fail = .bad_request };
    if (!std.ascii.isDigit(ver[0]) or !std.ascii.isDigit(ver[2])) return .{ .fail = .bad_request };
    if (ver[0] != '1') return .{ .fail = .http_version_not_supported };
    req.minor_version = ver[2] - '0';
    return .ok;
}

fn deriveBodyFraming(req: *Request) LineResult {
    var host_count: usize = 0;
    for (req.headers()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "host")) {
            host_count += 1;
            if (header.value.len == 0) return .{ .fail = .bad_request };
        } else if (std.ascii.eqlIgnoreCase(header.name, "expect")) {
            if (!std.ascii.eqlIgnoreCase(header.value, "100-continue"))
                return .{ .fail = .expectation_failed };
            req.expect_continue = req.minor_version >= 1;
        }
    }
    if (host_count > 1 or (req.minor_version >= 1 and host_count != 1))
        return .{ .fail = .bad_request };

    // keep-alive default: 1.1 on, 1.0 off, adjusted by Connection.
    req.keep_alive = req.minor_version >= 1;
    if (req.header("connection")) |c| {
        if (headerHasToken(c, "close")) req.keep_alive = false;
        if (headerHasToken(c, "keep-alive")) req.keep_alive = true;
    }
    const te = req.header("transfer-encoding");
    const cl = req.header("content-length");
    if (te != null and cl != null) return .{ .fail = .bad_request }; // smuggling
    if (te) |t| {
        // Only "chunked" (as the final/only coding) is supported.
        const last = lastToken(t);
        if (std.ascii.eqlIgnoreCase(last, "chunked")) {
            req.chunked = true;
        } else {
            return .{ .fail = .not_implemented };
        }
    } else if (cl) |c| {
        req.content_length = parseContentLength(c) orelse return .{ .fail = .bad_request };
    }
    return .ok;
}

fn parseContentLength(s: []const u8) ?u64 {
    const t = std.mem.trim(u8, s, " \t");
    if (t.len == 0) return null;
    var n: u64 = 0;
    for (t) |c| {
        if (!std.ascii.isDigit(c)) return null;
        n = std.math.mul(u64, n, 10) catch return null;
        n = std.math.add(u64, n, c - '0') catch return null;
    }
    return n;
}

/// Does a comma-separated header field contain `token` (case-insensitive)?
fn headerHasToken(field: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, field, ',');
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

fn lastToken(field: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, field, ',');
    var last: []const u8 = "";
    while (it.next()) |part| last = std.mem.trim(u8, part, " \t");
    return last;
}

// ---------------------------------------------------------------------------
// Chunked transfer decoding
// ---------------------------------------------------------------------------

pub const ChunkResult = union(enum) {
    need_more,
    done: struct { consumed: usize, body_len: usize },
    fail: Status,
};

/// Decode a chunked body from `input` into `out`. `out` may alias `input`
/// (the write cursor never overtakes the read cursor, so forward copy is safe).
pub fn decodeChunked(input: []const u8, out: []u8) ChunkResult {
    var r: usize = 0;
    var w: usize = 0;
    while (true) {
        const nl = std.mem.indexOfPos(u8, input, r, "\r\n") orelse return .need_more;
        const size_line = input[r..nl];
        // Chunk extensions after ';' are ignored.
        const hex = if (std.mem.indexOfScalar(u8, size_line, ';')) |semi| size_line[0..semi] else size_line;
        const size = parseHexSize(hex) orelse return .{ .fail = .bad_request };
        r = nl + 2;

        if (size == 0) {
            // Last chunk: consume trailer lines until a blank line.
            while (true) {
                const t = std.mem.indexOfPos(u8, input, r, "\r\n") orelse return .need_more;
                if (t == r) return .{ .done = .{ .consumed = r + 2, .body_len = w } };
                r = t + 2;
            }
        }

        if (input.len < r + size + 2) return .need_more;
        if (w + size > out.len) return .{ .fail = .payload_too_large };
        std.mem.copyForwards(u8, out[w .. w + size], input[r .. r + size]);
        w += size;
        r += size;
        if (!std.mem.eql(u8, input[r .. r + 2], "\r\n")) return .{ .fail = .bad_request };
        r += 2;
    }
}

fn parseHexSize(hex: []const u8) ?u64 {
    if (hex.len == 0) return null;
    var n: u64 = 0;
    for (hex) |c| {
        const d = std.fmt.charToDigit(c, 16) catch return null;
        n = std.math.mul(u64, n, 16) catch return null;
        n += d;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Response builder
// ---------------------------------------------------------------------------

/// Buffers a response in memory, then serializes it with Content-Length.
/// Streaming/chunked responses are a later enhancement.
// ponytail: full-buffer response keeps the handler API trivial; add a streaming
// writer only when someone needs to send bodies too big to hold.
pub const Response = struct {
    gpa: Allocator,
    status: Status = .ok,
    header_lines: std.ArrayList(u8) = .empty,
    body_buf: std.ArrayList(u8) = .empty,

    pub fn init(gpa: Allocator) Response {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Response) void {
        self.header_lines.deinit(self.gpa);
        self.body_buf.deinit(self.gpa);
    }

    pub fn reset(self: *Response) void {
        self.status = .ok;
        self.header_lines.clearRetainingCapacity();
        self.body_buf.clearRetainingCapacity();
    }

    /// Add a header. Do not set Content-Length or Connection — those are emitted
    /// automatically by `serialize`.
    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !void {
        try self.header_lines.appendSlice(self.gpa, name);
        try self.header_lines.appendSlice(self.gpa, ": ");
        try self.header_lines.appendSlice(self.gpa, value);
        try self.header_lines.appendSlice(self.gpa, "\r\n");
    }

    pub fn write(self: *Response, bytes: []const u8) !void {
        try self.body_buf.appendSlice(self.gpa, bytes);
    }

    pub fn print(self: *Response, comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.allocPrint(self.gpa, fmt, args);
        defer self.gpa.free(s);
        try self.body_buf.appendSlice(self.gpa, s);
    }

    /// Emit the full response into `out`.
    pub fn serialize(self: *const Response, out: *std.ArrayList(u8), gpa: Allocator, keep_alive: bool) !void {
        try self.serializeImpl(out, gpa, keep_alive, true);
    }

    /// Emit response headers for a HEAD request, preserving the body length.
    pub fn serializeHead(self: *const Response, out: *std.ArrayList(u8), gpa: Allocator, keep_alive: bool) !void {
        try self.serializeImpl(out, gpa, keep_alive, false);
    }

    fn serializeImpl(self: *const Response, out: *std.ArrayList(u8), gpa: Allocator, keep_alive: bool, include_body: bool) !void {
        var line: [64]u8 = undefined;
        const status_code = @intFromEnum(self.status);
        const body_forbidden = status_code < 200 or self.status == .no_content or self.status == .not_modified;
        const status_line = std.fmt.bufPrint(&line, "HTTP/1.1 {d} {s}\r\n", .{
            status_code, self.status.phrase(),
        }) catch unreachable;
        try out.appendSlice(gpa, status_line);
        try out.appendSlice(gpa, self.header_lines.items);

        if (status_code >= 200 and self.status != .no_content) {
            const cl = std.fmt.bufPrint(&line, "Content-Length: {d}\r\n", .{self.body_buf.items.len}) catch unreachable;
            try out.appendSlice(gpa, cl);
        }
        try out.appendSlice(gpa, if (keep_alive) "Connection: keep-alive\r\n" else "Connection: close\r\n");
        try out.appendSlice(gpa, "\r\n");
        if (include_body and !body_forbidden) try out.appendSlice(gpa, self.body_buf.items);
    }
};

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn expectDone(r: HeadResult) usize {
    return switch (r) {
        .done => |n| n,
        else => std.debug.panic("expected done, got {any}", .{r}),
    };
}

test "Method.fromSlice" {
    try testing.expectEqual(Method.GET, Method.fromSlice("GET").?);
    try testing.expectEqual(Method.DELETE, Method.fromSlice("DELETE").?);
    try testing.expect(Method.fromSlice("get") == null);
    try testing.expect(Method.fromSlice("BREW") == null);
}

test "parse minimal GET" {
    var req: Request = .{};
    const raw = "GET /hello?x=1 HTTP/1.1\r\nHost: a\r\n\r\n";
    const n = expectDone(parseHead(&req, raw));
    try testing.expectEqual(raw.len, n);
    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/hello?x=1", req.target);
    try testing.expectEqualStrings("/hello", req.path);
    try testing.expectEqualStrings("x=1", req.query);
    try testing.expectEqual(@as(u8, 1), req.minor_version);
    try testing.expect(req.keep_alive);
    try testing.expectEqualStrings("a", req.header("host").?);
    try testing.expectEqualStrings("a", req.header("HOST").?);
}

test "need_more on partial input" {
    var req: Request = .{};
    try testing.expect(parseHead(&req, "GET / HTTP/1.1\r\nHost: a") == .need_more);
    try testing.expect(parseHead(&req, "") == .need_more);
    try testing.expect(parseHead(&req, "GET / HTTP/1.1\r\n\r") == .need_more);
}

test "header value OWS is trimmed; multiple headers" {
    var req: Request = .{};
    const raw = "GET / HTTP/1.1\r\nHost:   example.com  \r\nX-A:1\r\nX-B:\t2\t\r\n\r\n";
    _ = expectDone(parseHead(&req, raw));
    try testing.expectEqual(@as(usize, 3), req.headers_len);
    try testing.expectEqualStrings("example.com", req.header("host").?);
    try testing.expectEqualStrings("1", req.header("x-a").?);
    try testing.expectEqualStrings("2", req.header("x-b").?);
}

test "keep-alive rules" {
    var req: Request = .{};
    _ = expectDone(parseHead(&req, "GET / HTTP/1.0\r\n\r\n"));
    try testing.expect(!req.keep_alive);

    req.reset();
    _ = expectDone(parseHead(&req, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"));
    try testing.expect(req.keep_alive);

    req.reset();
    _ = expectDone(parseHead(&req, "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"));
    try testing.expect(!req.keep_alive);
}

test "content-length parsed" {
    var req: Request = .{};
    _ = expectDone(parseHead(&req, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 42\r\n\r\n"));
    try testing.expectEqual(@as(u64, 42), req.content_length.?);
    try testing.expect(!req.chunked);
}

test "chunked flagged" {
    var req: Request = .{};
    _ = expectDone(parseHead(&req, "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"));
    try testing.expect(req.chunked);
    try testing.expect(req.content_length == null);
}

test "Host and Expect requirements" {
    var req: Request = .{};
    _ = expectDone(parseHead(&req, "POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n"));
    try testing.expect(req.expect_continue);
    req.reset();
    try testing.expectEqual(Status.expectation_failed, parseHead(&req, "GET / HTTP/1.1\r\nHost: a\r\nExpect: magic\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.bad_request, parseHead(&req, "GET / HTTP/1.1\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.bad_request, parseHead(&req, "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n").fail);
    req.reset();
    _ = expectDone(parseHead(&req, "POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n"));
    try testing.expect(!req.expect_continue);
}

test "rejects: bad version, bad method chars, folding, smuggling, bad CL" {
    var req: Request = .{};
    try testing.expectEqual(Status.http_version_not_supported, parseHead(&req, "GET / HTTP/2.0\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.bad_request, parseHead(&req, "GET / HTTP/1\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.not_implemented, parseHead(&req, "FOOBAR / HTTP/1.1\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.bad_request, parseHead(&req, "GE(T) / HTTP/1.1\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.bad_request, parseHead(&req, "GET / HTTP/1.1\r\n bad: fold\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.bad_request, parseHead(&req, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.bad_request, parseHead(&req, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1x\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.not_implemented, parseHead(&req, "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n").fail);
    req.reset();
    try testing.expectEqual(Status.bad_request, parseHead(&req, "GET  HTTP/1.1\r\n\r\n").fail);
}

test "too many headers" {
    var req: Request = .{};
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, "GET / HTTP/1.1\r\n");
    var i: usize = 0;
    while (i < max_headers + 1) : (i += 1)
        try buf.print(testing.allocator, "X-{d}: v\r\n", .{i});
    try buf.appendSlice(testing.allocator, "\r\n");
    try testing.expectEqual(Status.request_header_fields_too_large, parseHead(&req, buf.items).fail);
}

test "decodeChunked basic" {
    var out: [64]u8 = undefined;
    const input = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    const r = decodeChunked(input, &out);
    try testing.expectEqual(input.len, r.done.consumed);
    try testing.expectEqual(@as(usize, 9), r.done.body_len);
    try testing.expectEqualStrings("Wikipedia", out[0..9]);
}

test "decodeChunked with extension and trailers" {
    var out: [64]u8 = undefined;
    const input = "3;name=value\r\nabc\r\n0\r\nX-Trailer: yes\r\n\r\n";
    const r = decodeChunked(input, &out);
    try testing.expectEqual(input.len, r.done.consumed);
    try testing.expectEqualStrings("abc", out[0..r.done.body_len]);
}

test "decodeChunked need_more and errors" {
    var out: [64]u8 = undefined;
    try testing.expect(decodeChunked("4\r\nWi", &out) == .need_more);
    try testing.expect(decodeChunked("4\r\nWiki\r\n", &out) == .need_more); // missing terminator
    try testing.expectEqual(Status.bad_request, decodeChunked("zz\r\n", &out).fail);
    var tiny: [2]u8 = undefined;
    try testing.expectEqual(Status.payload_too_large, decodeChunked("4\r\nWiki\r\n0\r\n\r\n", &tiny).fail);
}

test "decodeChunked in-place aliasing" {
    var buf: [64]u8 = undefined;
    const input = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    @memcpy(buf[0..input.len], input);
    const r = decodeChunked(buf[0..input.len], buf[0..input.len]);
    try testing.expectEqualStrings("Wikipedia", buf[0..r.done.body_len]);
}

test "Response.serialize with body and headers" {
    const gpa = testing.allocator;
    var res = Response.init(gpa);
    defer res.deinit();
    res.status = .ok;
    try res.setHeader("Content-Type", "text/plain");
    try res.write("hi");

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try res.serialize(&out, gpa, true);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nhi",
        out.items,
    );
}

test "Response.serialize close + empty body" {
    const gpa = testing.allocator;
    var res = Response.init(gpa);
    defer res.deinit();
    res.status = .not_found;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try res.serialize(&out, gpa, false);
    try testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        out.items,
    );
}

test "Response.serializeHead preserves length without body" {
    const gpa = testing.allocator;
    var res = Response.init(gpa);
    defer res.deinit();
    try res.write("hello");

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try res.serializeHead(&out, gpa, false);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        out.items,
    );
}

test "Response omits bodies forbidden by status" {
    const gpa = testing.allocator;
    var res = Response.init(gpa);
    defer res.deinit();
    try res.write("hello");

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    res.status = .no_content;
    try res.serialize(&out, gpa, true);
    try testing.expectEqualStrings(
        "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n",
        out.items,
    );

    out.clearRetainingCapacity();
    res.status = .not_modified;
    try res.serialize(&out, gpa, false);
    try testing.expectEqualStrings(
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        out.items,
    );
}
