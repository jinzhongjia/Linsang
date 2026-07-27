//! Linsang — a small, embeddable HTTP/1.1 + WebSocket server library.
//!
//! No `std.http`, no third-party dependencies, no libc where the OS permits
//! (Linux/Windows). Low memory. See docs/DESIGN.md.

const std = @import("std");

pub const version = "0.1.0-dev";

pub const http = @import("http.zig");
pub const websocket = @import("websocket.zig");
pub const tls = @import("tls/root.zig");
pub const connection = @import("connection.zig");
pub const server = @import("server.zig");

pub const Config = connection.Config;
pub const TlsConfig = connection.TlsConfig;
pub const Connection = connection.Connection;
pub const WebSocketPeer = connection.WebSocketPeer;
pub const Action = connection.Action;
pub const StreamHandler = connection.StreamHandler;
pub const StaticFiles = connection.StaticFiles;
pub const Server = server.Server;

pub const Request = http.Request;
pub const Response = http.Response;
pub const Method = http.Method;
pub const Status = http.Status;

// Referencing each module in the test block forces `zig build test` to run
// that file's tests.
test {
    _ = http;
    _ = websocket;
    _ = tls;
    _ = connection;
    _ = server;
}

fn checkProtocolInput(input: []u8) !void {
    var request: http.Request = .{};
    switch (http.parseHead(&request, input)) {
        .done => |consumed| try std.testing.expect(consumed <= input.len),
        else => {},
    }

    var decoded: [512]u8 = undefined;
    switch (http.decodeChunked(input, &decoded)) {
        .done => |done| {
            try std.testing.expect(done.consumed <= input.len);
            try std.testing.expect(done.body_len <= input.len);
        },
        else => {},
    }

    switch (websocket.parseFrame(input, true)) {
        .done => |done| try std.testing.expect(done.consumed <= input.len),
        else => {},
    }
}

fn fuzzProtocolParsers(_: void, smith: *std.testing.Smith) !void {
    var bytes: [512]u8 = undefined;
    const len: usize = smith.slice(&bytes);
    try checkProtocolInput(bytes[0..len]);
}

fn smithSliceCorpus(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

test "protocol parsers tolerate arbitrary input" {
    const http_seed = smithSliceCorpus("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    const chunked_seed = smithSliceCorpus("4\r\nWiki\r\n0\r\n\r\n");
    const websocket_seed = smithSliceCorpus("\x81\x82\x01\x02\x03\x04Hi");
    try std.testing.fuzz({}, fuzzProtocolParsers, .{
        .corpus = &.{
            &http_seed,
            &chunked_seed,
            &websocket_seed,
        },
    });
}

test "protocol parsers tolerate 10K deterministic random inputs" {
    var prng = std.Random.DefaultPrng.init(0x4c_69_6e_73_61_6e_67);
    const random = prng.random();
    var bytes: [512]u8 = undefined;
    for (0..10_000) |_| {
        const len = random.intRangeAtMost(usize, 0, bytes.len);
        random.bytes(bytes[0..len]);
        try checkProtocolInput(bytes[0..len]);
    }
}
