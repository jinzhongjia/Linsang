//! Demo standalone server: `zig build run`.
//! Serves a small HTML page over HTTP and echoes messages on the /ws WebSocket.

const std = @import("std");
const linsang = @import("Linsang");
const http = linsang.http;
const ws = linsang.websocket;

fn onRequest(req: *const http.Request, res: *http.Response, ud: ?*anyopaque) linsang.Action {
    _ = ud;
    if (std.mem.eql(u8, req.path, "/ws")) return .upgrade;

    res.status = .ok;
    res.setHeader("Content-Type", "text/html; charset=utf-8") catch {};
    res.print(
        \\<!doctype html><meta charset=utf-8><title>Linsang</title>
        \\<h1>Linsang {s}</h1><p>You requested <code>{s}</code></p>
        \\<p>Open a WebSocket to <code>/ws</code> for an echo server.</p>
    , .{ linsang.version, req.path }) catch {};
    return .respond;
}

fn onWsMessage(conn: *linsang.Connection, msg: ws.Message, ud: ?*anyopaque) void {
    _ = ud;
    conn.sendText(msg.data) catch {};
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    // ponytail: std.Io.Evented 0.16 has no net vtable yet; switch runtimes when
    // the stdlib implementation lands.
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();

    var server = linsang.Server.init(gpa, .{
        .address = "0.0.0.0",
        .port = 8080,
        .on_request = onRequest,
        .on_ws_message = onWsMessage,
    });
    std.log.info("Linsang {s} listening on http://0.0.0.0:8080  (WebSocket echo at /ws)", .{linsang.version});
    try server.run(threaded.io());
}
