const std = @import("std");
const linsang = @import("Linsang");

fn onRequest(
    _: *const linsang.Request,
    response: *linsang.Response,
    _: ?*anyopaque,
) linsang.Action {
    response.setHeader("Content-Type", "text/plain") catch {};
    response.write("interop ok") catch {};
    return .respond;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) {
        std.debug.print("usage: {s} CERT KEY\n", .{args[0]});
        return error.InvalidArguments;
    }

    var threaded = std.Io.Threaded.init(init.gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var auth = try linsang.tls.CertKeyPair.fromFilePath(
        init.gpa,
        io,
        std.Io.Dir.cwd(),
        args[1],
        args[2],
    );
    defer auth.deinit(init.gpa);

    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var stdout_buffer: [64]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    try stdout_writer.interface.print(
        "{d}\n",
        .{listener.socket.address.getPort()},
    );
    try stdout_writer.interface.flush();

    const stream = try listener.accept(io);
    const config: linsang.Config = .{
        .request_timeout = .fromSeconds(10),
        .keep_alive_timeout = .fromSeconds(2),
        .tls = .{ .auth = &auth },
        .on_request = onRequest,
    };
    linsang.connection.handle(io, stream, init.gpa, &config) catch |err| switch (err) {
        error.EndOfStream => {},
        else => |e| return e,
    };
}
