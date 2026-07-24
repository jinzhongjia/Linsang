//! `std.Io.net` listen/accept loop with one `std.Io.Group` task per connection.

const std = @import("std");
const connection = @import("connection.zig");

const Allocator = std.mem.Allocator;
const Config = connection.Config;
const NetServer = std.Io.net.Server;

pub const Server = struct {
    gpa: Allocator,
    config: Config,

    pub fn init(gpa: Allocator, config: Config) Server {
        return .{ .gpa = gpa, .config = config };
    }

    pub fn listen(self: *const Server, io: std.Io) !NetServer {
        const address = try std.Io.net.IpAddress.parse(self.config.address, self.config.port);
        return address.listen(io, .{
            .kernel_backlog = self.config.backlog,
            .reuse_address = true,
        });
    }

    pub fn run(self: *Server, io: std.Io) !void {
        var listener = try self.listen(io);
        defer listener.deinit(io);

        var connections: std.Io.Group = .init;
        defer connections.cancel(io);
        while (true) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.ConnectionAborted => continue,
                else => return err,
            };
            connections.async(io, serveConnection, .{
                io,
                stream,
                self.gpa,
                &self.config,
            });
        }
    }
};

fn serveConnection(
    io: std.Io,
    stream: std.Io.net.Stream,
    gpa: Allocator,
    config: *const Config,
) std.Io.Cancelable!void {
    connection.handle(io, stream, gpa, config) catch |err| {
        if (err == error.Canceled) return error.Canceled;
    };
}

const http = @import("http.zig");
const testing = std.testing;

fn okHandler(req: *const http.Request, res: *http.Response, _: ?*anyopaque) connection.Action {
    res.print("you asked for {s}", .{req.path}) catch {};
    return .respond;
}

fn acceptOne(
    io: std.Io,
    listener: *NetServer,
    config: *const Config,
) std.Io.Cancelable!void {
    const stream = listener.accept(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    connection.handle(io, stream, testing.allocator, config) catch |err| {
        if (err == error.Canceled) return error.Canceled;
    };
}

test "listen and serve HTTP over std.Io.net TCP" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.init(testing.allocator, .{
        .address = "127.0.0.1",
        .port = 0,
        .on_request = okHandler,
    });
    var listener = try server.listen(io);
    defer listener.deinit(io);
    var group: std.Io.Group = .init;
    group.async(io, acceptOne, .{ io, &listener, &server.config });

    const address: std.Io.net.IpAddress = .{
        .ip4 = .loopback(listener.socket.address.getPort()),
    };
    const client = try address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    var write_buffer: [128]u8 = undefined;
    var writer = client.writer(io, &write_buffer);
    try writer.interface.writeAll("GET /road HTTP/1.1\r\nConnection: close\r\n\r\n");
    try writer.interface.flush();

    var response: [512]u8 = undefined;
    var len: usize = 0;
    while (true) {
        var parts = [1][]u8{response[len..]};
        const n = try io.vtable.netRead(io.userdata, client.socket.handle, &parts);
        if (n == 0) break;
        len += n;
    }
    try testing.expect(std.mem.startsWith(u8, response[0..len], "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, response[0..len], "you asked for /road") != null);
    try group.await(io);
}
