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

    pub fn start(self: *Server, io: std.Io) Running {
        return .{
            .io = io,
            .future = io.async(runAny, .{ self, io }),
        };
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

pub const Running = struct {
    io: std.Io,
    future: std.Io.Future(anyerror!void),

    /// Stop accepting, cancel active connections, and wait for their cleanup.
    pub fn stop(self: *Running) !void {
        self.future.cancel(self.io) catch |err| switch (err) {
            error.Canceled => {},
            else => return err,
        };
    }

    pub fn wait(self: *Running) !void {
        try self.future.await(self.io);
    }
};

fn runAny(server: *Server, io: std.Io) anyerror!void {
    try server.run(io);
}

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
    try writer.interface.writeAll("GET /road HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
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

test "running server can be stopped cleanly" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(testing.allocator, .{
        .address = "127.0.0.1",
        .port = 0,
        .on_request = okHandler,
    });
    var running = server.start(io);
    try running.stop();
}

fn acceptMany(
    io: std.Io,
    listener: *NetServer,
    config: *const Config,
    count: usize,
) anyerror!void {
    var connections: std.Io.Group = .init;
    defer connections.cancel(io);
    for (0..count) |_| {
        const stream = try listener.accept(io);
        connections.async(io, serveConnection, .{
            io,
            stream,
            testing.allocator,
            config,
        });
    }
    try connections.await(io);
}

fn stressClient(io: std.Io, address: std.Io.net.IpAddress, id: usize) anyerror!void {
    const client = try address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    var write_buffer: [128]u8 = undefined;
    var writer = client.writer(io, &write_buffer);
    const slow = id % 4 == 0;
    if (slow)
        try writer.interface.writeAll("GET /slow")
    else
        try writer.interface.print(
            "GET /{d} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .{id},
        );
    try writer.interface.flush();

    var response: [512]u8 = undefined;
    var len: usize = 0;
    while (len < response.len) {
        var parts = [1][]u8{response[len..]};
        const n = try io.vtable.netRead(io.userdata, client.socket.handle, &parts);
        if (n == 0) break;
        len += n;
    }
    const expected = if (slow) "HTTP/1.1 408" else "HTTP/1.1 200 OK\r\n";
    if (!std.mem.startsWith(u8, response[0..len], expected))
        return error.BadResponse;
}

const StressResult = union(enum) {
    accept: anyerror!void,
    client: anyerror!void,
};

test "concurrent connections complete without leaks or deadlock" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const count = 16;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(testing.allocator, .{
        .address = "127.0.0.1",
        .port = 0,
        .request_timeout = .fromMilliseconds(250),
        .on_request = okHandler,
    });
    var listener = try server.listen(io);
    defer listener.deinit(io);
    const address: std.Io.net.IpAddress = .{
        .ip4 = .loopback(listener.socket.address.getPort()),
    };

    var results: [count + 1]StressResult = undefined;
    var select = std.Io.Select(StressResult).init(io, &results);
    defer select.cancelDiscard();
    select.async(.accept, acceptMany, .{ io, &listener, &server.config, count });
    for (0..count) |id|
        select.async(.client, stressClient, .{ io, address, id });

    for (0..count + 1) |_| switch (try select.await()) {
        .accept => |result| try result,
        .client => |result| try result,
    };
}

test "canceling active connections does not deadlock" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const count = 8;
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
    const address: std.Io.net.IpAddress = .{
        .ip4 = .loopback(listener.socket.address.getPort()),
    };
    var accepting = io.async(
        acceptMany,
        .{ io, &listener, &server.config, count },
    );

    var clients: [count]std.Io.net.Stream = undefined;
    var connected: usize = 0;
    defer for (clients[0..connected]) |client| client.close(io);
    while (connected < clients.len) : (connected += 1)
        clients[connected] = try address.connect(io, .{ .mode = .stream });
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);

    accepting.cancel(io) catch |err| switch (err) {
        error.Canceled => {},
        else => return err,
    };
}
