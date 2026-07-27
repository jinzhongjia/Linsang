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
        if (self.config.max_connections == 0) return error.InvalidConfiguration;
        const address = try std.Io.net.IpAddress.parse(self.config.address, self.config.port);
        return address.listen(io, .{
            .kernel_backlog = self.config.backlog,
            .reuse_address = true,
        });
    }

    /// Bind synchronously, then serve in a background task. `Running.address`
    /// contains the selected port before this function returns.
    pub fn start(self: *Server, io: std.Io) !Running {
        var listener = try self.listen(io);
        errdefer listener.deinit(io);
        return .{
            .io = io,
            .address = listener.socket.address,
            .future = io.async(runBound, .{ self, io, listener }),
        };
    }

    pub fn run(self: *Server, io: std.Io) !void {
        var listener = try self.listen(io);
        defer listener.deinit(io);
        try self.serve(io, &listener);
    }

    fn serve(self: *Server, io: std.Io, listener: *NetServer) !void {
        var connections: std.Io.Group = .init;
        defer connections.cancel(io);
        var active: std.atomic.Value(usize) = .init(0);
        while (true) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.ConnectionAborted => continue,
                else => return err,
            };
            if (active.fetchAdd(1, .monotonic) >= self.config.max_connections) {
                _ = active.fetchSub(1, .monotonic);
                if (self.config.tls == null) {
                    var buffer: [128]u8 = undefined;
                    var writer = stream.writer(io, &buffer);
                    writer.interface.writeAll(
                        "HTTP/1.1 503 Service Unavailable\r\n" ++
                            "Content-Length: 0\r\nConnection: close\r\n\r\n",
                    ) catch {};
                    writer.interface.flush() catch {};
                }
                stream.shutdown(io, .send) catch {};
                // ponytail: 1 ms drain avoids TCP RST; use a bounded reject group
                // only if overload-response throughput matters.
                var discard: [1024]u8 = undefined;
                _ = stream.socket.receiveTimeout(io, &discard, .{ .duration = .{
                    .clock = .awake,
                    .raw = .fromMilliseconds(1),
                } }) catch {};
                stream.close(io);
                continue;
            }
            connections.async(io, serveLimitedConnection, .{
                io,
                stream,
                self.gpa,
                &self.config,
                &active,
            });
        }
    }
};

pub const Running = struct {
    io: std.Io,
    /// The actual listener address, including the selected port when configured
    /// with port zero.
    address: std.Io.net.IpAddress,
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

fn runBound(server: *Server, io: std.Io, bound_listener: NetServer) anyerror!void {
    var listener = bound_listener;
    defer listener.deinit(io);
    try server.serve(io, &listener);
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

fn serveLimitedConnection(
    io: std.Io,
    stream: std.Io.net.Stream,
    gpa: Allocator,
    config: *const Config,
    active: *std.atomic.Value(usize),
) std.Io.Cancelable!void {
    defer _ = active.fetchSub(1, .monotonic);
    try serveConnection(io, stream, gpa, config);
}

const http = @import("http.zig");
const testing = std.testing;

fn okHandler(req: *const http.Request, res: *http.Response, _: ?*anyopaque) connection.Action {
    res.print("you asked for {s}", .{req.path}) catch {};
    return .respond;
}

fn countHandler(_: *const http.Request, _: *http.Response, data: ?*anyopaque) connection.Action {
    const count: *std.atomic.Value(usize) = @ptrCast(@alignCast(data.?));
    _ = count.fetchAdd(1, .monotonic);
    return .respond;
}

fn waitForCount(io: std.Io, count: *const std.atomic.Value(usize), expected: usize) !void {
    for (0..100) |_| {
        if (count.load(.monotonic) == expected) return;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
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

test "start exposes the bound address and running server stops cleanly" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(testing.allocator, .{
        .address = "127.0.0.1",
        .port = 0,
        .on_request = okHandler,
    });
    var running = try server.start(io);
    try testing.expect(running.address.getPort() != 0);

    const client = try running.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    var write_buffer: [128]u8 = undefined;
    var writer = client.writer(io, &write_buffer);
    try writer.interface.writeAll(
        "GET /bound HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    try writer.interface.flush();
    var response: [512]u8 = undefined;
    var parts = [1][]u8{&response};
    const received = try io.vtable.netRead(io.userdata, client.socket.handle, &parts);
    try testing.expect(std.mem.indexOf(u8, response[0..received], "you asked for /bound") != null);
    try running.stop();
}

test "server enforces max connections" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var invalid = Server.init(testing.allocator, .{
        .max_connections = 0,
        .on_request = countHandler,
    });
    try testing.expectError(error.InvalidConfiguration, invalid.listen(io));
    var count: std.atomic.Value(usize) = .init(0);
    var server = Server.init(testing.allocator, .{
        .address = "127.0.0.1",
        .port = 0,
        .max_connections = 1,
        .on_request = countHandler,
        .user_data = &count,
    });
    var listener = try server.listen(io);
    defer listener.deinit(io);
    var serving = io.async(Server.serve, .{ &server, io, &listener });
    defer serving.cancel(io) catch {};
    const address: std.Io.net.IpAddress = .{
        .ip4 = .loopback(listener.socket.address.getPort()),
    };

    const first = try address.connect(io, .{ .mode = .stream });
    defer first.close(io);
    var first_buffer: [128]u8 = undefined;
    var first_writer = first.writer(io, &first_buffer);
    try first_writer.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try first_writer.interface.flush();
    try waitForCount(io, &count, 1);

    const second = try address.connect(io, .{ .mode = .stream });
    defer second.close(io);
    var second_buffer: [128]u8 = undefined;
    var second_writer = second.writer(io, &second_buffer);
    try second_writer.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    try second_writer.interface.flush();
    var response: [128]u8 = undefined;
    var parts = [1][]u8{&response};
    const received = try io.vtable.netRead(io.userdata, second.socket.handle, &parts);
    try testing.expect(std.mem.startsWith(
        u8,
        response[0..received],
        "HTTP/1.1 503 Service Unavailable\r\n",
    ));
    try testing.expectEqual(@as(usize, 1), count.load(.monotonic));

    try first.shutdown(io, .both);
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
