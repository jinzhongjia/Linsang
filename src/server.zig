//! `std.Io.net` listen/accept loop with one `std.Io.Group` task per connection.

const std = @import("std");
const connection = @import("connection.zig");

const Allocator = std.mem.Allocator;
const Config = connection.Config;
const NetServer = std.Io.net.Server;

pub const Server = struct {
    gpa: Allocator,
    config: Config,
    shutdown: Shutdown = .{},

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
        self.shutdown.stopping = false;
        return .{
            .io = io,
            .address = listener.socket.address,
            .server = self,
            .future = try io.concurrent(runBound, .{ self, io, listener }),
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
            if (self.shutdown.isStopping(io)) {
                stream.close(io);
                return;
            }
            if (active.fetchAdd(1, .monotonic) >= self.config.max_connections) {
                _ = active.fetchSub(1, .monotonic);
                defer stream.close(io);
                try rejectOverloaded(io, stream, self.config.tls != null);
                continue;
            }
            connections.concurrent(io, serveLimitedConnection, .{
                io,
                stream,
                self,
                &active,
            }) catch {
                _ = active.fetchSub(1, .monotonic);
                stream.close(io);
            };
        }
    }
};

/// Stopping does not rely on cancelation alone. Zig 0.17.0 can drop a pending
/// cancelation (stack-capturing allocators unwind through a cancelable lock
/// and discard `error.Canceled`), and void callbacks cannot propagate one.
/// `Running.stop` therefore also shuts down every active socket and wakes the
/// accept loop, which then sees `stopping`.
const Shutdown = struct {
    mutex: std.Io.Mutex = .init,
    stopping: bool = false,
    streams: std.DoublyLinkedList = .{},

    const Entry = struct {
        node: std.DoublyLinkedList.Node = .{},
        stream: std.Io.net.Stream,
    };

    fn isStopping(self: *Shutdown, io: std.Io) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.stopping;
    }

    /// Returns false once stopping; the caller must not serve the stream.
    fn register(self: *Shutdown, io: std.Io, entry: *Entry) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.stopping) return false;
        self.streams.append(&entry.node);
        return true;
    }

    /// Must run before the stream is closed, so a reused descriptor is never
    /// shut down by `begin`.
    fn unregister(self: *Shutdown, io: std.Io, entry: *Entry) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.streams.remove(&entry.node);
    }

    fn begin(self: *Shutdown, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.stopping = true;
        var it = self.streams.first;
        while (it) |node| : (it = node.next) {
            const entry: *Entry = @fieldParentPtr("node", node);
            entry.stream.shutdown(io, .both) catch {};
        }
    }
};

/// Answer an over-limit client without serving it. Cancelation is reported
/// rather than swallowed so the accept loop still stops.
fn rejectOverloaded(io: std.Io, stream: std.Io.net.Stream, tls: bool) std.Io.Cancelable!void {
    if (!tls) {
        var buffer: [128]u8 = undefined;
        var writer = stream.writer(io, &buffer);
        writer.interface.writeAll(
            "HTTP/1.1 503 Service Unavailable\r\n" ++
                "Content-Length: 0\r\nConnection: close\r\n\r\n",
        ) catch {};
        writer.interface.flush() catch {};
        if (writer.err) |err| if (err == error.Canceled) return error.Canceled;
    }
    stream.shutdown(io, .send) catch |err| if (err == error.Canceled) return error.Canceled;
    // ponytail: 1 ms drain avoids TCP RST; use a bounded reject group
    // only if overload-response throughput matters.
    var discard: [1024]u8 = undefined;
    _ = stream.socket.receiveTimeout(io, &discard, .{ .duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(1),
    } }) catch |err| if (err == error.Canceled) return error.Canceled;
}

pub const Running = struct {
    io: std.Io,
    /// The actual listener address, including the selected port when configured
    /// with port zero.
    address: std.Io.net.IpAddress,
    server: *Server,
    future: std.Io.Future(anyerror!void),

    /// Stop accepting, cancel active connections, and wait for their cleanup.
    pub fn stop(self: *Running) !void {
        self.requestStop();
        self.future.cancel(self.io) catch |err| switch (err) {
            error.Canceled => {},
            else => return err,
        };
    }

    pub fn wait(self: *Running) !void {
        try self.future.await(self.io);
    }

    /// Shut down active sockets and wake the accept loop, independent of
    /// cancelation. The caller's own pending cancelation is left untouched.
    fn requestStop(self: *Running) void {
        const protection = self.io.swapCancelProtection(.blocked);
        defer _ = self.io.swapCancelProtection(protection);
        self.server.shutdown.begin(self.io);
        var target = self.address;
        switch (target) {
            .ip4 => |ip4| if (std.mem.allEqual(u8, &ip4.bytes, 0)) {
                target = .{ .ip4 = .loopback(ip4.port) };
            },
            .ip6 => |ip6| if (std.mem.allEqual(u8, &ip6.bytes, 0)) {
                target = .{ .ip6 = .loopback(ip6.port) };
            },
        }
        const wake = target.connect(self.io, .{ .mode = .stream }) catch return;
        wake.close(self.io);
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
    server: *Server,
    active: *std.atomic.Value(usize),
) std.Io.Cancelable!void {
    defer _ = active.fetchSub(1, .monotonic);
    var entry: Shutdown.Entry = .{ .stream = stream };
    defer stream.close(io);
    if (!server.shutdown.register(io, &entry)) return;
    defer server.shutdown.unregister(io, &entry);
    connection.handleWithoutClose(io, stream, server.gpa, &server.config) catch |err| {
        if (err == error.Canceled) return error.Canceled;
    };
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
        const n = (try client.readWithControl(io, &parts, &.{})).data_len;
        if (n == 0) break;
        len += n;
    }
    try testing.expect(std.mem.startsWith(u8, response[0..len], "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, response[0..len], "you asked for /road") != null);
    try group.await(io);
}

test "start exposes the bound address and running server stops cleanly" {
    // Async may legally run inline; the listener and deadline races must not.
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .nothing });
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
    const received = (try client.readWithControl(io, &parts, &.{})).data_len;
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
    const received = (try second.readWithControl(io, &parts, &.{})).data_len;
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
        const n = (try client.readWithControl(io, &parts, &.{})).data_len;
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

fn upgradeHandler(_: *const http.Request, _: *http.Response, _: ?*anyopaque) connection.Action {
    return .upgrade;
}

/// Swallows cancelation the way a void callback has to, without `recancel`.
fn swallowingMessageHandler(conn: *connection.Connection, _: @import("websocket.zig").Message, _: ?*anyopaque) void {
    std.Io.sleep(conn.io, .fromMilliseconds(300), .awake) catch {};
}

fn writeAllTo(stream: std.Io.net.Stream, io: std.Io, bytes: []const u8) !void {
    var buffer: [256]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

/// Keeps a WebSocket busy with masked pings until the server goes away.
fn pingUntilClosed(stream: std.Io.net.Stream, io: std.Io) void {
    for (0..200) |_| {
        writeAllTo(stream, io, "\x89\x80\x01\x02\x03\x04") catch return;
        std.Io.sleep(io, .fromMilliseconds(25), .awake) catch return;
    }
}

test "stop finishes while a busy WebSocket handler swallows cancelation" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(testing.allocator, .{
        .address = "127.0.0.1",
        .port = 0,
        .on_request = upgradeHandler,
        .on_ws_message = swallowingMessageHandler,
        .ws_idle_timeout = .fromSeconds(2),
    });
    var running = try server.start(io);
    var stopped = false;
    defer if (!stopped) running.stop() catch {};

    const client = try running.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAllTo(client, io, "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n" ++
        "\x81\x82\x01\x02\x03\x04\x49\x6b");
    var pinger = try io.concurrent(pingUntilClosed, .{ client, io });
    defer pinger.await(io);
    // Let the handler start sleeping, so stop's cancelation lands in it.
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);

    const started = std.Io.Timestamp.now(io, .awake);
    try running.stop();
    stopped = true;
    const elapsed = started.durationTo(std.Io.Timestamp.now(io, .awake));
    // Pings outlive the idle timeout; only shutting the socket ends it early.
    try testing.expect(elapsed.toMilliseconds() < 1000);
}

const AwaitRace = union(enum) {
    done: anyerror!void,
    timeout: std.Io.Cancelable!void,
};

fn awaitRunning(running: *Running) anyerror!void {
    return running.future.await(running.io);
}

test "stop wakes an accept loop that lost its cancelation" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(testing.allocator, .{
        .address = "0.0.0.0",
        .port = 0,
        .on_request = okHandler,
    });
    var running = try server.start(io);

    // No cancelation at all: the stop flag and wake-up connection must end
    // the accept loop. The future is awaited here instead of by `stop`.
    running.requestStop();
    var results: [2]AwaitRace = undefined;
    var select = std.Io.Select(AwaitRace).init(io, &results);
    defer select.cancelDiscard();
    try select.concurrent(.done, awaitRunning, .{&running});
    try select.concurrent(.timeout, std.Io.sleep, .{ io, std.Io.Duration.fromSeconds(2), .awake });
    switch (try select.await()) {
        .done => |result| try result,
        .timeout => {
            // Wake the loop ourselves so the awaiting task finishes cleanly.
            const loopback: std.Io.net.IpAddress = .{ .ip4 = .loopback(running.address.getPort()) };
            if (loopback.connect(io, .{ .mode = .stream })) |client| client.close(io) else |_| {}
            while (true) switch (try select.await()) {
                .done => break,
                .timeout => {},
            };
            return error.Timeout;
        },
    }
}

fn rejectAfterCancel(io: std.Io, stream: std.Io.net.Stream) std.Io.Cancelable!void {
    std.Io.sleep(io, .fromSeconds(10), .awake) catch io.recancel();
    return rejectOverloaded(io, stream, false);
}

test "rejecting an overloaded client reports cancelation" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const bind_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind_address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const peer_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(listener.socket.address.getPort()) };
    const client = try peer_address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const accepted = try listener.accept(io);
    defer accepted.close(io);

    var rejecting = try io.concurrent(rejectAfterCancel, .{ io, accepted });
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    try testing.expectError(error.Canceled, rejecting.cancel(io));
}
