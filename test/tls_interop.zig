//! TLS interop harness: RSA/ECDSA × TLS 1.2/1.3 × real clients.
//!
//! Clients:
//! * curl on every OS (Schannel on Windows, the system TLS stack)
//! * openssl s_client on POSIX only — Windows does not ship OpenSSL
//!
//! Certificates are fixtures so Windows does not need openssl for keygen.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const TlsVersion = enum { @"1.2", @"1.3" };
const CertFiles = struct { cert: []const u8, key: []const u8 };

const http_request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const command_timeout: Io.Timeout = .{ .duration = .{
    .clock = .awake,
    .raw = .fromSeconds(15),
} };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 6) {
        std.debug.print("usage: {s} SERVER RSA_CERT RSA_KEY ECDSA_CERT ECDSA_KEY\n", .{args[0]});
        return error.InvalidArguments;
    }

    var threaded = std.Io.Threaded.init(init.gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = init.gpa;
    const arena = init.arena.allocator();

    const server_path = try Io.Dir.cwd().realPathFileAlloc(io, args[1], arena);
    const pairs = [_]CertFiles{
        .{
            .cert = try Io.Dir.cwd().realPathFileAlloc(io, args[2], arena),
            .key = try Io.Dir.cwd().realPathFileAlloc(io, args[3], arena),
        },
        .{
            .cert = try Io.Dir.cwd().realPathFileAlloc(io, args[4], arena),
            .key = try Io.Dir.cwd().realPathFileAlloc(io, args[5], arena),
        },
    };

    try requireCommand(gpa, io, &.{ "curl", "--version" });
    if (builtin.os.tag != .windows) try requireCommand(gpa, io, &.{ "openssl", "version" });

    var curl_tls13 = true;
    for (pairs) |files| {
        for ([_]TlsVersion{ .@"1.2", .@"1.3" }) |version| {
            if (version != .@"1.3" or curl_tls13) {
                runCurl(gpa, io, server_path, files, version) catch |err| switch (err) {
                    error.CurlTlsNotBuiltIn => {
                        curl_tls13 = false;
                        std.debug.print("curl has no TLS 1.3 support; skipping remaining curl TLS 1.3 cases\n", .{});
                    },
                    else => |e| return e,
                };
            }
            if (builtin.os.tag != .windows) try runOpenssl(gpa, io, server_path, files, version);
        }
    }

    if (builtin.os.tag == .windows) {
        std.debug.print("TLS interop: RSA/ECDSA x TLS 1.2/1.3 x curl/Schannel OK\n", .{});
    } else {
        std.debug.print("TLS interop: RSA/ECDSA x TLS 1.2/1.3 x curl/OpenSSL OK\n", .{});
    }
}

fn requireCommand(gpa: Allocator, io: Io, argv: []const []const u8) !void {
    const result = std.process.run(gpa, io, .{
        .argv = argv,
        .create_no_window = true,
        .timeout = command_timeout,
    }) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("missing command on PATH: {s}\n", .{argv[0]});
            return error.MissingCommand;
        },
        else => |e| return e,
    };
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    if (nonzero(result.term)) {
        dump("stderr", result.stderr);
        std.debug.print("{s} failed\n", .{argv[0]});
        return error.CommandFailed;
    }
}

fn startServer(io: Io, server_path: []const u8, files: CertFiles) !std.process.Child {
    return std.process.spawn(io, .{
        .argv = &.{ server_path, files.cert, files.key },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
        .create_no_window = true,
    }) catch |err| {
        std.debug.print("failed to spawn {s}: {s}\n", .{ server_path, @errorName(err) });
        return err;
    };
}

fn readPort(io: Io, child: *std.process.Child) !u16 {
    var buf: [64]u8 = undefined;
    var reader = child.stdout.?.readerStreaming(io, &buf);
    const line = reader.interface.takeDelimiterExclusive('\n') catch {
        return error.ServerDidNotStart;
    };
    return std.fmt.parseInt(u16, std.mem.trim(u8, line, " \t\r"), 10) catch error.ServerDidNotStart;
}

fn runCurl(
    gpa: Allocator,
    io: Io,
    server_path: []const u8,
    files: CertFiles,
    version: TlsVersion,
) !void {
    var child = try startServer(io, server_path, files);
    defer child.kill(io);
    const port = try readPort(io, &child);

    var url_buf: [64]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{port}) catch unreachable;
    var resolve_buf: [64]u8 = undefined;
    const resolve = std.fmt.bufPrint(&resolve_buf, "localhost:{d}:127.0.0.1", .{port}) catch unreachable;

    const result = try std.process.run(gpa, io, .{
        .argv = switch (version) {
            .@"1.2" => &.{
                "curl",              "--silent",  "--show-error", "--fail",    "--insecure",
                "--http1.1",         "--noproxy", "*",            "--resolve", resolve,
                "--connect-timeout", "5",         "--max-time",   "10",        "--tlsv1.2",
                "--tls-max",         "1.2",       url,
            },
            .@"1.3" => &.{
                "curl",              "--silent",  "--show-error", "--fail",    "--insecure",
                "--http1.1",         "--noproxy", "*",            "--resolve", resolve,
                "--connect-timeout", "5",         "--max-time",   "10",        "--tlsv1.3",
                "--tls-max",         "1.3",       url,
            },
        },
        .create_no_window = true,
        .timeout = command_timeout,
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    if (nonzero(result.term) or !std.mem.eql(u8, result.stdout, "interop ok")) {
        const not_built_in = switch (result.term) {
            .exited => |code| code == 4,
            else => false,
        };
        if (version == .@"1.3" and not_built_in) return error.CurlTlsNotBuiltIn;
        std.debug.print("curl TLS {s} failed with certificate {s}\n", .{ @tagName(version), files.cert });
        dump("curl stdout", result.stdout);
        dump("curl stderr", result.stderr);
        return error.CurlFailed;
    }
    _ = child.wait(io) catch {};
}

fn runOpenssl(
    gpa: Allocator,
    io: Io,
    server_path: []const u8,
    files: CertFiles,
    version: TlsVersion,
) !void {
    var child = try startServer(io, server_path, files);
    defer child.kill(io);
    const port = try readPort(io, &child);

    var connect_buf: [32]u8 = undefined;
    const connect = std.fmt.bufPrint(&connect_buf, "127.0.0.1:{d}", .{port}) catch unreachable;
    const tls_arg = switch (version) {
        .@"1.2" => "-tls1_2",
        .@"1.3" => "-tls1_3",
    };

    var client = try std.process.spawn(io, .{
        .argv = &.{
            "openssl",  "s_client", "-quiet",      "-ign_eof",  tls_arg,
            "-connect", connect,    "-servername", "localhost",
        },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
        .create_no_window = true,
    });
    defer client.kill(io);

    {
        var buf: [128]u8 = undefined;
        var writer = client.stdin.?.writerStreaming(io, &buf);
        writer.interface.writeAll(http_request) catch {};
        writer.interface.flush() catch {};
    }
    if (client.stdin) |stdin| {
        stdin.close(io);
        client.stdin = null;
    }

    var multi_buf: Io.File.MultiReader.Buffer(2) = undefined;
    var multi: Io.File.MultiReader = undefined;
    multi.init(gpa, io, multi_buf.toStreams(), &.{ client.stdout.?, client.stderr.? });
    defer multi.deinit();
    multi.fillRemaining(command_timeout) catch {};
    const stdout = try multi.toOwnedSlice(0);
    defer gpa.free(stdout);
    const stderr = try multi.toOwnedSlice(1);
    defer gpa.free(stderr);
    _ = client.wait(io) catch {};

    if (std.mem.indexOf(u8, stdout, "interop ok") == null) {
        std.debug.print("openssl s_client TLS {s} failed with certificate {s}\n", .{
            @tagName(version),
            files.cert,
        });
        dump("s_client stdout", stdout);
        dump("s_client stderr", stderr);
        return error.OpenSslFailed;
    }
    _ = child.wait(io) catch {};
}

fn nonzero(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code != 0,
        else => true,
    };
}

fn dump(label: []const u8, data: []const u8) void {
    if (data.len == 0) return;
    const slice = data[0..@min(data.len, 4096)];
    std.debug.print("{s}:\n{s}\n", .{ label, slice });
}
