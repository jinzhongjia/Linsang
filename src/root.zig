//! Linsang — a small, embeddable HTTP/1.1 + WebSocket server library.
//!
//! No `std.http`, no third-party dependencies, no libc where the OS permits
//! (Linux/Windows). Low memory. See docs/DESIGN.md.

const std = @import("std");

pub const version = "0.1.0-dev";

pub const socket = @import("socket.zig");
pub const poller = @import("poller.zig");
pub const http = @import("http.zig");
pub const websocket = @import("websocket.zig");
pub const connection = @import("connection.zig");
pub const server = @import("server.zig");

pub const Config = connection.Config;
pub const Connection = connection.Connection;
pub const Action = connection.Action;
pub const Server = server.Server;

pub const Request = http.Request;
pub const Response = http.Response;
pub const Method = http.Method;
pub const Status = http.Status;

// Referencing each module in the test block forces `zig build test` to run
// that file's tests.
test {
    _ = socket;
    _ = poller;
    _ = http;
    _ = websocket;
    _ = connection;
    _ = server;
}
