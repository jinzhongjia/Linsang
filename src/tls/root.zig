//! TLS server transport.
//!
//! Derived from ianic/tls.zig commit d633a0f276294f84836ab9a81ba79b805790b2c8
//! (MIT); see LICENSE in this directory.

const std = @import("std");

pub const input_buffer_len = @import("cipher.zig").max_ciphertext_record_len;
pub const output_buffer_len = @import("cipher.zig").max_encrypted_record_len;

pub const Connection = @import("connection.zig").Connection;
pub const CipherSuite = @import("cipher.zig").CipherSuite;
pub const cipher_suites = @import("cipher.zig").cipher_suites;
pub const PrivateKey = @import("PrivateKey.zig");

const common = @import("handshake_common.zig");
pub const CertKeyPair = common.CertKeyPair;
pub const cert = common.cert;

pub const ServerOptions = @import("handshake_server.zig").Options;

pub fn server(input: *std.Io.Reader, output: *std.Io.Writer, options: ServerOptions) !Connection {
    var handshake: @import("handshake_server.zig").Handshake = .{
        .input = input,
        .output = output,
    };
    return .{
        .cipher = try handshake.handshake(options),
        .input = input,
        .output = output,
        .alpn_protocol = handshake.alpn_protocol,
    };
}

test {
    _ = @import("protocol.zig");
    _ = @import("record.zig");
    _ = @import("cipher.zig");
    _ = @import("transcript.zig");
    _ = @import("PrivateKey.zig");
    _ = @import("handshake_common.zig");
    _ = @import("handshake_server.zig");
    _ = @import("connection.zig");
}
