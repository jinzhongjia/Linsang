const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const Io = std.Io;
const Certificate = std.crypto.Certificate;

const Cipher = @import("cipher.zig").Cipher;
const CipherSuite = @import("cipher.zig").CipherSuite;
const cipher_suites = @import("cipher.zig").cipher_suites;
const max_cleartext_len = @import("cipher.zig").max_cleartext_len;

const Transcript = @import("transcript.zig").Transcript;
const record = @import("record.zig");
const Record = record.Record;
const PrivateKey = @import("PrivateKey.zig");
const proto = @import("protocol.zig");

const common = @import("handshake_common.zig");
const CertificateBuilder = common.CertificateBuilder;
const CertificateParser = common.CertificateParser;
const DhKeyPair = common.DhKeyPair;
const CertKeyPair = common.CertKeyPair;
const cert = common.cert;

const log = std.log.scoped(.tls);

pub const Options = struct {
    rng: std.Random,

    /// Server authentication. If null server will not send Certificate and
    /// CertificateVerify message.
    auth: ?*CertKeyPair,

    /// If not null server will request client certificate. If auth_type is
    /// .request empty client certificate message will be accepted.
    /// Client certificate will be verified with root_ca certificates.
    client_auth: ?ClientAuth = null,

    /// TLS 1.3 and TLS 1.2 cipher suites, in preference order.
    cipher_suites: []const CipherSuite = cipher_suites.secure,

    /// ALPN protocol names supported by the server, in preference order.
    /// If empty, no ALPN extension is sent in the response.
    alpn_protocols: []const []const u8 = &.{},

    now: Io.Timestamp,
};

pub const ClientAuth = struct {
    /// Set of root certificate authorities that server use when verifying
    /// client certificates.
    root_ca: cert.Bundle,

    auth_type: Type = .require,

    pub const Type = enum {
        /// Client certificate will be requested during the handshake, but does
        /// not require that the client send any certificates.
        request,
        /// Client certificate will be requested during the handshake, and client
        /// has to send valid certificate.
        require,
    };
};

pub const Handshake = struct {
    // public key len: x25519 = 32, secp256r1 = 65, secp384r1 = 97
    const max_pub_key_len = 98;
    const supported_named_groups = &[_]proto.NamedGroup{ .x25519, .secp256r1, .secp384r1 };

    /// Underlying network connection stream reader/writer pair.
    input: *Io.Reader,
    output: *Io.Writer,

    server_random: [32]u8 = undefined,
    client_random: [32]u8 = undefined,
    legacy_session_id_buf: [32]u8 = undefined,
    legacy_session_id: []u8 = &.{},
    cipher_suite: CipherSuite = @enumFromInt(0),
    signature_scheme: proto.SignatureScheme = @enumFromInt(0),
    named_group: proto.NamedGroup = @enumFromInt(0),
    client_pub_key_buf: [max_pub_key_len]u8 = undefined,
    client_pub_key: []u8 = &.{},
    server_pub_key_buf: [max_pub_key_len]u8 = undefined,
    server_pub_key: []u8 = &.{},
    tls_version: proto.Version = .tls_1_2,
    dh_kp: DhKeyPair = undefined,
    master_secret: [48]u8 = undefined,
    key_material: [48 * 4]u8 = undefined,

    cipher: Cipher = undefined,
    cipher_ready: bool = false,
    transcript: Transcript = .{},
    /// ALPN protocol selected during handshake.
    alpn_protocol: ?[]const u8 = null,

    const Self = @This();

    fn writeAlert(h: *Self, cph: ?*Cipher, err: anyerror) !void {
        if (cph) |c| {
            const cleartext = proto.alertFromError(err);
            const ciphertext = try c.encrypt(h.output.unusedCapacitySlice(), .alert, &cleartext);
            h.output.advance(ciphertext.len);
        } else {
            const alert = record.header(.alert, 2) ++ proto.alertFromError(err);
            try h.output.writeAll(&alert);
        }
        try h.output.flush();
    }

    pub fn handshake(h: *Self, opt: Options) !Cipher {
        h.initKeys(opt);

        h.readClientHello(opt.cipher_suites, opt.alpn_protocols) catch |err| {
            try h.writeAlert(null, err);
            return err;
        };
        h.transcript.use(h.cipher_suite.hash());

        h.serverFlight(opt) catch |err| {
            try h.writeAlert(if (h.cipher_ready) &h.cipher else null, err);
            return err;
        };
        try h.output.flush();

        h.clientFlight2(opt) catch |err| {
            // Alert received from client
            if (!mem.startsWith(u8, @errorName(err), "TlsAlert")) {
                try h.writeAlert(if (h.cipher_ready) &h.cipher else null, err);
            }
            return err;
        };
        return h.cipher;
    }

    fn initKeys(h: *Self, opt: Options) void {
        opt.rng.bytes(&h.server_random);
        if (opt.auth) |a| {
            // required signature scheme in client hello
            h.signature_scheme = a.key.signature_scheme;
        }
    }

    fn clientFlight1(h: *Self, opt: Options) !void {
        try h.readClientHello(opt.cipher_suites, opt.alpn_protocols);
        h.transcript.use(h.cipher_suite.hash());
    }

    fn clientFlight2(h: *Self, opt: Options) !void {
        if (h.tls_version == .tls_1_2)
            return h.clientFlight2Tls12(opt);

        // calculate application cipher before updating transcript in readClientFlight2
        const application_secret = h.transcript.applicationSecret();
        const app_cipher = try Cipher.initTls13(h.cipher_suite, application_secret, .server);
        // set application cipher instead of EndOfStream error
        h.readClientFlight2(opt) catch |err| {
            if (err != error.EndOfStream and err != error.InputBufferUndersize) {
                // don't change on short reads: https://github.com/ianic/tls.zig/commit/2f3f23485e01e4be8219c4a1ceda01ed961da61d
                h.cipher = app_cipher;
            }
            return err;
        };
        h.cipher = app_cipher;
    }

    fn serverFlight(h: *Self, opt: Options) !void {
        return switch (h.tls_version) {
            .tls_1_2 => h.serverFlightTls12(opt),
            .tls_1_3 => h.serverFlightTls13(opt),
            else => error.TlsProtocolVersion,
        };
    }

    fn serverFlightTls12(h: *Self, opt: Options) !void {
        const auth = opt.auth orelse return error.TlsHandshakeFailure;
        // ponytail: TLS 1.2 client authentication is omitted until an application needs mTLS.
        if (opt.client_auth != null) return error.TlsUnsupportedFeature;

        var seed: [DhKeyPair.seed_len]u8 = undefined;
        opt.rng.bytes(&seed);
        h.dh_kp = try DhKeyPair.init(seed, &.{h.named_group});
        h.server_pub_key = try common.dupe(
            &h.server_pub_key_buf,
            try h.dh_kp.publicKey(h.named_group),
        );

        var w: record.Writer = .initFromIo(h.output);
        {
            const hello = try h.makeServerHelloTls12(&w);
            h.transcript.update(hello[record.header_len..]);
        }
        {
            var hw = try w.writerAdvance(record.header_len);
            const cb = CertificateBuilder{
                .rng = opt.rng,
                .cert_key_pair = auth,
                .transcript = &h.transcript,
                .tls_version = .tls_1_2,
                .side = .server,
            };
            try cb.makeCertificate(&hw);
            h.transcript.update(hw.buffered());
            try w.record(.handshake, hw.buffered());
        }
        {
            var signed_buf: [1024]u8 = undefined;
            var params_buf: [1 + 2 + 1 + max_pub_key_len]u8 = undefined;
            var params = record.Writer.init(&params_buf);
            try params.enumValue(proto.Curve.named_curve);
            try params.enumValue(h.named_group);
            try params.int(u8, h.server_pub_key.len);
            try params.slice(h.server_pub_key);

            var message_buf: [64 + params_buf.len]u8 = undefined;
            var message = Io.Writer.fixed(&message_buf);
            try message.writeAll(&h.client_random);
            try message.writeAll(&h.server_random);
            try message.writeAll(params.buffered());
            const signed = try auth.signMessage(message.buffered(), opt.rng, &signed_buf);

            var hw = try w.writerAdvance(record.header_len);
            try hw.handshakeRecordHeader(
                .server_key_exchange,
                params.buffered().len + 4 + signed.bytes.len,
            );
            try hw.slice(params.buffered());
            try hw.enumValue(signed.scheme);
            try hw.int(u16, signed.bytes.len);
            try hw.slice(signed.bytes);
            h.transcript.update(hw.buffered());
            try w.record(.handshake, hw.buffered());
        }
        {
            var hw = try w.writerAdvance(record.header_len);
            try hw.handshakeRecord(.server_hello_done, &.{});
            h.transcript.update(hw.buffered());
            try w.record(.handshake, hw.buffered());
        }
        h.output.advance(w.buffered().len);
    }

    fn serverFlightTls13(h: *Self, opt: Options) !void {
        var w: record.Writer = .initFromIo(h.output);

        const shared_key = brk: {
            var seed: [DhKeyPair.seed_len]u8 = undefined;
            opt.rng.bytes(&seed);
            var kp = try DhKeyPair.init(seed, &[_]proto.NamedGroup{h.named_group});
            h.server_pub_key = try common.dupe(&h.server_pub_key_buf, try kp.publicKey(h.named_group));
            break :brk try kp.sharedKey(h.named_group, h.client_pub_key);
        };
        {
            const hello = try h.makeServerHelloTls13(&w);
            h.transcript.update(hello[record.header_len..]);
        }
        {
            const handshake_secret = h.transcript.handshakeSecret(shared_key);
            h.cipher = try Cipher.initTls13(h.cipher_suite, handshake_secret, .server);
            h.cipher_ready = true;
        }
        try w.record(.change_cipher_spec, &[_]u8{1});
        {
            var hw = try w.writerAdvance(record.header_len);
            if (h.alpn_protocol) |selected| {
                // EncryptedExtensions with ALPN
                // Build the extensions payload first
                const proto_len: u16 = @intCast(selected.len);
                const alpn_ext_len = 2 + 2 + 2 + 1 + proto_len; // ext_type(2) + ext_len(2) + list_len(2) + proto_len_byte(1) + proto
                const ee_header_pos = try hw.skip(4); // handshake header placeholder
                try hw.int(u16, alpn_ext_len); // extensions length
                try hw.alpn(&.{selected});
                var hdr_w = hw.writerAt(ee_header_pos);
                try hdr_w.handshakeRecordHeader(.encrypted_extensions, hw.pos() - ee_header_pos - 4);
            } else {
                try hw.handshakeRecord(.encrypted_extensions, &[_]u8{ 0, 0 });
            }
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }
        if (opt.client_auth) |_| { // Certificate request
            var hw = try w.writerAdvance(record.header_len);
            try makeCertificateRequestTls13(&hw);
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }
        if (opt.auth) |auth| {
            const cb = CertificateBuilder{
                .rng = opt.rng,
                .cert_key_pair = auth,
                .transcript = &h.transcript,
                .side = .server,
            };
            { // Certificate
                var hw = try w.writerAdvance(record.header_len);
                try cb.makeCertificate(&hw);
                h.transcript.update(hw.buffered());
                try h.writeEncrypted(&w, hw.buffered());
            }
            { // Certificate verify
                var hw = try w.writerAdvance(record.header_len);
                try cb.makeCertificateVerify(&hw);
                h.transcript.update(hw.buffered());
                try h.writeEncrypted(&w, hw.buffered());
            }
        }
        { // Finished
            var hw = try w.writerAdvance(record.header_len);
            try hw.handshakeRecord(.finished, h.transcript.serverFinishedTls13());
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }

        h.output.advance(w.buffered().len);
    }

    fn clientFlight2Tls12(h: *Self, opt: Options) !void {
        {
            var d = try Record.decoder(h.input);
            try d.expectContentType(.handshake);
            const message = d.payload;
            if (try d.decode(proto.Handshake) != .client_key_exchange)
                return error.TlsUnexpectedMessage;
            const message_len = try d.decode(u24);
            if (message_len != d.rest().len) return error.TlsDecodeError;
            const client_key = try d.slice(try d.decode(u8));
            if (!d.eof()) return error.TlsDecodeError;

            const shared_key = try h.dh_kp.sharedKey(h.named_group, client_key);
            h.transcript.update(message);
            h.transcript.masterSecret(
                &h.master_secret,
                shared_key,
                h.client_random,
                h.server_random,
            );
            h.transcript.keyMaterial(
                &h.key_material,
                &h.master_secret,
                h.client_random,
                h.server_random,
            );
            h.cipher = try Cipher.initTls12(
                h.cipher_suite,
                &h.key_material,
                .server,
                opt.rng,
            );
            h.cipher_ready = true;
        }
        {
            const rec = try Record.read(h.input);
            if (rec.protocol_version != .tls_1_2 or
                rec.content_type != .change_cipher_spec or
                !mem.eql(u8, rec.payload, &.{1}))
                return error.TlsUnexpectedMessage;
        }
        {
            const rec = try Record.read(h.input);
            if (rec.protocol_version != .tls_1_2 or rec.content_type != .handshake)
                return error.TlsUnexpectedMessage;
            var cleartext_buf: [max_cleartext_len]u8 = undefined;
            const content_type, const cleartext = try h.cipher.decrypt(&cleartext_buf, rec);
            if (content_type != .handshake or cleartext.len != 16)
                return error.TlsDecodeError;

            const expected = record.handshakeHeader(.finished, 12) ++
                h.transcript.clientFinishedTls12(&h.master_secret);
            if (!std.crypto.timing_safe.eql([16]u8, expected, cleartext[0..16].*))
                return error.TlsDecryptError;
            h.transcript.update(cleartext);
        }
        {
            var w: record.Writer = .initFromIo(h.output);
            try w.record(.change_cipher_spec, &.{1});
            const finished = record.handshakeHeader(.finished, 12) ++
                h.transcript.serverFinishedTls12(&h.master_secret);
            const ciphertext = try h.cipher.encrypt(w.unused(), .handshake, &finished);
            w.advance(ciphertext.len);
            h.transcript.update(&finished);
            h.output.advance(w.buffered().len);
            try h.output.flush();
        }
    }

    fn readClientFlight2(h: *Self, opt: Options) !void {
        // buffer for decrypted handshake records
        var cleartext_buffer: [max_cleartext_len]u8 = undefined;
        // cleartext writer
        var cw = Io.Writer.fixed(&cleartext_buffer);

        var handshake_state: proto.Handshake = .finished;
        var crt_parser: CertificateParser = undefined;
        if (opt.client_auth) |client_auth| {
            crt_parser = .{
                .root_ca = client_auth.root_ca,
                .host = "",
                .now_sec = opt.now.toSeconds(),
            };
            handshake_state = .certificate;
        }

        outer: while (true) {
            const rec = try Record.read(h.input);
            if (rec.protocol_version != .tls_1_2 and rec.content_type != .alert)
                return error.TlsProtocolVersion;

            switch (rec.content_type) {
                .change_cipher_spec => {
                    if (rec.payload.len != 1) return error.TlsUnexpectedMessage;
                },
                .application_data => {
                    const content_type, const cleartext = try h.cipher.decrypt(cw.unusedCapacitySlice(), rec);
                    cw.advance(cleartext.len);

                    var d = record.Decoder.init(content_type, cw.buffered());
                    try d.expectContentType(.handshake);
                    while (!d.eof()) {
                        const handshake_type = try d.decode(proto.Handshake);
                        const length = try d.decode(u24);

                        if (length > max_cleartext_len)
                            return error.TlsRecordOverflow;
                        if (length > d.rest().len)
                            continue :outer; // fragmented handshake into multiple records

                        defer {
                            h.transcript.update(d.payload[0..d.idx]);
                            _ = cw.consume(d.idx);
                            d = record.Decoder.init(content_type, cw.buffered());
                        }

                        if (handshake_state != handshake_type)
                            return error.TlsUnexpectedMessage;

                        switch (handshake_type) {
                            .certificate => {
                                if (length == 4) {
                                    // got empty certificate message
                                    if (opt.client_auth.?.auth_type == .require)
                                        return error.TlsCertificateRequired;
                                    try d.skip(length);
                                    handshake_state = .finished;
                                } else {
                                    try crt_parser.parseCertificate(&d, .tls_1_3);
                                    handshake_state = .certificate_verify;
                                }
                            },
                            .certificate_verify => {
                                try crt_parser.parseCertificateVerify(&d);
                                crt_parser.verifySignature(h.transcript.clientCertificateVerify()) catch |err| return switch (err) {
                                    error.TlsUnknownSignatureScheme => error.TlsIllegalParameter,
                                    else => error.TlsDecryptError,
                                };
                                handshake_state = .finished;
                            },
                            .finished => {
                                const actual = try d.slice(length);
                                const expected = h.transcript.clientFinishedTls13();
                                if (!mem.eql(u8, expected, actual))
                                    return if (expected.len == actual.len)
                                        error.TlsDecryptError
                                    else
                                        error.TlsDecodeError;
                                return;
                            },
                            else => return error.TlsUnexpectedMessage,
                        }
                    }
                },
                .alert => {
                    var d = record.Decoder.init(rec.content_type, rec.payload);
                    return d.raiseAlert();
                },
                else => return error.TlsUnexpectedMessage,
            }
        }
    }

    /// Write encrypted handshake message into `w` Cleartext and write buffer
    /// `w.unused()` are reusing same buffer. Cleartext is written 5 bytes ahead
    /// (record header len) from w.unused() position to avoid memcopy in the
    /// encrypt. Encrypt will add tls record head in first 5 bytes, encrypt
    /// cleartext and add hmac at end.
    fn writeEncrypted(h: *Self, w: *record.Writer, cleartext: []const u8) !void {
        const ciphertext = try h.cipher.encrypt(w.unused(), .handshake, cleartext);
        w.advance(ciphertext.len);
    }

    fn makeServerHelloTls13(h: *Self, w: *record.Writer) ![]const u8 {
        const header_pos = try w.skip(9);

        try w.enumValue(proto.Version.tls_1_2);
        try w.slice(&h.server_random);
        {
            try w.int(u8, h.legacy_session_id.len);
            if (h.legacy_session_id.len > 0) try w.slice(h.legacy_session_id);
        }
        try w.enumValue(h.cipher_suite);
        try w.slice(&[_]u8{0}); // compression method

        const ext_len_pos = try w.skip(2); // extensions length placeholder writer
        { // supported versions extension
            try w.enumValue(proto.Extension.supported_versions);
            try w.int(u16, 2);
            try w.enumValue(proto.Version.tls_1_3);
        }
        { // key share extension
            const key_len: u16 = @intCast(h.server_pub_key.len);
            try w.enumValue(proto.Extension.key_share);
            try w.int(u16, key_len + 4);
            try w.enumValue(h.named_group);
            try w.int(u16, key_len);
            try w.slice(h.server_pub_key);
        }
        var ew = w.writerAt(ext_len_pos);
        try ew.int(u16, w.pos() - ext_len_pos - 2);
        var hw = w.writerAt(header_pos);
        try hw.recordHeader(.handshake, w.pos() - 5);
        try hw.handshakeRecordHeader(.server_hello, w.pos() - 9);

        return w.buffered();
    }

    fn makeServerHelloTls12(h: *Self, w: *record.Writer) ![]const u8 {
        const header_pos = try w.skip(record.header_len + 4);
        try w.enumValue(proto.Version.tls_1_2);
        try w.slice(&h.server_random);
        try w.int(u8, 0); // session resumption is intentionally unsupported
        try w.enumValue(h.cipher_suite);
        try w.int(u8, 0); // null compression
        if (h.alpn_protocol) |selected| {
            const ext_len_pos = try w.skip(2);
            try w.alpn(&.{selected});
            var ew = w.writerAt(ext_len_pos);
            try ew.int(u16, w.pos() - ext_len_pos - 2);
        }
        var hw = w.writerAt(header_pos);
        try hw.recordHeader(.handshake, w.pos() - record.header_len);
        try hw.handshakeRecordHeader(
            .server_hello,
            w.pos() - record.header_len - 4,
        );
        return w.buffered();
    }

    fn makeCertificateRequestTls13(w: *record.Writer) !void {
        const header_pos = try w.skip(4 + 1 + 2);
        const ext_head = w.pos();
        try w.extension(.signature_algorithms, common.supported_signature_algorithms);
        const ext_len = w.pos() - ext_head;
        var hw = w.writerAt(header_pos);
        try hw.handshakeRecordHeader(.certificate_request, ext_len + 3);
        try hw.int(u8, 0); // certificate request context length = 0
        try hw.int(u16, ext_len); // extensions length
    }

    fn readClientHello(h: *Self, supported_cipher_suites: []const CipherSuite, server_alpn_protocols: []const []const u8) !void {
        var d = try Record.decoder(h.input);
        if (d.payload.len > max_cleartext_len) return error.TlsRecordOverflow;
        try d.expectContentType(.handshake);
        h.transcript.update(d.payload);

        const handshake_type = try d.decode(proto.Handshake);
        if (handshake_type != .client_hello) return error.TlsUnexpectedMessage;
        if (try d.decode(u24) != d.rest().len) return error.TlsDecodeError;
        if (try d.decode(proto.Version) != .tls_1_2) return error.TlsProtocolVersion;

        h.client_random = try d.array(32);
        { // legacy session id
            const len = try d.decode(u8);
            h.legacy_session_id = try common.dupe(&h.legacy_session_id_buf, try d.slice(len));
        }
        const offered_ciphers = try d.slice(try d.decode(u16));
        if (offered_ciphers.len == 0 or offered_ciphers.len % 2 != 0)
            return error.TlsDecodeError;
        const compression_methods = try d.slice(try d.decode(u8));
        if (std.mem.indexOfScalar(u8, compression_methods, 0) == null)
            return error.TlsIllegalParameter;

        var key_share_received = false;
        var supported_group: proto.NamedGroup = @enumFromInt(0);
        var client_supports_12 = true;
        var client_supports_13 = false;
        var saw_supported_versions = false;
        var signature_supported = opt: {
            if (@intFromEnum(h.signature_scheme) == 0) break :opt true;
            break :opt false;
        };

        if (d.eof()) {
            h.tls_version = .tls_1_2;
            return error.TlsMissingExtension;
        }

        // extensions
        const extensions_end_idx = try d.decode(u16) + d.idx;
        if (extensions_end_idx != d.payload.len) return error.TlsDecodeError;
        while (d.idx < extensions_end_idx) {
            const extension_type = try d.decode(proto.Extension);
            const extension_len = try d.decode(u16);
            const extension_end = std.math.add(usize, d.idx, extension_len) catch
                return error.TlsDecodeError;
            if (extension_end > extensions_end_idx) return error.TlsDecodeError;

            switch (extension_type) {
                .supported_versions => {
                    saw_supported_versions = true;
                    client_supports_12 = false;
                    const end_idx = try d.decode(u8) + d.idx;
                    if (end_idx != extension_end) return error.TlsDecodeError;
                    while (d.idx < end_idx) {
                        switch (try d.decode(proto.Version)) {
                            .tls_1_2 => client_supports_12 = true,
                            .tls_1_3 => client_supports_13 = true,
                            else => {},
                        }
                    }
                },
                .key_share => {
                    if (extension_len == 0) return error.TlsDecodeError;
                    key_share_received = true;
                    var selected_named_group_idx = supported_named_groups.len;
                    const end_idx = try d.decode(u16) + d.idx;
                    if (end_idx != extension_end) return error.TlsDecodeError;
                    while (d.idx < end_idx) {
                        const named_group = try d.decode(proto.NamedGroup);
                        switch (@intFromEnum(named_group)) {
                            0x0001...0x0016,
                            0x001a...0x001c,
                            0xff01...0xff02,
                            => return error.TlsIllegalParameter,
                            else => {},
                        }
                        const client_pub_key = try d.slice(try d.decode(u16));
                        for (supported_named_groups, 0..) |supported, idx| {
                            if (named_group == supported and idx < selected_named_group_idx) {
                                h.named_group = named_group;
                                h.client_pub_key = try common.dupe(&h.client_pub_key_buf, client_pub_key);
                                selected_named_group_idx = idx;
                            }
                        }
                    }
                    if (@intFromEnum(h.named_group) == 0)
                        return error.TlsIllegalParameter;
                },
                .supported_groups => {
                    const end_idx = try d.decode(u16) + d.idx;
                    if (end_idx != extension_end) return error.TlsDecodeError;
                    var selected_named_group_idx = supported_named_groups.len;
                    while (d.idx < end_idx) {
                        const named_group = try d.decode(proto.NamedGroup);
                        switch (@intFromEnum(named_group)) {
                            0x0001...0x0016,
                            0x001a...0x001c,
                            0xff01...0xff02,
                            => return error.TlsIllegalParameter,
                            else => {},
                        }
                        for (supported_named_groups, 0..) |supported, idx| {
                            if (named_group == supported and idx < selected_named_group_idx) {
                                supported_group = named_group;
                                selected_named_group_idx = idx;
                            }
                        }
                    }
                },
                .signature_algorithms => {
                    const list_len = try d.decode(u16);
                    if (list_len == 0 or d.idx + list_len != extension_end)
                        return error.TlsDecodeError;
                    while (d.idx < extension_end) {
                        if (try d.decode(proto.SignatureScheme) == h.signature_scheme)
                            signature_supported = true;
                    }
                },
                .application_layer_protocol_negotiation => {
                    // RFC 7301: parse client ALPN extension and select a protocol
                    if (server_alpn_protocols.len > 0) {
                        const list_end = try d.decode(u16) + d.idx;
                        if (list_end != extension_end) return error.TlsDecodeError;
                        // Find the first server protocol that the client supports
                        // (server preference order)
                        var best_match: ?[]const u8 = null;
                        var best_server_idx: usize = server_alpn_protocols.len;
                        const saved_idx = d.idx;
                        for (server_alpn_protocols, 0..) |server_proto, si| {
                            d.idx = saved_idx;
                            while (d.idx < list_end) {
                                const proto_len = try d.decode(u8);
                                const client_proto = try d.slice(proto_len);
                                if (si < best_server_idx and mem.eql(u8, client_proto, server_proto)) {
                                    best_match = server_proto;
                                    best_server_idx = si;
                                }
                            }
                        }
                        d.idx = list_end;
                        h.alpn_protocol = best_match;
                        if (best_match == null) {
                            return error.TlsNoApplicationProtocol;
                        }
                    } else {
                        try d.skip(extension_end - d.idx);
                    }
                },
                else => {
                    try d.skip(extension_end - d.idx);
                },
            }
            if (d.idx != extension_end) return error.TlsDecodeError;
        }

        if (saw_supported_versions and !client_supports_12 and !client_supports_13)
            return error.TlsProtocolVersion;
        if (!signature_supported) return error.TlsHandshakeFailure;

        const selected_13 = if (client_supports_13)
            selectCipher(supported_cipher_suites, offered_ciphers, .tls_1_3, optAuth(h.signature_scheme))
        else
            null;
        const selected_12 = if (client_supports_12)
            selectCipher(supported_cipher_suites, offered_ciphers, .tls_1_2, optAuth(h.signature_scheme))
        else
            null;
        h.cipher_suite = selected_13 orelse selected_12 orelse
            return error.TlsNoSupportedCiphers;
        h.tls_version = if (cipher_suites.includes(cipher_suites.tls13, h.cipher_suite))
            .tls_1_3
        else
            .tls_1_2;

        if (h.tls_version == .tls_1_3) {
            if (!key_share_received) return error.TlsMissingExtension;
            if (@intFromEnum(h.named_group) == 0) return error.TlsIllegalParameter;
        } else {
            if (@intFromEnum(supported_group) == 0) return error.TlsHandshakeFailure;
            h.named_group = supported_group;
            if (client_supports_13 and hasTls13Cipher(supported_cipher_suites))
                h.server_random[24..32].* = "DOWNGRD\x01".*;
        }
    }

    const AuthKind = enum { none, ecdsa, rsa, ed25519 };

    fn optAuth(scheme: proto.SignatureScheme) AuthKind {
        return switch (scheme) {
            .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ecdsa_secp521r1_sha512 => .ecdsa,
            .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => .rsa,
            .ed25519 => .ed25519,
            else => .none,
        };
    }

    fn selectCipher(
        supported: []const CipherSuite,
        offered: []const u8,
        version: proto.Version,
        auth: AuthKind,
    ) ?CipherSuite {
        for (supported) |candidate| {
            const right_version = switch (version) {
                .tls_1_3 => cipher_suites.includes(cipher_suites.tls13, candidate),
                .tls_1_2 => cipher_suites.includes(cipher_suites.tls12, candidate) and
                    tls12AuthCompatible(candidate, auth),
                else => false,
            };
            if (!right_version) continue;
            var i: usize = 0;
            while (i < offered.len) : (i += 2)
                if (std.mem.readInt(u16, offered[i..][0..2], .big) == @intFromEnum(candidate))
                    return candidate;
        }
        return null;
    }

    fn tls12AuthCompatible(cipher_suite: CipherSuite, auth: AuthKind) bool {
        return switch (cipher_suite) {
            .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            => auth == .ecdsa,
            .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            => auth == .rsa,
            else => false,
        };
    }

    fn hasTls13Cipher(supported: []const CipherSuite) bool {
        for (supported) |candidate|
            if (cipher_suites.includes(cipher_suites.tls13, candidate)) return true;
        return false;
    }
};

const testing = std.testing;
const data12 = @import("testdata/tls12.zig");
const data13 = @import("testdata/tls13.zig");
const testu = @import("testu.zig");

fn fuzzClientHello(_: void, smith: *testing.Smith) !void {
    var bytes: [2048]u8 = undefined;
    const len = smith.slice(&bytes);
    var reader: Io.Reader = .fixed(bytes[0..len]);
    var h: Handshake = .{
        .input = &reader,
        .output = undefined,
        .signature_scheme = .ecdsa_secp256r1_sha256,
    };
    h.readClientHello(cipher_suites.secure, &.{"http/1.1"}) catch return;

    try h.cipher_suite.validate();
    try testing.expect(h.tls_version == .tls_1_2 or h.tls_version == .tls_1_3);
    try testing.expect(@intFromEnum(h.named_group) != 0);
}

fn smithSliceCorpus(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

test "client hello parser tolerates arbitrary input" {
    const tls12_seed = smithSliceCorpus(&data12.client_hello);
    const tls13_seed = smithSliceCorpus(&data13.client_hello);
    try testing.fuzz({}, fuzzClientHello, .{
        .corpus = &.{ &tls12_seed, &tls13_seed },
    });
}

test "TLS 1.2 CBC suites are not selectable" {
    const offered = [_]u8{ 0xc0, 0x13 }; // ECDHE_RSA_WITH_AES_128_CBC_SHA
    try testing.expect(Handshake.selectCipher(
        &.{.ECDHE_RSA_WITH_AES_128_CBC_SHA},
        &offered,
        .tls_1_2,
        .rsa,
    ) == null);
}

test "read client hello" {
    var reader: Io.Reader = .fixed(&data13.client_hello);
    var h: Handshake = .{
        .input = &reader,
        .output = undefined,
    };
    h.signature_scheme = .ecdsa_secp521r1_sha512; // this must be supported in signature_algorithms extension
    try h.readClientHello(cipher_suites.tls13, &.{});

    try testing.expectEqual(CipherSuite.AES_128_GCM_SHA256, h.cipher_suite);
    try testing.expectEqual(.x25519, h.named_group);
    try testing.expectEqualSlices(u8, &data13.client_random, &h.client_random);
    try testing.expectEqualSlices(u8, &data13.client_public_key, h.client_pub_key);
}

test "make server hello" {
    var h: Handshake = .{ .input = undefined, .output = undefined };

    h.cipher_suite = .AES_256_GCM_SHA384;
    testu.fillFrom(&h.server_random, 0);
    testu.fillFrom(&h.server_pub_key_buf, 0x20);
    h.named_group = .x25519;
    h.server_pub_key = h.server_pub_key_buf[0..32];

    const expected = &testu.hexToBytes(
        \\ 16 03 03 00 5a 02 00 00 56
        \\ 03 03
        \\ 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        \\ 00
        \\ 13 02 00
        \\ 00 2e 00 2b 00 02 03 04
        \\ 00 33 00 24 00 1d 00 20
        \\ 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
    );

    var buffer: [128]u8 = undefined;
    var w: record.Writer = .init(&buffer);
    const actual = try h.makeServerHelloTls13(&w);
    try testing.expectEqual(95, actual.len);
    try testing.expectEqualSlices(u8, expected, actual);
}

test "make certificate request" {
    var buffer: [32]u8 = undefined;

    const expected = testu.hexToBytes("0d 00 00 1b" ++ // handshake header
        "00 00 18" ++ // extension length
        "00 0d" ++ // signature algorithms extension
        "00 14" ++ // extension length
        "00 12" ++ // list length 6 * 2 bytes
        "04 03 05 03 08 04 08 05 08 06 08 07 02 01 04 01 05 01" // signature schemes
    );

    var w: record.Writer = .init(&buffer);
    try Handshake.makeCertificateRequestTls13(&w);
    try testing.expectEqualSlices(u8, &expected, w.buffered());
}

pub const NonBlock = struct {
    const Self = @This();

    // inner sync handshake
    inner: Handshake = undefined,
    opt: Options = undefined,
    state: State = undefined,

    const State = enum {
        init,
        client_flight_1,
        server_flight,
        client_flight_2,

        fn next(self: *State) void {
            self.* = @enumFromInt(@intFromEnum(self.*) + 1);
        }
    };

    pub fn init(opt: Options) Self {
        var inner: Handshake = .{
            .input = undefined,
            .output = undefined,
        };
        inner.initKeys(opt);
        return .{
            .opt = opt,
            .inner = inner,
            .state = .init,
        };
    }

    fn recv(self: *Self) !void {
        const prev: Transcript = self.inner.transcript;
        errdefer self.inner.transcript = prev;

        switch (self.state) {
            .init => {
                try self.inner.clientFlight1(self.opt);
                self.state.next();
            },
            .server_flight => {
                try self.inner.clientFlight2(self.opt);
                self.state.next();
            },
            else => return,
        }
    }

    /// True when handshake is successfully finished
    pub fn done(self: Self) bool {
        return self.state == .client_flight_2;
    }

    /// Runs next handshake step.
    pub fn run(
        self: *Self,
        /// Data received from the peer
        recv_buf: []const u8,
        /// Scratch buffer where data to be sent to the peer will be prepared
        send_buf: []u8,
    ) !struct {
        /// Number of bytes consumed from recv_buf
        recv_pos: usize,
        /// Number of bytes prepared in send_buf
        send_pos: usize,
        /// Unused part of the recv_buf,
        unused_recv: []const u8,
        /// Part of the send_buf that should be sent to the peer
        send: []const u8,
    } {
        if (self.done()) return .{
            .recv_pos = 0,
            .send_pos = 0,
            .unused_recv = &.{},
            .send = &.{},
        };

        var reader: Io.Reader = .fixed(recv_buf);
        self.inner.input = &reader;
        var writer: Io.Writer = .fixed(send_buf);
        self.inner.output = &writer;

        var recv_pos: usize = 0;
        out: switch (self.state) {
            .init, .server_flight => {
                self.recv() catch |err| switch (err) {
                    error.EndOfStream, error.InputBufferUndersize => {
                        return .{
                            .recv_pos = 0,
                            .send_pos = 0,
                            .unused_recv = recv_buf,
                            .send = &.{},
                        };
                    },
                    else => return err,
                };
                recv_pos = reader.seek;
                continue :out self.state;
            },
            .client_flight_1 => {
                if (recv_buf.ptr == send_buf.ptr and recv_pos != recv_buf.len) {
                    // recv buffer is fully consumed, same buffer can be used for write
                    return error.TlsUnexpectedMessage;
                }
                try self.inner.serverFlight(self.opt);
                self.state.next();
            },
            .client_flight_2 => {
                // done
            },
        }

        return .{
            .recv_pos = recv_pos,
            .send_pos = writer.end,
            .unused_recv = recv_buf[recv_pos..],
            .send = writer.buffered(),
        };
    }

    /// Cipher produced in handshake, null until successful handshake.
    pub fn cipher(self: Self) ?Cipher {
        return if (self.done()) self.inner.cipher else null;
    }

    /// ALPN protocol negotiated during handshake, null if none.
    pub fn alpnProtocol(self: Self) ?[]const u8 {
        return self.inner.alpn_protocol;
    }
};
