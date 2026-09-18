const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The library module: the public API surface (src/root.zig).
    const mod = b.addModule("Linsang", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Demo standalone server.
    const exe = b.addExecutable(.{
        .name = "linsang",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "Linsang", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the demo server");
    run_step.dependOn(&run_cmd.step);

    const interop_server = b.addExecutable(.{
        .name = "tls-interop-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/tls_interop_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "Linsang", .module = mod }},
        }),
    });
    const interop_runner = b.addExecutable(.{
        .name = "tls-interop",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/tls_interop.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const interop_cmd = b.addRunArtifact(interop_runner);
    interop_cmd.addArtifactArg(interop_server);
    interop_cmd.addFileArg(b.path("src/tls/testdata/server_cert.pem"));
    interop_cmd.addFileArg(b.path("src/tls/testdata/server_key.pem"));
    interop_cmd.addFileArg(b.path("src/tls/testdata/ecdsa_cert.pem"));
    interop_cmd.addFileArg(b.path("src/tls/testdata/ec_prime256v1_private_key.pem"));
    const interop_step = b.step("interop", "Test TLS with curl (and OpenSSL on POSIX)");
    interop_step.dependOn(&interop_cmd.step);

    // Tests: root.zig references every module, so this runs the whole suite.
    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&run_mod_tests.step);

    // Zig 0.16's Debug fuzz runner has a StackTrace type mismatch.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    const protocol_fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
        .filters = &.{"protocol parsers tolerate arbitrary input"},
    });
    const static_fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
        .filters = &.{"static file parsers tolerate arbitrary input"},
    });
    const tls_fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
        .filters = &.{"client hello parser tolerates arbitrary input"},
    });
    const fuzz_step = b.step("fuzz", "Fuzz HTTP, static file, WebSocket, and TLS parsers");
    fuzz_step.dependOn(&b.addRunArtifact(protocol_fuzz_tests).step);
    fuzz_step.dependOn(&b.addRunArtifact(static_fuzz_tests).step);
    fuzz_step.dependOn(&b.addRunArtifact(tls_fuzz_tests).step);
}
