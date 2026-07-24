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
    const tls_fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
        .filters = &.{"client hello parser tolerates arbitrary input"},
    });
    const fuzz_step = b.step("fuzz", "Fuzz HTTP, WebSocket, and TLS parsers");
    fuzz_step.dependOn(&b.addRunArtifact(protocol_fuzz_tests).step);
    fuzz_step.dependOn(&b.addRunArtifact(tls_fuzz_tests).step);
}
