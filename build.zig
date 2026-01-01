const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "hello",
        .root_module = root_module,
    });
    exe.linkSystemLibrary("wininet");
    exe.linkSystemLibrary("kernel32");
    exe.linkSystemLibrary("ws2_32");
    exe.linkLibC();
    exe.want_lto = true;
    exe.rdynamic = false;

    exe.root_module.strip = true;

    b.installArtifact(exe);
}
