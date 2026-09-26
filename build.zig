const std = @import("std");

// The pinned compiler lives in .zigversion and nowhere else, so the toolchain question has one
// answer and a build with any other version fails closed rather than drifting.
const pinned_zig = std.mem.trim(u8, @embedFile(".zigversion"), " \t\r\n");

pub fn build(b: *std.Build) void {
    if (!std.mem.eql(u8, pinned_zig, @import("builtin").zig_version_string)) {
        std.debug.print("gossmark: this tree builds with zig {s}, not {s}\n", .{ pinned_zig, @import("builtin").zig_version_string });
        std.process.exit(1);
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core = b.createModule(.{
        .root_source_file = b.path("core/mark.zig"),
        .target = target,
        .optimize = optimize,
    });
    _ = b.addModule("gossmark", .{ .root_source_file = b.path("core/mark.zig") });

    const unit_tests = b.addTest(.{ .root_module = core });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run every unit test").dependOn(&run_unit_tests.step);
}
