const std = @import("std");
const builtin = @import("builtin");

// The pinned compiler lives in .zigversion and nowhere else, so the toolchain question has one
// answer and a build with any other version fails closed rather than drifting.
const pinned_zig = std.mem.trim(u8, @embedFile(".zigversion"), " \t\r\n");

const c_flags = &[_][]const u8{ "-std=c11", "-Wall", "-Wextra", "-Werror" };

fn coreFor(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("core/mark.zig"), .target = target, .optimize = optimize });
}

/// A root under abi/ or conformance/ that reaches the core as `@import("gossmark")`.
fn rootFor(b: *std.Build, source: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, libc: bool) *std.Build.Module {
    const m = b.createModule(.{
        .root_source_file = b.path(source),
        .target = target,
        .optimize = optimize,
        .link_libc = if (libc) true else null,
    });
    m.addImport("gossmark", coreFor(b, target, optimize));
    return m;
}

fn installInto(b: *std.Build, artifact: *std.Build.Step.Compile, dir: []const u8) *std.Build.Step {
    return &b.addInstallArtifact(artifact, .{ .dest_dir = .{ .override = .{ .custom = dir } } }).step;
}


/// An empty environment variable names nothing; a relative path from one is worse than a clear
/// failure, so it is read as absent.
fn named(value: ?[]const u8) ?[]const u8 {
    const text = value orelse return null;
    return if (text.len == 0) null else text;
}

/// macOS keeps the JDK behind a tool rather than in the environment, so ask it.
fn systemJavaHome(b: *std.Build) ?[]const u8 {
    if (builtin.os.tag != .macos) return null;
    var code: u8 = 0;
    const out = b.runAllowFail(&.{"/usr/libexec/java_home"}, &code, .ignore) catch return null;
    const found = std.mem.trim(u8, out, " \t\r\n");
    return if (found.len == 0) null else b.dupe(found);
}

pub fn build(b: *std.Build) void {
    if (!std.mem.eql(u8, pinned_zig, builtin.zig_version_string)) {
        std.debug.print("gossmark: this tree builds with zig {s}, not {s}\n", .{ pinned_zig, builtin.zig_version_string });
        std.process.exit(1);
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("gossmark", .{ .root_source_file = b.path("core/mark.zig") });

    // The C surface, as a shared library and a static archive. Every SDK below is a thin binding
    // over exactly these symbols, so no client carries logic another client would have to match.
    const shared = b.addLibrary(.{
        .name = "gossmark",
        .linkage = .dynamic,
        .root_module = rootFor(b, "abi/gossmark.zig", target, optimize, true),
    });
    const static = b.addLibrary(.{
        .name = "gossmark",
        .linkage = .static,
        .root_module = rootFor(b, "abi/gossmark.zig", target, optimize, true),
    });
    const c_step = b.step("c", "Stage the C SDK: the header, the shared library and the static archive");
    c_step.dependOn(installInto(b, shared, "c"));
    c_step.dependOn(installInto(b, static, "c"));
    c_step.dependOn(&b.addInstallFile(b.path("include/gossmark.h"), "c/gossmark.h").step);

    // The wasm32 core the web package loads. Freestanding, because the engine asks the host for
    // nothing: no clock, no randomness, no network.
    const wasm = b.addExecutable(.{
        .name = "gossmark",
        .root_module = rootFor(b, "abi/wasm.zig", b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }), .ReleaseSmall, false),
    });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    b.step("wasm", "Build the wasm32 core for the web package").dependOn(installInto(b, wasm, "wasm"));

    // The unit tests: the core, then the C surface over it.
    const unit_tests = b.addTest(.{ .root_module = coreFor(b, target, optimize) });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const abi_tests = b.addTest(.{ .root_module = rootFor(b, "abi/gossmark.zig", target, optimize, true) });
    const run_abi_tests = b.addRunArtifact(abi_tests);

    const test_step = b.step("test", "Run every unit test");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_abi_tests.step);

    // The conformance command answers one operation per run, so every SDK can be replayed
    // through the same frozen vectors and held to the same bytes.
    const conform = b.addExecutable(.{ .name = "conform", .root_module = rootFor(b, "conformance/conform.zig", target, optimize, false) });
    b.step("conform", "Build the conformance command that answers one JSON operation per run").dependOn(&b.addInstallArtifact(conform, .{}).step);
    const replay = b.addRunArtifact(conform);
    replay.addArg("--replay");
    replay.addFileArg(b.path("conformance/vectors"));
    b.step("conformance", "Replay the frozen vectors through the core").dependOn(&replay.step);

    // The JNI layer: one entry, so there is no per-call signature to keep in step with C.
    const java_home = named(b.option([]const u8, "java-home", "JDK root holding include/jni.h (default: $JAVA_HOME, else the system JDK)")) orelse
        named(b.graph.environ_map.get("JAVA_HOME")) orelse systemJavaHome(b);
    const jni_step = b.step("jni", "Build the JNI shared library for the host JVM");
    if (java_home) |root| {
        const jni = b.addLibrary(.{ .name = "gossmark_jni", .root_module = rootFor(b, "abi/jni.zig", target, optimize, true), .linkage = .dynamic });
        jni.root_module.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ root, "include" }) });
        const platform = switch (target.result.os.tag) {
            .macos => "darwin",
            .windows => "win32",
            else => "linux",
        };
        jni.root_module.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ root, "include", platform }) });
        jni_step.dependOn(installInto(b, jni, "jni"));
    } else {
        jni_step.dependOn(&b.addFail("the jni step needs -Djava-home=<jdk> or JAVA_HOME").step);
    }

    const ndk = named(b.option([]const u8, "ndk", "Android NDK root (default: $ANDROID_NDK_HOME)")) orelse
        named(b.graph.environ_map.get("ANDROID_NDK_HOME"));
    const android_step = b.step("android", "Build the JNI shared library for arm64-v8a and x86_64");
    if (ndk) |root| {
        const host_tag = switch (builtin.os.tag) {
            .macos => "darwin-x86_64",
            .windows => "windows-x86_64",
            else => "linux-x86_64",
        };
        const sysroot_include = b.pathJoin(&.{ root, "toolchains", "llvm", "prebuilt", host_tag, "sysroot", "usr", "include" });
        const abis = [_]struct { dir: []const u8, arch: std.Target.Cpu.Arch }{
            .{ .dir = "arm64-v8a", .arch = .aarch64 },
            .{ .dir = "x86_64", .arch = .x86_64 },
        };
        for (abis) |abi| {
            const abi_target = b.resolveTargetQuery(.{ .cpu_arch = abi.arch, .os_tag = .linux, .abi = .android });
            const lib = b.addLibrary(.{ .name = "gossmark_jni", .root_module = rootFor(b, "abi/jni.zig", abi_target, optimize, false), .linkage = .dynamic });
            lib.root_module.addIncludePath(.{ .cwd_relative = sysroot_include });
            android_step.dependOn(installInto(b, lib, b.pathJoin(&.{ "android", abi.dir })));
        }
    } else {
        android_step.dependOn(&b.addFail("the android step needs -Dndk=<ndk root> or ANDROID_NDK_HOME").step);
    }

    // The Apple slices, wrapped into an xcframework by tools/build-xcframework.sh. Static,
    // because an app embedding a dynamic library pays for it at every launch and gains nothing:
    // there is no second consumer in the process to share it with.
    const apple_step = b.step("apple", "Build the iOS device, iOS simulator and macOS static libraries");
    const apple_slices = [_]struct { dir: []const u8, query: std.Target.Query }{
        .{ .dir = "ios", .query = .{ .cpu_arch = .aarch64, .os_tag = .ios } },
        .{ .dir = "ios-simulator", .query = .{ .cpu_arch = .aarch64, .os_tag = .ios, .abi = .simulator } },
        .{ .dir = "ios-simulator-x86_64", .query = .{ .cpu_arch = .x86_64, .os_tag = .ios, .abi = .simulator } },
        .{ .dir = "macos", .query = .{ .cpu_arch = .aarch64, .os_tag = .macos } },
        .{ .dir = "macos-x86_64", .query = .{ .cpu_arch = .x86_64, .os_tag = .macos } },
    };
    for (apple_slices) |slice| {
        const slice_target = b.resolveTargetQuery(slice.query);
        const lib = b.addLibrary(.{
            .name = "gossmark_static",
            .root_module = rootFor(b, "abi/gossmark.zig", slice_target, optimize, false),
            .linkage = .static,
        });
        apple_step.dependOn(installInto(b, lib, slice.dir));
    }

    _ = c_flags;
}
