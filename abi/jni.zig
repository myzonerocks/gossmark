//! One JNI entry, `Native.call(op, args, nums)` in the Kotlin package: an array of byte arrays
//! and an array of longs in, a length-prefixed run of outputs back, and a Java exception carrying
//! the status on anything but success. The typing lives in Kotlin, so this layer stays one
//! function and there is no per-call JNI signature to keep in step with the C surface.
const std = @import("std");
const abi = @import("gossmark.zig");
const c = @cImport(@cInclude("jni.h"));

const Env = [*c]c.JNIEnv;
const Buffer = abi.GmBuffer;

pub const Op = enum(i32) {
    abi_version = 0,
    preimage_len = 1,
    signed_len = 2,
    verified_len = 3,
    public_key = 4,
    sign = 5,
    verify_direct = 6,
    verify_staff = 7,
    snapshot_sign = 8,
    snapshot_open = 9,
};

const heap = std.heap.smp_allocator;

fn throwStatus(env: Env, status: i32) void {
    const found = env.*.*.FindClass.?(env, "rocks/myzone/gossmark/MarkException");
    if (found == null) return;
    var text: [32]u8 = undefined;
    const message = std.fmt.bufPrintZ(&text, "{d}", .{status}) catch "internal";
    _ = env.*.*.ThrowNew.?(env, found, message.ptr);
}

/// A byte array out of the JVM, copied into the library's own memory for the call.
fn takeBytes(env: Env, array: c.jbyteArray) []u8 {
    if (array == null) return &.{};
    const len: usize = @intCast(env.*.*.GetArrayLength.?(env, array));
    const out = heap.alloc(u8, len) catch return &.{};
    if (len > 0) env.*.*.GetByteArrayRegion.?(env, array, 0, @intCast(len), @ptrCast(out.ptr));
    return out;
}

fn giveBytes(env: Env, data: []const u8) c.jbyteArray {
    const array = env.*.*.NewByteArray.?(env, @intCast(data.len));
    if (array == null or data.len == 0) return array;
    env.*.*.SetByteArrayRegion.?(env, array, 0, @intCast(data.len), @ptrCast(@constCast(data.ptr)));
    return array;
}

fn argAt(env: Env, args: c.jobjectArray, index: i32) []u8 {
    if (args == null) return &.{};
    if (index >= env.*.*.GetArrayLength.?(env, args)) return &.{};
    const item = env.*.*.GetObjectArrayElement.?(env, args, index);
    return takeBytes(env, @ptrCast(item));
}

fn numAt(env: Env, nums: c.jlongArray, index: i32) i64 {
    if (nums == null) return 0;
    if (index >= env.*.*.GetArrayLength.?(env, nums)) return 0;
    var value: c.jlong = 0;
    env.*.*.GetLongArrayRegion.?(env, nums, index, 1, &value);
    return @intCast(value);
}

/// Every call answers with a single byte array. A call whose answer is a number puts it in the
/// first eight bytes, big-endian, so there is one return shape rather than two.
export fn Java_rocks_myzone_gossmark_Native_call(
    env: Env,
    class: c.jclass,
    op_raw: c.jint,
    args: c.jobjectArray,
    nums: c.jlongArray,
) c.jbyteArray {
    _ = class;
    const op: Op = @enumFromInt(@as(i32, op_raw));
    var cell = Buffer{ .ptr = null, .len = 0 };
    defer abi.gm_free(&cell);

    var number: ?u64 = null;
    const status: i32 = switch (op) {
        .abi_version => blk: {
            number = abi.gm_abi_version();
            break :blk 0;
        },
        .preimage_len => blk: {
            number = abi.gm_preimage_len();
            break :blk 0;
        },
        .signed_len => blk: {
            number = abi.gm_signed_len();
            break :blk 0;
        },
        .verified_len => blk: {
            number = abi.gm_verified_len();
            break :blk 0;
        },
        .public_key => blk: {
            const seed = argAt(env, args, 0);
            defer heap.free(seed);
            break :blk @intFromEnum(abi.gm_public_key(seed.ptr, seed.len, &cell));
        },
        .sign => blk: {
            const seed = argAt(env, args, 0);
            defer heap.free(seed);
            const body = argAt(env, args, 1);
            defer heap.free(body);
            break :blk @intFromEnum(abi.gm_sign(seed.ptr, seed.len, body.ptr, body.len, &cell));
        },
        .verify_direct => blk: {
            const signed = argAt(env, args, 0);
            defer heap.free(signed);
            const roots = argAt(env, args, 1);
            defer heap.free(roots);
            const revoked = argAt(env, args, 2);
            defer heap.free(revoked);
            break :blk @intFromEnum(abi.gm_verify_direct(signed.ptr, signed.len, roots.ptr, roots.len, revoked.ptr, revoked.len, numAt(env, nums, 0), &cell));
        },
        .verify_staff => blk: {
            const staff = argAt(env, args, 0);
            defer heap.free(staff);
            const capability = argAt(env, args, 1);
            defer heap.free(capability);
            const roots = argAt(env, args, 2);
            defer heap.free(roots);
            const revoked = argAt(env, args, 3);
            defer heap.free(revoked);
            break :blk @intFromEnum(abi.gm_verify_staff(staff.ptr, staff.len, capability.ptr, capability.len, roots.ptr, roots.len, revoked.ptr, revoked.len, numAt(env, nums, 0), &cell));
        },
        .snapshot_sign => blk: {
            const seed = argAt(env, args, 0);
            defer heap.free(seed);
            const ids = argAt(env, args, 1);
            defer heap.free(ids);
            break :blk @intFromEnum(abi.gm_snapshot_sign(seed.ptr, seed.len, @intCast(numAt(env, nums, 0)), numAt(env, nums, 1), ids.ptr, ids.len, &cell));
        },
        .snapshot_open => blk: {
            const snapshot = argAt(env, args, 0);
            defer heap.free(snapshot);
            const roots = argAt(env, args, 1);
            defer heap.free(roots);
            var seq: u64 = 0;
            var at: i64 = 0;
            const answer = abi.gm_snapshot_open(snapshot.ptr, snapshot.len, roots.ptr, roots.len, @intCast(numAt(env, nums, 0)), &cell, &seq, &at);
            if (answer != .ok) break :blk @intFromEnum(answer);
            // The sequence and the moment ride in front of the ids, so one array carries all of
            // it and Kotlin reads them off the front.
            const ids = if (cell.ptr) |p| p[0..cell.len] else &[_]u8{};
            const joined = heap.alloc(u8, 16 + ids.len) catch break :blk @intFromEnum(abi.Status.out_of_memory);
            defer heap.free(joined);
            std.mem.writeInt(u64, joined[0..8], seq, .big);
            std.mem.writeInt(i64, joined[8..16], at, .big);
            @memcpy(joined[16..], ids);
            return giveBytes(env, joined);
        },
    };

    if (status != 0) {
        throwStatus(env, status);
        return null;
    }
    if (number) |value| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        return giveBytes(env, &bytes);
    }
    const data = if (cell.ptr) |p| p[0..cell.len] else &[_]u8{};
    return giveBytes(env, data);
}
