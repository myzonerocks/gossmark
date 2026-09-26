//! Answers one JSON operation on stdin with one JSON object on stdout, or replays a directory
//! of recorded operations and compares every field. Byte fields are base64. Nothing persists
//! between runs, and nothing here reads a clock: every operation is handed the moment it should
//! check against, so a vector recorded today still passes in ten years.
//!
//! This is what holds the four SDKs to the same bytes. Each of them rebuilds the signed preimage
//! itself, and the only thing that catches a rebuild that differs is replaying the same vectors
//! through every one of them.
const std = @import("std");
const mark = @import("gossmark");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const b64 = std.base64.standard;

const cred = mark.cred;
const chain = mark.chain;
const revoke = mark.revoke;
const wire = mark.wire;

const max_list = 64;

/// Nothing in an answer here is unstable: every operation is deterministic, because every key is
/// derived from a seed the vector names and no operation reads a clock or draws randomness.
const unstable_fields = [_][]const u8{};

const Input = struct {
    arena: Allocator,
    obj: std.json.ObjectMap,

    fn str(in: Input, key: []const u8) ![]const u8 {
        const v = in.obj.get(key) orelse return error.MissingField;
        return if (v == .string) v.string else error.WrongType;
    }

    fn optStr(in: Input, key: []const u8) ?[]const u8 {
        const v = in.obj.get(key) orelse return null;
        return if (v == .string) v.string else null;
    }

    fn blob(in: Input, key: []const u8) ![]u8 {
        return decode(in.arena, try in.str(key));
    }

    fn optBlob(in: Input, key: []const u8) !?[]u8 {
        const s = in.optStr(key) orelse return null;
        return try decode(in.arena, s);
    }

    fn fixed(in: Input, key: []const u8, comptime n: usize) ![n]u8 {
        const b = try in.blob(key);
        if (b.len != n) return error.WrongLength;
        return b[0..n].*;
    }

    fn number(in: Input, key: []const u8) !u64 {
        const v = in.obj.get(key) orelse return error.MissingField;
        return if (v == .integer) @intCast(v.integer) else error.WrongType;
    }

    fn optNumber(in: Input, key: []const u8) !?u64 {
        const v = in.obj.get(key) orelse return null;
        return switch (v) {
            .integer => |i| @intCast(i),
            .null => null,
            else => error.WrongType,
        };
    }

    fn word32(in: Input, key: []const u8) !u32 {
        return @intCast(try in.number(key));
    }

    fn nested(in: Input, key: []const u8) !Input {
        const v = in.obj.get(key) orelse return error.MissingField;
        return if (v == .object) .{ .arena = in.arena, .obj = v.object } else error.WrongType;
    }

    fn optNested(in: Input, key: []const u8) !?Input {
        const v = in.obj.get(key) orelse return null;
        return switch (v) {
            .object => |o| .{ .arena = in.arena, .obj = o },
            .null => null,
            else => error.WrongType,
        };
    }

    fn items(in: Input, key: []const u8) ![]Value {
        const v = in.obj.get(key) orelse return &.{};
        return if (v == .array) v.array.items else error.WrongType;
    }
};

const Answer = struct {
    arena: Allocator,
    buf: std.ArrayList(u8) = .empty,
    first: bool = true,

    fn key(a: *Answer, field: []const u8) !void {
        try a.buf.append(a.arena, if (a.first) '{' else ',');
        a.first = false;
        try a.buf.append(a.arena, '"');
        try a.buf.appendSlice(a.arena, field);
        try a.buf.appendSlice(a.arena, "\":");
    }

    fn blob(a: *Answer, field: []const u8, data: []const u8) !void {
        try a.key(field);
        try a.buf.append(a.arena, '"');
        const start = a.buf.items.len;
        try a.buf.resize(a.arena, start + b64.Encoder.calcSize(data.len));
        _ = b64.Encoder.encode(a.buf.items[start..], data);
        try a.buf.append(a.arena, '"');
    }

    fn number(a: *Answer, field: []const u8, v: u64) !void {
        try a.key(field);
        try a.buf.print(a.arena, "{d}", .{v});
    }

    fn optNumber(a: *Answer, field: []const u8, v: ?u64) !void {
        try a.key(field);
        if (v) |x| try a.buf.print(a.arena, "{d}", .{x}) else try a.buf.appendSlice(a.arena, "null");
    }

    fn flag(a: *Answer, field: []const u8, v: bool) !void {
        try a.key(field);
        try a.buf.appendSlice(a.arena, if (v) "true" else "false");
    }

    fn text(a: *Answer, field: []const u8, s: []const u8) !void {
        try a.key(field);
        try a.buf.append(a.arena, '"');
        for (s) |ch| switch (ch) {
            '"' => try a.buf.appendSlice(a.arena, "\\\""),
            '\\' => try a.buf.appendSlice(a.arena, "\\\\"),
            '\n' => try a.buf.appendSlice(a.arena, "\\n"),
            else => try a.buf.append(a.arena, ch),
        };
        try a.buf.append(a.arena, '"');
    }

    fn finish(a: *Answer) ![]const u8 {
        if (a.first) try a.buf.append(a.arena, '{');
        try a.buf.appendSlice(a.arena, "}\n");
        return a.buf.items;
    }
};

fn decode(arena: Allocator, s: []const u8) ![]u8 {
    const out = try arena.alloc(u8, try b64.Decoder.calcSizeForSlice(s));
    try b64.Decoder.decode(out, s);
    return out;
}

fn emit(init: std.process.Init, text: []const u8) !void {
    var out_buf: [1 << 12]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &out_buf);
    try w.interface.writeAll(text);
    try w.interface.flush();
}

fn sameValue(a: Value, b: Value) bool {
    return switch (a) {
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        .integer => |x| b == .integer and x == b.integer,
        .bool => |x| b == .bool and x == b.bool,
        .null => b == .null,
        else => false,
    };
}

const Replay = struct {
    files: usize = 0,
    checked: usize = 0,
    failed: usize = 0,

    fn file(r: *Replay, arena: Allocator, file_name: []const u8, text: []const u8) !void {
        r.files += 1;
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
        for (parsed.array.items, 0..) |item, index| {
            const check = item.object.get("check") orelse continue;
            if (check != .bool or !check.bool) continue;
            r.checked += 1;
            const op = item.object.get("op").?.string;
            const in: Input = .{ .arena = arena, .obj = item.object.get("args").?.object };
            const expected = item.object.get("result").?.object;
            var out: Answer = .{ .arena = arena };
            answer(arena, op, in, &out) catch |e| {
                r.failed += 1;
                std.debug.print("conformance: {s}#{d} {s}: {t}\n", .{ file_name, index, op, e });
                continue;
            };
            const produced = try std.json.parseFromSliceLeaky(Value, arena, try out.finish(), .{});
            var fields = expected.iterator();
            while (fields.next()) |kv| {
                var unstable = false;
                for (unstable_fields) |f| unstable = unstable or std.mem.eql(u8, f, kv.key_ptr.*);
                if (unstable) continue;
                const got = produced.object.get(kv.key_ptr.*) orelse Value{ .null = {} };
                if (!sameValue(kv.value_ptr.*, got)) {
                    r.failed += 1;
                    std.debug.print("conformance: {s}#{d} {s}: field '{s}' differs\n", .{ file_name, index, op, kv.key_ptr.* });
                    break;
                }
            }
        }
    }
};

fn replayDir(init: std.process.Init, dir_path: []const u8) !u8 {
    const arena = init.arena.allocator();
    var dir = try std.Io.Dir.cwd().openDir(init.io, dir_path, .{ .iterate = true });
    defer dir.close(init.io);
    var it = dir.iterate();
    var replay: Replay = .{};
    while (try it.next(init.io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        const text = try dir.readFileAlloc(init.io, entry.name, arena, .limited(1 << 28));
        try replay.file(arena, entry.name, text);
    }
    std.debug.print("conformance: {d} files, {d} operations replayed, {d} failed\n", .{ replay.files, replay.checked, replay.failed });
    return if (replay.failed == 0 and replay.files > 0) 0 else 1;
}

fn keyPair(seed: [32]u8) !std.crypto.sign.Ed25519.KeyPair {
    return std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
}

/// A list of root keys as a vector gives it: base64 of the count and the keys, the same bytes the
/// C surface takes, so a vector exercises the wire shape and not only the engine behind it.
fn rootsFrom(in: Input, store: *[max_list][32]u8) !chain.Roots {
    const bytes = try in.blob("roots");
    return wire.takeRoots(bytes, store);
}

fn revokedFrom(in: Input, store: *[max_list][16]u8) !chain.Revoked {
    const bytes = in.optStr("revoked") orelse return chain.Revoked.none;
    const decoded = try decode(in.arena, bytes);
    return wire.takeRevoked(decoded, store);
}

fn putSeen(out: *Answer, seen: chain.Verified) !void {
    try out.number("kind", @intFromEnum(seen.kind));
    try out.text("category", seen.categoryName());
    try out.number("subject_chain", seen.subject.chain);
    try out.blob("subject_address", &seen.subject.address);
    try out.number("issued_at", @intCast(seen.issued_at));
    try out.number("expires_at", @intCast(seen.expires_at));
    try out.blob("issuer", &seen.issuer);
    if (seen.via) |via| {
        try out.number("via_chain", via.chain);
        try out.blob("via_address", &via.address);
    }
    var bytes: [wire.verified_len]u8 = undefined;
    wire.putVerified(seen, &bytes);
    try out.blob("verified", &bytes);
}

fn answer(arena: Allocator, op: []const u8, in: Input, out: *Answer) !void {
    _ = arena;
    if (std.mem.eql(u8, op, "public_key")) {
        const pair = try keyPair(try in.fixed("seed", 32));
        try out.blob("key", &pair.public_key.bytes);
        return;
    }
    if (std.mem.eql(u8, op, "preimage")) {
        // The bytes a signature is made over, on their own. A vector for this is what catches an
        // SDK laying a field out differently long before a signature fails in the field.
        const item = try credFrom(in);
        var bytes: [cred.preimage_len]u8 = undefined;
        cred.preimage(&item, &bytes);
        try out.blob("preimage", &bytes);
        try out.number("len", cred.preimage_len);
        return;
    }
    if (std.mem.eql(u8, op, "sign")) {
        const pair = try keyPair(try in.fixed("seed", 32));
        const item = try credFrom(in);
        const signed = try cred.sign(pair, item);
        var bytes: [wire.signed_len]u8 = undefined;
        wire.putSigned(signed, &bytes);
        try out.blob("signed", &bytes);
        return;
    }
    if (std.mem.eql(u8, op, "verify_direct")) {
        const item = try wire.takeSigned(try in.blob("signed"));
        var root_store: [max_list][32]u8 = undefined;
        var revoked_store: [max_list][16]u8 = undefined;
        const seen = try chain.verifyDirect(
            item,
            try rootsFrom(in, &root_store),
            try revokedFrom(in, &revoked_store),
            @intCast(try in.number("now")),
        );
        try putSeen(out, seen);
        return;
    }
    if (std.mem.eql(u8, op, "verify_staff")) {
        const staff = try wire.takeSigned(try in.blob("staff"));
        const capability = try wire.takeSigned(try in.blob("capability"));
        var root_store: [max_list][32]u8 = undefined;
        var revoked_store: [max_list][16]u8 = undefined;
        const seen = try chain.verifyStaff(
            staff,
            capability,
            try rootsFrom(in, &root_store),
            try revokedFrom(in, &revoked_store),
            @intCast(try in.number("now")),
        );
        try putSeen(out, seen);
        return;
    }
    if (std.mem.eql(u8, op, "snapshot_sign")) {
        const pair = try keyPair(try in.fixed("seed", 32));
        const flat = try in.blob("ids");
        if (flat.len % 16 != 0) return error.WrongLength;
        const count = flat.len / 16;
        if (count > max_list) return error.BadCount;
        var ids: [max_list][16]u8 = undefined;
        for (0..count) |i| @memcpy(&ids[i], flat[i * 16 ..][0..16]);
        const item = try revoke.sign(pair, .{
            .issuer = pair.public_key.bytes,
            .seq = try in.number("seq"),
            .issued_at = @intCast(try in.number("issued_at")),
            .ids = ids[0..count],
        });
        var bytes: [wire.snapshotLen(max_list)]u8 = undefined;
        const room = bytes[0..wire.snapshotLen(count)];
        try wire.putSnapshot(item, room);
        try out.blob("snapshot", room);
        return;
    }
    if (std.mem.eql(u8, op, "snapshot_open")) {
        var store: [max_list][16]u8 = undefined;
        const item = try wire.takeSnapshot(try in.blob("snapshot"), &store);
        var root_store: [max_list][32]u8 = undefined;
        try revoke.verify(item, try rootsFrom(in, &root_store));
        var holder = revoke.Holder{ .seq = try in.number("held_seq"), .issued_at = 1 };
        try holder.accept(item, try rootsFrom(in, &root_store));
        try out.number("seq", holder.seq);
        try out.number("issued_at", @intCast(holder.issued_at));
        try out.number("count", holder.ids.len);
        return;
    }
    return error.UnknownOperation;
}

/// A credential as a vector gives it: every field named, so a vector is readable and a change to
/// the layout shows up as a changed preimage rather than as a mystery.
fn credFrom(in: Input) !cred.Credential {
    const kind = cred.Kind.fromByte(@intCast(try in.number("kind"))) orelse return error.UnknownKind;
    const base = cred.Credential{
        .kind = kind,
        .issuer = try in.fixed("issuer", 32),
        .subject = .{
            .chain = try in.number("subject_chain"),
            .address = try in.fixed("subject_address", 20),
        },
        .issued_at = @intCast(try in.number("issued_at")),
        .expires_at = @intCast(try in.optNumber("expires_at") orelse 0),
        .id = try in.fixed("id", 16),
        .delegate = if (in.optStr("delegate")) |_| try in.fixed("delegate", 32) else [_]u8{0} ** 32,
    };
    return base.withCategory(in.optStr("category") orelse "");
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    var argv = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    _ = argv.next();
    if (argv.next()) |mode| {
        if (std.mem.eql(u8, mode, "--replay")) return replayDir(init, argv.next() orelse "conformance/vectors");
        std.debug.print("conform: usage: conform [--replay <dir>]\n", .{});
        return 2;
    }
    var in_buf: [1 << 16]u8 = undefined;
    var reader = std.Io.File.stdin().reader(init.io, &in_buf);
    const input = try reader.interface.allocRemaining(arena, .unlimited);
    const parsed = try std.json.parseFromSliceLeaky(Value, arena, input, .{});
    if (parsed != .object) return error.WrongType;
    const in: Input = .{ .arena = arena, .obj = parsed.object };
    const op = try in.str("op");
    var out: Answer = .{ .arena = arena };
    answer(arena, op, in, &out) catch |e| {
        var failure: Answer = .{ .arena = arena };
        try failure.text("error", @errorName(e));
        try failure.text("op", op);
        try emit(init, try failure.finish());
        return 1;
    };
    try emit(init, try out.finish());
    return 0;
}
