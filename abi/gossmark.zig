//! The C ABI: every input is a pointer and a length, every byte output a library-owned buffer
//! the caller frees, every call one status. Nothing here calls back into the host, and nothing
//! here fetches: a verifier is handed its roots and its revocation snapshot and answers from
//! those, which is what lets a badge be checked offline.
const std = @import("std");
const builtin = @import("builtin");
const mark = @import("gossmark");

const cred = mark.cred;
const chain = mark.chain;
const revoke = mark.revoke;
const wire = mark.wire;

const is_wasm = builtin.cpu.arch == .wasm32 and builtin.os.tag == .freestanding;
const heap: std.mem.Allocator = if (is_wasm) std.heap.wasm_allocator else std.heap.smp_allocator;

pub const abi_version: u32 = 1;

/// How many roots and how many revoked ids one call will read. Bounded on purpose: a caller that
/// hands over a longer list gets a clear refusal rather than an allocation sized by its input.
pub const max_roots = 16;
pub const max_revoked = 1 << 20;

pub const GmBuffer = extern struct {
    ptr: ?[*]u8,
    len: usize,
};

pub const Status = enum(i32) {
    ok = 0,
    bad_argument = 1,
    bad_signature = 2,
    untrusted_issuer = 3,
    not_live = 4,
    revoked = 5,
    wrong_kind = 6,
    out_of_scope = 7,
    no_delegate = 8,
    stale = 9,
    out_of_memory = 10,
    internal = 11,
};

fn statusFor(e: anyerror) Status {
    return switch (e) {
        error.OutOfMemory => .out_of_memory,
        error.WrongLength, error.UnknownKind, error.BadCount, error.CategoryTooLong, error.IssuerMismatch => .bad_argument,
        error.BadSignature => .bad_signature,
        error.UntrustedIssuer => .untrusted_issuer,
        error.NotLive => .not_live,
        error.Revoked => .revoked,
        error.WrongKind => .wrong_kind,
        error.OutOfScope => .out_of_scope,
        error.NoDelegate => .no_delegate,
        error.Stale => .stale,
        else => .internal,
    };
}

fn bytesIn(p: ?[*]const u8, n: usize) []const u8 {
    return if (p) |ptr| ptr[0..n] else &.{};
}

fn give(cell: ?*GmBuffer, data: []const u8) !void {
    const out = cell orelse return error.BadArgument;
    // Nothing is handed back as nothing. A zero-length allocation answers an aligned sentinel
    // pointer rather than a real address, and a host that builds a view at that offset is asking
    // for a window past the end of memory: a web client threw on every page load for exactly
    // this, on a deployment that had simply revoked nobody.
    if (data.len == 0) {
        out.* = .{ .ptr = null, .len = 0 };
        return;
    }
    const copy = try heap.alloc(u8, data.len);
    @memcpy(copy, data);
    out.* = .{ .ptr = copy.ptr, .len = copy.len };
}

/// The ABI this library speaks. A host that reads a different number should not call anything
/// else here: the shapes below are fixed per version and never quietly change within one.
pub export fn gm_abi_version() u32 {
    return abi_version;
}

/// Hands back a buffer the library gave. Safe to call on a cell that was never filled.
pub export fn gm_free(cell: ?*GmBuffer) void {
    const buf = cell orelse return;
    if (buf.ptr) |p| heap.free(p[0..buf.len]);
    buf.* = .{ .ptr = null, .len = 0 };
}

/// Room for a host to write an input into. A wasm host has no way to reach the library's heap
/// otherwise, and guessing at the module's layout from `__heap_base` is a guess that breaks the
/// day the layout changes. Freed with gm_dealloc, never with gm_free: this is the host's memory,
/// not a cell the library filled.
pub export fn gm_alloc(len: usize) ?[*]u8 {
    if (len == 0) return null;
    const block = heap.alloc(u8, len) catch return null;
    return block.ptr;
}

pub export fn gm_dealloc(ptr: ?[*]u8, len: usize) void {
    const p = ptr orelse return;
    if (len == 0) return;
    heap.free(p[0..len]);
}

/// How long a signed credential is on the wire, so a host can size a check before it makes one.
pub export fn gm_signed_len() usize {
    return wire.signed_len;
}

/// How long the bytes a signature is made over are. A host builds a credential into a buffer of
/// this size, so no binding carries the number itself and none of them can carry a stale one.
pub export fn gm_preimage_len() usize {
    return cred.preimage_len;
}

/// How long a verified badge is on the wire.
pub export fn gm_verified_len() usize {
    return wire.verified_len;
}

/// The public key a seed belongs to. An issuer names its key in every credential it signs, so a
/// host needs this before it can build one.
pub export fn gm_public_key(seed_ptr: ?[*]const u8, seed_len: usize, out: ?*GmBuffer) Status {
    const seed = bytesIn(seed_ptr, seed_len);
    if (seed.len != 32) return .bad_argument;
    const pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch return .bad_argument;
    give(out, &pair.public_key.bytes) catch |e| return statusFor(e);
    return .ok;
}

/// Signs a credential. The bytes in are the preimage exactly as this library lays it out; the
/// bytes out are that preimage followed by the signature. The issuer named inside must be the
/// key the seed belongs to, so a credential can never claim one issuer and be signed by another.
pub export fn gm_sign(seed_ptr: ?[*]const u8, seed_len: usize, cred_ptr: ?[*]const u8, cred_len: usize, out: ?*GmBuffer) Status {
    const seed = bytesIn(seed_ptr, seed_len);
    if (seed.len != 32) return .bad_argument;
    const body = bytesIn(cred_ptr, cred_len);
    if (body.len != cred.preimage_len) return .bad_argument;

    // Read it back through the wire shape so the fields are the ones this library would have
    // written, rather than whatever the caller believed it was sending.
    var padded: [wire.signed_len]u8 = undefined;
    @memcpy(padded[0..cred.preimage_len], body);
    @memset(padded[cred.preimage_len..], 0);
    const parsed = wire.takeSigned(&padded) catch |e| return statusFor(e);

    const pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch return .bad_argument;
    const item = cred.sign(pair, parsed.cred) catch |e| return statusFor(e);
    var bytes: [wire.signed_len]u8 = undefined;
    wire.putSigned(item, &bytes);
    give(out, &bytes) catch |e| return statusFor(e);
    return .ok;
}

const Lists = struct {
    roots: chain.Roots,
    revoked: chain.Revoked,
    root_store: [max_roots][32]u8,
    revoked_store: []([16]u8),

    fn open(roots_bytes: []const u8, revoked_bytes: []const u8) !Lists {
        var self: Lists = undefined;
        self.roots = try wire.takeRoots(roots_bytes, &self.root_store);
        if (revoked_bytes.len < 4) return error.WrongLength;
        const count = std.mem.readInt(u32, revoked_bytes[0..4], .big);
        if (count > max_revoked) return error.BadCount;
        self.revoked_store = try heap.alloc([16]u8, count);
        errdefer heap.free(self.revoked_store);
        self.revoked = try wire.takeRevoked(revoked_bytes, self.revoked_store);
        return self;
    }

    fn close(self: *Lists) void {
        heap.free(self.revoked_store);
    }
};

/// Checks a badge Goss signed itself, and writes what it says. The roots and the revocation list
/// are the caller's, so this answers with no network and no clock of its own: the moment to check
/// against is given too, because a client with a wrong clock should fail the same way everywhere.
pub export fn gm_verify_direct(
    signed_ptr: ?[*]const u8,
    signed_len_in: usize,
    roots_ptr: ?[*]const u8,
    roots_len: usize,
    revoked_ptr: ?[*]const u8,
    revoked_len: usize,
    now: i64,
    out: ?*GmBuffer,
) Status {
    const item = wire.takeSigned(bytesIn(signed_ptr, signed_len_in)) catch |e| return statusFor(e);
    var lists = Lists.open(bytesIn(roots_ptr, roots_len), bytesIn(revoked_ptr, revoked_len)) catch |e| return statusFor(e);
    defer lists.close();
    const seen = chain.verifyDirect(item, lists.roots, lists.revoked, now) catch |e| return statusFor(e);
    var bytes: [wire.verified_len]u8 = undefined;
    wire.putVerified(seen, &bytes);
    give(out, &bytes) catch |e| return statusFor(e);
    return .ok;
}

/// Checks a badge an organization issued, walking its capability back to a root. The scope is
/// checked here rather than trusted, and revoking the capability's id refuses every badge that
/// flowed from it without any of them being touched.
pub export fn gm_verify_staff(
    staff_ptr: ?[*]const u8,
    staff_len: usize,
    cap_ptr: ?[*]const u8,
    cap_len: usize,
    roots_ptr: ?[*]const u8,
    roots_len: usize,
    revoked_ptr: ?[*]const u8,
    revoked_len: usize,
    now: i64,
    out: ?*GmBuffer,
) Status {
    const staff = wire.takeSigned(bytesIn(staff_ptr, staff_len)) catch |e| return statusFor(e);
    const capability = wire.takeSigned(bytesIn(cap_ptr, cap_len)) catch |e| return statusFor(e);
    var lists = Lists.open(bytesIn(roots_ptr, roots_len), bytesIn(revoked_ptr, revoked_len)) catch |e| return statusFor(e);
    defer lists.close();
    const seen = chain.verifyStaff(staff, capability, lists.roots, lists.revoked, now) catch |e| return statusFor(e);
    var bytes: [wire.verified_len]u8 = undefined;
    wire.putVerified(seen, &bytes);
    give(out, &bytes) catch |e| return statusFor(e);
    return .ok;
}

/// Signs a revocation snapshot: the ids given, under the seed's key, at the sequence and moment
/// given. The bytes out are the whole snapshot, ready to hand to any verifier.
pub export fn gm_snapshot_sign(
    seed_ptr: ?[*]const u8,
    seed_len: usize,
    seq: u64,
    issued_at: i64,
    ids_ptr: ?[*]const u8,
    ids_len: usize,
    out: ?*GmBuffer,
) Status {
    const seed = bytesIn(seed_ptr, seed_len);
    if (seed.len != 32) return .bad_argument;
    const ids_bytes = bytesIn(ids_ptr, ids_len);
    if (ids_bytes.len % 16 != 0) return .bad_argument;
    const count = ids_bytes.len / 16;
    if (count > max_revoked) return .bad_argument;

    const ids = heap.alloc([16]u8, count) catch return .out_of_memory;
    defer heap.free(ids);
    for (0..count) |i| @memcpy(&ids[i], ids_bytes[i * 16 ..][0..16]);

    const pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch return .bad_argument;
    const item = revoke.sign(pair, .{
        .issuer = pair.public_key.bytes,
        .seq = seq,
        .issued_at = issued_at,
        .ids = ids,
    }) catch |e| return statusFor(e);

    const bytes = heap.alloc(u8, wire.snapshotLen(count)) catch return .out_of_memory;
    defer heap.free(bytes);
    wire.putSnapshot(item, bytes) catch |e| return statusFor(e);
    give(out, bytes) catch |e| return statusFor(e);
    return .ok;
}

/// Checks a snapshot against the roots and, if it is newer than the sequence the caller already
/// holds, writes the ids out for the caller to keep. An older one is refused: replaying an
/// earlier list must never bring a revoked badge back.
pub export fn gm_snapshot_open(
    snapshot_ptr: ?[*]const u8,
    snapshot_len: usize,
    roots_ptr: ?[*]const u8,
    roots_len: usize,
    held_seq: u64,
    out_ids: ?*GmBuffer,
    out_seq: ?*u64,
    out_issued_at: ?*i64,
) Status {
    const bytes = bytesIn(snapshot_ptr, snapshot_len);
    if (bytes.len < 32 + 8 + 8 + 4) return .bad_argument;
    const count = std.mem.readInt(u32, bytes[32 + 8 + 8 ..][0..4], .big);
    if (count > max_revoked) return .bad_argument;

    const store = heap.alloc([16]u8, count) catch return .out_of_memory;
    defer heap.free(store);
    const item = wire.takeSnapshot(bytes, store) catch |e| return statusFor(e);

    var root_store: [max_roots][32]u8 = undefined;
    const roots = wire.takeRoots(bytesIn(roots_ptr, roots_len), &root_store) catch |e| return statusFor(e);
    revoke.verify(item, roots) catch |e| return statusFor(e);
    if (item.snapshot.seq <= held_seq) return .stale;

    const flat = heap.alloc(u8, @as(usize, count) * 16) catch return .out_of_memory;
    defer heap.free(flat);
    for (item.snapshot.ids, 0..) |id, i| @memcpy(flat[i * 16 ..][0..16], &id);
    give(out_ids, flat) catch |e| return statusFor(e);
    if (out_seq) |cell| cell.* = item.snapshot.seq;
    if (out_issued_at) |cell| cell.* = item.snapshot.issued_at;
    return .ok;
}

const testing = std.testing;

fn seedOf(byte: u8) [32]u8 {
    return [_]u8{byte} ** 32;
}

test "the abi signs and checks a direct badge end to end" {
    var key_cell = GmBuffer{ .ptr = null, .len = 0 };
    const seed = seedOf(1);
    try testing.expectEqual(Status.ok, gm_public_key(&seed, seed.len, &key_cell));
    defer gm_free(&key_cell);
    const issuer = key_cell.ptr.?[0..32].*;

    const base = cred.Credential{
        .kind = .individual,
        .issuer = issuer,
        .subject = .{ .chain = 1, .address = [_]u8{9} ** 20 },
        .issued_at = 100,
        .id = [_]u8{4} ** 16,
    };
    var body: [cred.preimage_len]u8 = undefined;
    cred.preimage(&(try base.withCategory("journalist")), &body);

    var signed_cell = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.ok, gm_sign(&seed, seed.len, &body, body.len, &signed_cell));
    defer gm_free(&signed_cell);

    var roots: [4 + 32]u8 = undefined;
    std.mem.writeInt(u32, roots[0..4], 1, .big);
    @memcpy(roots[4..], &issuer);
    var none: [4]u8 = undefined;
    std.mem.writeInt(u32, &none, 0, .big);

    var seen_cell = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.ok, gm_verify_direct(signed_cell.ptr, signed_cell.len, &roots, roots.len, &none, none.len, 500, &seen_cell));
    defer gm_free(&seen_cell);
    const seen = try wire.takeVerified(seen_cell.ptr.?[0..seen_cell.len]);
    try testing.expectEqual(cred.Kind.individual, seen.kind);
    try testing.expectEqualStrings("journalist", seen.categoryName());
}

test "the abi refuses a badge signed by a key outside the roots" {
    var key_cell = GmBuffer{ .ptr = null, .len = 0 };
    const seed = seedOf(2);
    try testing.expectEqual(Status.ok, gm_public_key(&seed, seed.len, &key_cell));
    defer gm_free(&key_cell);
    const issuer = key_cell.ptr.?[0..32].*;

    const base = cred.Credential{
        .kind = .individual,
        .issuer = issuer,
        .subject = .{ .chain = 1, .address = [_]u8{1} ** 20 },
        .issued_at = 10,
        .id = [_]u8{1} ** 16,
    };
    var body: [cred.preimage_len]u8 = undefined;
    cred.preimage(&base, &body);
    var signed_cell = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.ok, gm_sign(&seed, seed.len, &body, body.len, &signed_cell));
    defer gm_free(&signed_cell);

    var roots: [4 + 32]u8 = undefined;
    std.mem.writeInt(u32, roots[0..4], 1, .big);
    @memset(roots[4..], 0xAA);
    var none: [4]u8 = undefined;
    std.mem.writeInt(u32, &none, 0, .big);
    var seen_cell = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.untrusted_issuer, gm_verify_direct(signed_cell.ptr, signed_cell.len, &roots, roots.len, &none, none.len, 500, &seen_cell));
    try testing.expect(seen_cell.ptr == null);
}

test "the abi signs a snapshot, opens it once, and refuses it the second time" {
    const seed = seedOf(3);
    var key_cell = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.ok, gm_public_key(&seed, seed.len, &key_cell));
    defer gm_free(&key_cell);
    const issuer = key_cell.ptr.?[0..32].*;

    const ids = [_]u8{0xAB} ** 16 ++ [_]u8{0xCD} ** 16;
    var snap_cell = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.ok, gm_snapshot_sign(&seed, seed.len, 5, 900, &ids, ids.len, &snap_cell));
    defer gm_free(&snap_cell);

    var roots: [4 + 32]u8 = undefined;
    std.mem.writeInt(u32, roots[0..4], 1, .big);
    @memcpy(roots[4..], &issuer);

    var ids_cell = GmBuffer{ .ptr = null, .len = 0 };
    var seq: u64 = 0;
    var at: i64 = 0;
    try testing.expectEqual(Status.ok, gm_snapshot_open(snap_cell.ptr, snap_cell.len, &roots, roots.len, 0, &ids_cell, &seq, &at));
    defer gm_free(&ids_cell);
    try testing.expectEqual(@as(u64, 5), seq);
    try testing.expectEqual(@as(i64, 900), at);
    try testing.expectEqual(@as(usize, 32), ids_cell.len);

    var again = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.stale, gm_snapshot_open(snap_cell.ptr, snap_cell.len, &roots, roots.len, 5, &again, null, null));
}

test "freeing a cell that was never filled is safe" {
    var cell = GmBuffer{ .ptr = null, .len = 0 };
    gm_free(&cell);
    gm_free(null);
    try testing.expect(cell.ptr == null);
}

test "an empty answer carries no address at all" {
    // The bug this is here for: a zero-length allocation answers an aligned sentinel pointer
    // rather than a real address, and a web host that built a view at that offset threw on every
    // page load, on a deployment that had simply revoked nobody.
    var cell = GmBuffer{ .ptr = null, .len = 0 };
    try give(&cell, &.{});
    try testing.expect(cell.ptr == null);
    try testing.expectEqual(@as(usize, 0), cell.len);
    gm_free(&cell);

    // The path a client actually takes: sign an empty snapshot, open it, and get nothing back
    // that anybody has to dereference.
    const seed = seedOf(11);
    var key_cell = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.ok, gm_public_key(&seed, seed.len, &key_cell));
    defer gm_free(&key_cell);
    const issuer = key_cell.ptr.?[0..32].*;

    var snap = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.ok, gm_snapshot_sign(&seed, seed.len, 1, 900, null, 0, &snap));
    defer gm_free(&snap);

    var roots: [4 + 32]u8 = undefined;
    std.mem.writeInt(u32, roots[0..4], 1, .big);
    @memcpy(roots[4..], &issuer);
    var ids = GmBuffer{ .ptr = null, .len = 0 };
    try testing.expectEqual(Status.ok, gm_snapshot_open(snap.ptr, snap.len, &roots, roots.len, 0, &ids, null, null));
    defer gm_free(&ids);
    try testing.expect(ids.ptr == null);
    try testing.expectEqual(@as(usize, 0), ids.len);
}
