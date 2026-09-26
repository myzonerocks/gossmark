//! What crosses a boundary. Every shape here is fixed-width and big-endian, the way the signed
//! preimage is, so the four SDKs and the api all read and write the same bytes and a vector can
//! hold them to it. Nothing is length-prefixed except a list's own count, and a count is always
//! read before it is trusted.
const std = @import("std");
const cred = @import("cred.zig");
const chain = @import("chain.zig");
const revoke = @import("revoke.zig");

pub const Error = error{
    /// The bytes are shorter than the shape they claim to be, or longer than it can hold.
    WrongLength,
    /// A kind byte that is not one of the four.
    UnknownKind,
    /// A count that does not match the bytes that follow it.
    BadCount,
};

/// A signed credential on the wire: the preimage exactly as it is signed, then the signature.
/// Putting the signed bytes on the wire verbatim means a reader never rebuilds a preimage from
/// parsed fields and never has a chance to rebuild it differently.
pub const signed_len = cred.preimage_len + 64;

pub fn putSigned(item: cred.Signed, out: *[signed_len]u8) void {
    var bytes: [cred.preimage_len]u8 = undefined;
    cred.preimage(&item.cred, &bytes);
    @memcpy(out[0..cred.preimage_len], &bytes);
    @memcpy(out[cred.preimage_len..][0..64], &item.signature);
}

pub fn takeSigned(bytes: []const u8) Error!cred.Signed {
    if (bytes.len != signed_len) return error.WrongLength;
    var at: usize = 0;
    const kind = cred.Kind.fromByte(bytes[at]) orelse return error.UnknownKind;
    at += 1;
    var item = cred.Signed{
        .cred = .{ .kind = kind, .issuer = undefined, .subject = undefined, .issued_at = 0, .id = undefined },
        .signature = undefined,
    };
    @memcpy(&item.cred.issuer, bytes[at..][0..32]);
    at += 32;
    item.cred.subject.chain = std.mem.readInt(u64, bytes[at..][0..8], .big);
    at += 8;
    @memcpy(&item.cred.subject.address, bytes[at..][0..20]);
    at += 20;
    @memcpy(&item.cred.category, bytes[at..][0..cred.category_max]);
    at += cred.category_max;
    item.cred.issued_at = std.mem.readInt(i64, bytes[at..][0..8], .big);
    at += 8;
    item.cred.expires_at = std.mem.readInt(i64, bytes[at..][0..8], .big);
    at += 8;
    @memcpy(&item.cred.id, bytes[at..][0..16]);
    at += 16;
    @memcpy(&item.cred.delegate, bytes[at..][0..32]);
    at += 32;
    @memcpy(&item.signature, bytes[at..][0..64]);
    return item;
}

/// A verified badge on the wire: what a client draws from, and the only shape it should draw
/// from, because a credential that has not been through the chain has not been checked.
pub const verified_len = 1 + 8 + 20 + cred.category_max + 8 + 8 + 32 + 1 + 8 + 20;

pub fn putVerified(seen: chain.Verified, out: *[verified_len]u8) void {
    var at: usize = 0;
    out[at] = @intFromEnum(seen.kind);
    at += 1;
    std.mem.writeInt(u64, out[at..][0..8], seen.subject.chain, .big);
    at += 8;
    @memcpy(out[at..][0..20], &seen.subject.address);
    at += 20;
    @memcpy(out[at..][0..cred.category_max], &seen.category);
    at += cred.category_max;
    std.mem.writeInt(i64, out[at..][0..8], seen.issued_at, .big);
    at += 8;
    std.mem.writeInt(i64, out[at..][0..8], seen.expires_at, .big);
    at += 8;
    @memcpy(out[at..][0..32], &seen.issuer);
    at += 32;
    if (seen.via) |via| {
        out[at] = 1;
        at += 1;
        std.mem.writeInt(u64, out[at..][0..8], via.chain, .big);
        at += 8;
        @memcpy(out[at..][0..20], &via.address);
        at += 20;
    } else {
        // Written out in full rather than left short, so the shape is one length always and a
        // reader never has to know the answer before it can find the end.
        @memset(out[at..][0 .. 1 + 8 + 20], 0);
        at += 1 + 8 + 20;
    }
    std.debug.assert(at == verified_len);
}

pub fn takeVerified(bytes: []const u8) Error!chain.Verified {
    if (bytes.len != verified_len) return error.WrongLength;
    var at: usize = 0;
    const kind = cred.Kind.fromByte(bytes[at]) orelse return error.UnknownKind;
    at += 1;
    var seen = chain.Verified{
        .kind = kind,
        .subject = undefined,
        .category = undefined,
        .issued_at = 0,
        .expires_at = 0,
        .issuer = undefined,
    };
    seen.subject.chain = std.mem.readInt(u64, bytes[at..][0..8], .big);
    at += 8;
    @memcpy(&seen.subject.address, bytes[at..][0..20]);
    at += 20;
    @memcpy(&seen.category, bytes[at..][0..cred.category_max]);
    at += cred.category_max;
    seen.issued_at = std.mem.readInt(i64, bytes[at..][0..8], .big);
    at += 8;
    seen.expires_at = std.mem.readInt(i64, bytes[at..][0..8], .big);
    at += 8;
    @memcpy(&seen.issuer, bytes[at..][0..32]);
    at += 32;
    if (bytes[at] == 1) {
        at += 1;
        var via = cred.Subject{ .chain = 0, .address = undefined };
        via.chain = std.mem.readInt(u64, bytes[at..][0..8], .big);
        at += 8;
        @memcpy(&via.address, bytes[at..][0..20]);
        seen.via = via;
    }
    return seen;
}

/// A list of root keys: the count, then each key. The only thing a verifier is told out of band,
/// so it is a shape of its own rather than something squeezed into another call.
pub fn takeRoots(bytes: []const u8, into: [][32]u8) Error!chain.Roots {
    if (bytes.len < 4) return error.WrongLength;
    const count = std.mem.readInt(u32, bytes[0..4], .big);
    if (bytes.len != 4 + @as(usize, count) * 32) return error.BadCount;
    if (count > into.len) return error.BadCount;
    for (0..count) |i| @memcpy(&into[i], bytes[4 + i * 32 ..][0..32]);
    return .{ .keys = into[0..count] };
}

/// A list of revoked ids: the count, then each id.
pub fn takeRevoked(bytes: []const u8, into: [][16]u8) Error!chain.Revoked {
    if (bytes.len < 4) return error.WrongLength;
    const count = std.mem.readInt(u32, bytes[0..4], .big);
    if (bytes.len != 4 + @as(usize, count) * 16) return error.BadCount;
    if (count > into.len) return error.BadCount;
    for (0..count) |i| @memcpy(&into[i], bytes[4 + i * 16 ..][0..16]);
    return .{ .ids = into[0..count] };
}

/// A signed revocation snapshot: the fields, the count, every id, then the signature.
pub fn snapshotLen(count: usize) usize {
    return 32 + 8 + 8 + 4 + count * 16 + 64;
}

pub fn takeSnapshot(bytes: []const u8, into: [][16]u8) Error!revoke.Signed {
    if (bytes.len < 32 + 8 + 8 + 4) return error.WrongLength;
    var at: usize = 0;
    var item = revoke.Signed{
        .snapshot = .{ .issuer = undefined, .seq = 0, .issued_at = 0, .ids = &.{} },
        .signature = undefined,
    };
    @memcpy(&item.snapshot.issuer, bytes[at..][0..32]);
    at += 32;
    item.snapshot.seq = std.mem.readInt(u64, bytes[at..][0..8], .big);
    at += 8;
    item.snapshot.issued_at = std.mem.readInt(i64, bytes[at..][0..8], .big);
    at += 8;
    const count = std.mem.readInt(u32, bytes[at..][0..4], .big);
    at += 4;
    if (bytes.len != snapshotLen(count)) return error.BadCount;
    if (count > into.len) return error.BadCount;
    for (0..count) |i| @memcpy(&into[i], bytes[at + i * 16 ..][0..16]);
    at += @as(usize, count) * 16;
    item.snapshot.ids = into[0..count];
    @memcpy(&item.signature, bytes[at..][0..64]);
    return item;
}

pub fn putSnapshot(item: revoke.Signed, out: []u8) Error!void {
    if (out.len != snapshotLen(item.snapshot.ids.len)) return error.WrongLength;
    var at: usize = 0;
    @memcpy(out[at..][0..32], &item.snapshot.issuer);
    at += 32;
    std.mem.writeInt(u64, out[at..][0..8], item.snapshot.seq, .big);
    at += 8;
    std.mem.writeInt(i64, out[at..][0..8], item.snapshot.issued_at, .big);
    at += 8;
    std.mem.writeInt(u32, out[at..][0..4], @intCast(item.snapshot.ids.len), .big);
    at += 4;
    for (item.snapshot.ids, 0..) |id, i| @memcpy(out[at + i * 16 ..][0..16], &id);
    at += item.snapshot.ids.len * 16;
    @memcpy(out[at..][0..64], &item.signature);
}

const Ed25519 = std.crypto.sign.Ed25519;

test "a signed credential goes out and comes back the same" {
    const pair = try Ed25519.KeyPair.generateDeterministic([_]u8{12} ** 32);
    const base = cred.Credential{
        .kind = .staff,
        .issuer = pair.public_key.bytes,
        .subject = .{ .chain = 11155111, .address = [_]u8{0xAB} ** 20 },
        .issued_at = 1_700_000_000,
        .expires_at = 1_731_536_000,
        .id = [_]u8{0xCD} ** 16,
        .delegate = [_]u8{0xEF} ** 32,
    };
    const item = try cred.sign(pair, try base.withCategory("journalist"));
    var bytes: [signed_len]u8 = undefined;
    putSigned(item, &bytes);
    const back = try takeSigned(&bytes);
    try std.testing.expectEqual(item.cred.kind, back.cred.kind);
    try std.testing.expectEqual(item.cred.issued_at, back.cred.issued_at);
    try std.testing.expectEqual(item.cred.expires_at, back.cred.expires_at);
    try std.testing.expectEqualSlices(u8, &item.cred.delegate, &back.cred.delegate);
    try std.testing.expectEqualStrings("journalist", back.cred.categoryName());
    // The point of putting the signed bytes on the wire verbatim: what comes back still verifies.
    try cred.verify(back);
}

test "bytes of the wrong length are refused rather than read short" {
    var bytes: [signed_len - 1]u8 = [_]u8{0} ** (signed_len - 1);
    try std.testing.expectError(error.WrongLength, takeSigned(&bytes));
}

test "a kind byte nobody defined is refused" {
    var bytes: [signed_len]u8 = [_]u8{0} ** signed_len;
    bytes[0] = 9;
    try std.testing.expectError(error.UnknownKind, takeSigned(&bytes));
}

test "a verified badge carries its organization across the wire" {
    const seen = chain.Verified{
        .kind = .staff,
        .subject = .{ .chain = 1, .address = [_]u8{2} ** 20 },
        .category = [_]u8{0} ** cred.category_max,
        .issued_at = 5,
        .expires_at = 9,
        .issuer = [_]u8{3} ** 32,
        .via = .{ .chain = 1, .address = [_]u8{4} ** 20 },
    };
    var bytes: [verified_len]u8 = undefined;
    putVerified(seen, &bytes);
    const back = try takeVerified(&bytes);
    try std.testing.expect(back.via.?.eql(seen.via.?));
}

test "a direct badge comes back with no organization on it" {
    const seen = chain.Verified{
        .kind = .individual,
        .subject = .{ .chain = 1, .address = [_]u8{2} ** 20 },
        .category = [_]u8{0} ** cred.category_max,
        .issued_at = 5,
        .expires_at = 0,
        .issuer = [_]u8{3} ** 32,
    };
    var bytes: [verified_len]u8 = undefined;
    putVerified(seen, &bytes);
    const back = try takeVerified(&bytes);
    try std.testing.expect(back.via == null);
}

test "a count that disagrees with the bytes after it is refused" {
    var bytes: [4 + 32]u8 = [_]u8{0} ** (4 + 32);
    std.mem.writeInt(u32, bytes[0..4], 2, .big);
    var into: [4][32]u8 = undefined;
    try std.testing.expectError(error.BadCount, takeRoots(&bytes, &into));
}

test "a list longer than the room given is refused rather than overrunning it" {
    var bytes: [4 + 3 * 16]u8 = [_]u8{0} ** (4 + 3 * 16);
    std.mem.writeInt(u32, bytes[0..4], 3, .big);
    var into: [2][16]u8 = undefined;
    try std.testing.expectError(error.BadCount, takeRevoked(&bytes, &into));
}

test "a snapshot goes out and comes back still verifying" {
    const root = try Ed25519.KeyPair.generateDeterministic([_]u8{13} ** 32);
    const ids = [_][16]u8{ [_]u8{1} ** 16, [_]u8{2} ** 16 };
    const item = try revoke.sign(root, .{ .issuer = root.public_key.bytes, .seq = 7, .issued_at = 1234, .ids = &ids });

    var bytes: [snapshotLen(2)]u8 = undefined;
    try putSnapshot(item, &bytes);
    var into: [8][16]u8 = undefined;
    const back = try takeSnapshot(&bytes, &into);
    try std.testing.expectEqual(@as(u64, 7), back.snapshot.seq);
    try std.testing.expectEqual(@as(usize, 2), back.snapshot.ids.len);
    try revoke.verify(back, .{ .keys = &.{root.public_key.bytes} });
}
