const std = @import("std");
const cred = @import("cred.zig");

const Ed25519 = std.crypto.sign.Ed25519;

/// The domain tag a snapshot is signed under. Distinct from every credential tag, so a snapshot
/// can never be read as a credential nor a credential as a snapshot.
pub const tag = "gossmark/v1/revocations";

/// What has been revoked, as of a moment, signed by a root key.
///
/// A verifier holds the newest snapshot it has seen and answers from that, which is what lets a
/// badge be checked with no server in the loop. Two things make that safe rather than merely
/// convenient. It is signed, so nobody can hand a client a shorter list. And it is sequenced, so
/// an older snapshot cannot be replayed over a newer one to bring a revoked badge back: the
/// holder below refuses to go backwards.
///
/// The list is whole rather than a delta. A delta stream has to be replayed in order from a
/// known point, and a client that missed one shows a revoked checkmark until it notices; a whole
/// list cannot be behind in a way that shows too much.
pub const Snapshot = struct {
    /// Which root signed it.
    issuer: [32]u8,
    /// Rising by one each time a snapshot is published. Never reused.
    seq: u64,
    /// When it was published, seconds since the epoch. What a client shows when asking how
    /// fresh its own copy is.
    issued_at: i64,
    /// The ids revoked, in the order they were published. Any kind of credential may appear:
    /// revoking a capability's id is what takes down every badge that flowed from it.
    ids: []const [16]u8,
};

/// A snapshot and the signature over it.
pub const Signed = struct {
    snapshot: Snapshot,
    signature: [64]u8,
};

/// The digest a snapshot's signature is made over: the tag, then the fixed fields big-endian,
/// then the count, then every id in order. The count is signed as well as the ids, so a list
/// cannot be truncated and still verify.
fn digestOf(snapshot: Snapshot, out: *[32]u8) void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(tag);
    hasher.update(&snapshot.issuer);
    var scratch: [8]u8 = undefined;
    std.mem.writeInt(u64, &scratch, snapshot.seq, .big);
    hasher.update(&scratch);
    std.mem.writeInt(i64, &scratch, snapshot.issued_at, .big);
    hasher.update(&scratch);
    std.mem.writeInt(u64, &scratch, snapshot.ids.len, .big);
    hasher.update(&scratch);
    for (snapshot.ids) |id| hasher.update(&id);
    hasher.final(out);
}

pub fn sign(pair: Ed25519.KeyPair, snapshot: Snapshot) error{IssuerMismatch}!Signed {
    if (!std.mem.eql(u8, &snapshot.issuer, &pair.public_key.bytes)) return error.IssuerMismatch;
    var digest: [32]u8 = undefined;
    digestOf(snapshot, &digest);
    const sig = pair.sign(&digest, null) catch unreachable;
    return .{ .snapshot = snapshot, .signature = sig.toBytes() };
}

pub const Error = error{
    BadSignature,
    /// Signed by a key this verifier does not trust as a root.
    UntrustedIssuer,
    /// Older than, or the same age as, the snapshot already held. Refused so a revoked badge
    /// cannot be brought back by replaying an earlier list.
    Stale,
};

/// Whether a snapshot was signed by a root this verifier trusts.
pub fn verify(item: Signed, roots: @import("chain.zig").Roots) Error!void {
    if (!roots.trusts(item.snapshot.issuer)) return error.UntrustedIssuer;
    var digest: [32]u8 = undefined;
    digestOf(item.snapshot, &digest);
    const key = Ed25519.PublicKey.fromBytes(item.snapshot.issuer) catch return error.BadSignature;
    const sig = Ed25519.Signature.fromBytes(item.signature);
    sig.verify(&digest, key) catch return error.BadSignature;
}

/// What a verifier keeps between checks: the newest snapshot it has accepted. It never fetches
/// anything itself, so the caller decides when to offer a new one and this decides whether to
/// take it.
pub const Holder = struct {
    seq: u64 = 0,
    issued_at: i64 = 0,
    ids: []const [16]u8 = &.{},

    /// Takes a newer snapshot, or refuses it. The ids are borrowed, not copied, so the caller
    /// keeps the bytes alive for as long as the holder is used: an engine that allocated here
    /// would need an allocator on every client to do the one thing every client can do itself.
    pub fn accept(self: *Holder, item: Signed, roots: @import("chain.zig").Roots) Error!void {
        try verify(item, roots);
        if (item.snapshot.seq <= self.seq and self.issued_at != 0) return error.Stale;
        self.seq = item.snapshot.seq;
        self.issued_at = item.snapshot.issued_at;
        self.ids = item.snapshot.ids;
    }

    /// The set a chain walk asks.
    pub fn revoked(self: *const Holder) @import("chain.zig").Revoked {
        return .{ .ids = self.ids };
    }

    /// How old this verifier's copy is, in seconds. A client shows this rather than pretending
    /// an offline check is as fresh as an online one.
    pub fn ageAt(self: *const Holder, now: i64) i64 {
        if (self.issued_at == 0) return 0;
        return now - self.issued_at;
    }
};

const chain = @import("chain.zig");

test "a snapshot verifies under the root that signed it" {
    const root = try Ed25519.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const roots = chain.Roots{ .keys = &.{root.public_key.bytes} };
    const ids = [_][16]u8{[_]u8{1} ** 16};
    const item = try sign(root, .{ .issuer = root.public_key.bytes, .seq = 1, .issued_at = 500, .ids = &ids });
    try verify(item, roots);
}

test "a snapshot from a key that is not a root is refused" {
    const root = try Ed25519.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const stranger = try Ed25519.KeyPair.generateDeterministic([_]u8{99} ** 32);
    const roots = chain.Roots{ .keys = &.{root.public_key.bytes} };
    const item = try sign(stranger, .{ .issuer = stranger.public_key.bytes, .seq = 1, .issued_at = 500, .ids = &.{} });
    try std.testing.expectError(error.UntrustedIssuer, verify(item, roots));
}

test "a list cannot be shortened and still verify" {
    const root = try Ed25519.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const roots = chain.Roots{ .keys = &.{root.public_key.bytes} };
    const ids = [_][16]u8{ [_]u8{1} ** 16, [_]u8{2} ** 16 };
    var item = try sign(root, .{ .issuer = root.public_key.bytes, .seq = 1, .issued_at = 500, .ids = &ids });
    // Drop the badge somebody wanted back.
    item.snapshot.ids = ids[0..1];
    try std.testing.expectError(error.BadSignature, verify(item, roots));
}

test "an older snapshot cannot be replayed over a newer one" {
    const root = try Ed25519.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const roots = chain.Roots{ .keys = &.{root.public_key.bytes} };
    const gone = [_][16]u8{[_]u8{7} ** 16};
    const old = try sign(root, .{ .issuer = root.public_key.bytes, .seq = 1, .issued_at = 100, .ids = &.{} });
    const new = try sign(root, .{ .issuer = root.public_key.bytes, .seq = 2, .issued_at = 200, .ids = &gone });

    var holder = Holder{};
    try holder.accept(new, roots);
    try std.testing.expect(holder.revoked().has(gone[0]));
    try std.testing.expectError(error.Stale, holder.accept(old, roots));
    // The badge stays revoked: the replay changed nothing.
    try std.testing.expect(holder.revoked().has(gone[0]));
}

test "a holder with nothing in it takes the first snapshot it is offered" {
    const root = try Ed25519.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const roots = chain.Roots{ .keys = &.{root.public_key.bytes} };
    const first = try sign(root, .{ .issuer = root.public_key.bytes, .seq = 0, .issued_at = 50, .ids = &.{} });
    var holder = Holder{};
    try holder.accept(first, roots);
    try std.testing.expectEqual(@as(i64, 50), holder.issued_at);
    try std.testing.expectEqual(@as(i64, 450), holder.ageAt(500));
}

test "a badge falls the moment its id reaches the holder" {
    const root = try Ed25519.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const roots = chain.Roots{ .keys = &.{root.public_key.bytes} };
    const base = cred.Credential{
        .kind = .individual,
        .issuer = root.public_key.bytes,
        .subject = .{ .chain = 1, .address = [_]u8{3} ** 20 },
        .issued_at = 10,
        .id = [_]u8{0xEE} ** 16,
    };
    const badge = try cred.sign(root, try base.withCategory("creator"));

    var holder = Holder{};
    const clean = try sign(root, .{ .issuer = root.public_key.bytes, .seq = 1, .issued_at = 100, .ids = &.{} });
    try holder.accept(clean, roots);
    try std.testing.expect((try chain.verifyDirect(badge, roots, holder.revoked(), 500)).kind == .individual);

    const gone = [_][16]u8{badge.cred.id};
    const pulled = try sign(root, .{ .issuer = root.public_key.bytes, .seq = 2, .issued_at = 200, .ids = &gone });
    try holder.accept(pulled, roots);
    try std.testing.expectError(error.Revoked, chain.verifyDirect(badge, roots, holder.revoked(), 500));
}
