const std = @import("std");
const cred = @import("cred.zig");

/// The keys a verifier trusts to begin with, and the only thing it has to be told out of band.
/// Everything else in the design is reachable from here by signature alone, which is what lets
/// a badge be checked with no server in the loop.
///
/// More than one, because a root is rotated on a published schedule: during a rotation the old
/// key still has live credentials under it and the new one is already issuing.
pub const Roots = struct {
    keys: []const [32]u8,

    pub fn trusts(self: Roots, key: [32]u8) bool {
        for (self.keys) |known| {
            if (std.mem.eql(u8, &known, &key)) return true;
        }
        return false;
    }
};

/// What the caller knows to be revoked, as a set of credential ids. The engine never fetches it:
/// a verifier holds the latest signed snapshot it has seen and answers from that, so a check
/// works offline and a stale snapshot is the caller's problem to notice rather than a silent
/// pass. See revoke.zig for the snapshot itself.
pub const Revoked = struct {
    ids: []const [16]u8,

    pub fn has(self: Revoked, id: [16]u8) bool {
        for (self.ids) |gone| {
            if (std.mem.eql(u8, &gone, &id)) return true;
        }
        return false;
    }

    pub const none = Revoked{ .ids = &.{} };
};

pub const Error = error{
    /// The signature does not verify under the key the credential names.
    BadSignature,
    /// The issuer is not a key this verifier trusts, or not the key the chain says it must be.
    UntrustedIssuer,
    /// Outside its own window: not yet issued, or expired.
    NotLive,
    /// Named in the revocation snapshot the caller holds.
    Revoked,
    /// The wrong kind of credential for the question being asked.
    WrongKind,
    /// A staff badge whose category is not the one its org was approved for.
    OutOfScope,
    /// A capability that delegates to no key at all.
    NoDelegate,
};

/// What a verified badge says, once the whole chain has been walked. A caller draws from this
/// and never from the credential alone, because a credential alone has not been checked.
pub const Verified = struct {
    kind: cred.Kind,
    subject: cred.Subject,
    /// Held as its own bytes rather than as a slice into the credential: the credential is
    /// passed by value, so a slice into it would dangle the moment the check returned, and a
    /// verified badge has to outlive the thing it was read from.
    category: [cred.category_max]u8,
    issued_at: i64,
    expires_at: i64,
    /// The key that signed the badge itself: root for a direct badge, the organization for a
    /// staff badge. This is what the panel shows when somebody taps the checkmark.
    issuer: [32]u8,
    /// For a staff badge, the organization whose wallet the capability was granted to. The
    /// panel reads "verified by this organization, itself verified by Goss" from here.
    via: ?cred.Subject = null,

    /// The category as it reads, without its padding.
    pub fn categoryName(self: *const Verified) []const u8 {
        const end = std.mem.indexOfScalar(u8, &self.category, 0) orelse cred.category_max;
        return self.category[0..end];
    }
};

/// A badge Goss issued itself: an individual or an organization. One signature, checked against
/// the roots, plus the window and the revocation snapshot. Nothing about a handle is consulted,
/// here or anywhere below: the subject is the wallet-bound identifier and nothing else.
pub fn verifyDirect(item: cred.Signed, roots: Roots, revoked: Revoked, now: i64) Error!Verified {
    switch (item.cred.kind) {
        .individual, .organization => {},
        else => return error.WrongKind,
    }
    if (!roots.trusts(item.cred.issuer)) return error.UntrustedIssuer;
    try cred.verify(item);
    if (!item.cred.live(now)) return error.NotLive;
    if (revoked.has(item.cred.id)) return error.Revoked;
    return .{
        .kind = item.cred.kind,
        .subject = item.cred.subject,
        .category = item.cred.category,
        .issued_at = item.cred.issued_at,
        .expires_at = item.cred.expires_at,
        .issuer = item.cred.issuer,
    };
}

/// A badge an organization issued to its own staff. Three links, checked in order, and every one
/// of them must hold:
///
///   the capability is signed by a root key and is live and unrevoked,
///   the staff badge is signed by the very key that capability delegates to,
///   the staff badge's category is the one the capability was granted for.
///
/// The last of those is the scope, and it is checked here rather than trusted: an organization
/// approved for one category cannot issue for another, whatever its console would let it try.
///
/// Pulling the capability is therefore the kill switch the design asks for. Every staff badge
/// runs through it, so revoking that one id invalidates all of them at once, everywhere, without
/// touching a single staff badge.
pub fn verifyStaff(staff: cred.Signed, capability: cred.Signed, roots: Roots, revoked: Revoked, now: i64) Error!Verified {
    if (staff.cred.kind != .staff) return error.WrongKind;
    if (capability.cred.kind != .capability) return error.WrongKind;

    if (!roots.trusts(capability.cred.issuer)) return error.UntrustedIssuer;
    try cred.verify(capability);
    if (!capability.cred.live(now)) return error.NotLive;
    if (revoked.has(capability.cred.id)) return error.Revoked;

    const delegate = capability.cred.delegate;
    if (std.mem.allEqual(u8, &delegate, 0)) return error.NoDelegate;
    if (!std.mem.eql(u8, &staff.cred.issuer, &delegate)) return error.UntrustedIssuer;
    try cred.verify(staff);
    if (!staff.cred.live(now)) return error.NotLive;
    if (revoked.has(staff.cred.id)) return error.Revoked;

    if (!std.mem.eql(u8, staff.cred.categoryName(), capability.cred.categoryName())) return error.OutOfScope;

    return .{
        .kind = .staff,
        .subject = staff.cred.subject,
        .category = staff.cred.category,
        .issued_at = staff.cred.issued_at,
        .expires_at = staff.cred.expires_at,
        .issuer = staff.cred.issuer,
        .via = capability.cred.subject,
    };
}

const Ed25519 = std.crypto.sign.Ed25519;

const Fixture = struct {
    root: Ed25519.KeyPair,
    org: Ed25519.KeyPair,
    roots: [1][32]u8,

    fn make() !Fixture {
        const root = try Ed25519.KeyPair.generateDeterministic([_]u8{11} ** 32);
        const org = try Ed25519.KeyPair.generateDeterministic([_]u8{22} ** 32);
        return .{ .root = root, .org = org, .roots = .{root.public_key.bytes} };
    }

    fn trusted(self: *const Fixture) Roots {
        return .{ .keys = &self.roots };
    }

    fn direct(self: *const Fixture, kind: cred.Kind, category: []const u8, id: u8) !cred.Signed {
        const base = cred.Credential{
            .kind = kind,
            .issuer = self.root.public_key.bytes,
            .subject = .{ .chain = 1, .address = [_]u8{id} ** 20 },
            .issued_at = 100,
            .id = [_]u8{id} ** 16,
        };
        return cred.sign(self.root, try base.withCategory(category));
    }

    fn capability(self: *const Fixture, category: []const u8, expires: i64) !cred.Signed {
        const base = cred.Credential{
            .kind = .capability,
            .issuer = self.root.public_key.bytes,
            .subject = .{ .chain = 1, .address = [_]u8{0xAA} ** 20 },
            .issued_at = 100,
            .expires_at = expires,
            .id = [_]u8{0xCA} ** 16,
            .delegate = self.org.public_key.bytes,
        };
        return cred.sign(self.root, try base.withCategory(category));
    }

    fn staff(self: *const Fixture, category: []const u8, expires: i64) !cred.Signed {
        const base = cred.Credential{
            .kind = .staff,
            .issuer = self.org.public_key.bytes,
            .subject = .{ .chain = 1, .address = [_]u8{0xBB} ** 20 },
            .issued_at = 100,
            .expires_at = expires,
            .id = [_]u8{0xBB} ** 16,
        };
        return cred.sign(self.org, try base.withCategory(category));
    }
};

test "a badge Goss signed itself verifies against the roots" {
    const f = try Fixture.make();
    const badge = try f.direct(.individual, "journalist", 1);
    const seen = try verifyDirect(badge, f.trusted(), Revoked.none, 500);
    try std.testing.expectEqual(cred.Kind.individual, seen.kind);
    try std.testing.expectEqualStrings("journalist", seen.categoryName());
    try std.testing.expectEqual(@as(i64, 0), seen.expires_at);
}

test "a badge signed by a key the verifier does not trust is refused" {
    const f = try Fixture.make();
    const stranger = try Ed25519.KeyPair.generateDeterministic([_]u8{33} ** 32);
    const base = cred.Credential{
        .kind = .individual,
        .issuer = stranger.public_key.bytes,
        .subject = .{ .chain = 1, .address = [_]u8{1} ** 20 },
        .issued_at = 100,
        .id = [_]u8{1} ** 16,
    };
    const forged = try cred.sign(stranger, base);
    try std.testing.expectError(error.UntrustedIssuer, verifyDirect(forged, f.trusted(), Revoked.none, 500));
}

test "a revoked badge is refused even though its signature is good" {
    const f = try Fixture.make();
    const badge = try f.direct(.organization, "news", 2);
    try cred.verify(badge);
    const gone = Revoked{ .ids = &.{badge.cred.id} };
    try std.testing.expectError(error.Revoked, verifyDirect(badge, f.trusted(), gone, 500));
}

test "a staff badge walks its capability back to root" {
    const f = try Fixture.make();
    const cap = try f.capability("journalist", 10_000);
    const badge = try f.staff("journalist", 5_000);
    const seen = try verifyStaff(badge, cap, f.trusted(), Revoked.none, 500);
    try std.testing.expectEqual(cred.Kind.staff, seen.kind);
    try std.testing.expectEqualStrings("journalist", seen.categoryName());
    // The panel reads the organization from here, so the chain has to carry it out.
    try std.testing.expect(seen.via.?.eql(cap.cred.subject));
}

test "an organization cannot issue outside the scope it was granted" {
    const f = try Fixture.make();
    const cap = try f.capability("journalist", 10_000);
    const badge = try f.staff("intern", 5_000);
    try std.testing.expectError(error.OutOfScope, verifyStaff(badge, cap, f.trusted(), Revoked.none, 500));
}

test "pulling one capability invalidates every badge that flowed from it" {
    const f = try Fixture.make();
    const cap = try f.capability("journalist", 10_000);
    const one = try f.staff("journalist", 5_000);
    try std.testing.expect((try verifyStaff(one, cap, f.trusted(), Revoked.none, 500)).kind == .staff);
    const pulled = Revoked{ .ids = &.{cap.cred.id} };
    try std.testing.expectError(error.Revoked, verifyStaff(one, cap, f.trusted(), pulled, 500));
}

test "a staff badge signed by a key the capability does not delegate to is refused" {
    const f = try Fixture.make();
    const cap = try f.capability("journalist", 10_000);
    const impostor = try Ed25519.KeyPair.generateDeterministic([_]u8{44} ** 32);
    const base = cred.Credential{
        .kind = .staff,
        .issuer = impostor.public_key.bytes,
        .subject = .{ .chain = 1, .address = [_]u8{0xBB} ** 20 },
        .issued_at = 100,
        .expires_at = 5_000,
        .id = [_]u8{0xBC} ** 16,
    };
    const forged = try cred.sign(impostor, try base.withCategory("journalist"));
    try std.testing.expectError(error.UntrustedIssuer, verifyStaff(forged, cap, f.trusted(), Revoked.none, 500));
}

test "a staff badge past its twelve months is not live" {
    const f = try Fixture.make();
    const cap = try f.capability("journalist", 10_000);
    const badge = try f.staff("journalist", 5_000);
    try std.testing.expectError(error.NotLive, verifyStaff(badge, cap, f.trusted(), Revoked.none, 5_000));
}

test "an expired capability takes its staff badges with it" {
    const f = try Fixture.make();
    const cap = try f.capability("journalist", 1_000);
    const badge = try f.staff("journalist", 50_000);
    try std.testing.expectError(error.NotLive, verifyStaff(badge, cap, f.trusted(), Revoked.none, 2_000));
}

test "a direct badge is not a staff badge and neither answers the other's question" {
    const f = try Fixture.make();
    const badge = try f.direct(.individual, "creator", 3);
    const cap = try f.capability("creator", 10_000);
    try std.testing.expectError(error.WrongKind, verifyStaff(badge, cap, f.trusted(), Revoked.none, 500));
    try std.testing.expectError(error.WrongKind, verifyDirect(cap, f.trusted(), Revoked.none, 500));
}

test "a rotated root keeps the old key's badges verifying" {
    const f = try Fixture.make();
    const next = try Ed25519.KeyPair.generateDeterministic([_]u8{55} ** 32);
    const old_badge = try f.direct(.individual, "official", 4);
    const base = cred.Credential{
        .kind = .individual,
        .issuer = next.public_key.bytes,
        .subject = .{ .chain = 1, .address = [_]u8{5} ** 20 },
        .issued_at = 100,
        .id = [_]u8{5} ** 16,
    };
    const new_badge = try cred.sign(next, try base.withCategory("official"));
    const both = Roots{ .keys = &.{ f.root.public_key.bytes, next.public_key.bytes } };
    try std.testing.expect((try verifyDirect(old_badge, both, Revoked.none, 500)).kind == .individual);
    try std.testing.expect((try verifyDirect(new_badge, both, Revoked.none, 500)).kind == .individual);
}
