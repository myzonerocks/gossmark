const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;

/// What a credential says. The kind is part of the signed preimage, so a credential issued as
/// one kind can never be read as another: every kind carries its own domain tag and a signature
/// only verifies under the tag it was made with.
pub const Kind = enum(u8) {
    /// Goss vouches for a person. Permanent until revoked.
    individual = 1,
    /// Goss vouches for an organization. Permanent until revoked.
    organization = 2,
    /// Goss permits an organization to issue staff badges, in one category, up to a cap.
    /// A power rather than an identity, so it is the one credential that is re-reviewed.
    capability = 3,
    /// An organization vouches for its own staff. Signed by the org, chaining to root.
    staff = 4,

    /// The domain tag mixed into the preimage. Distinct per kind and never reused.
    pub fn tag(self: Kind) []const u8 {
        return switch (self) {
            .individual => "gossmark/v1/individual",
            .organization => "gossmark/v1/organization",
            .capability => "gossmark/v1/capability",
            .staff => "gossmark/v1/staff",
        };
    }
};

/// The longest a category may be. A category is a short word from a published list, not prose.
pub const category_max = 32;

/// The subject of every credential: a wallet-bound identifier, never a handle. A handle is a
/// display name its owner may change at will, and nothing in the chain may depend on it.
pub const Subject = struct {
    /// The chain the address lives on, as its EIP-155 id.
    chain: u64,
    /// The address itself, twenty bytes, as it appears on chain.
    address: [20]u8,

    pub fn eql(self: Subject, other: Subject) bool {
        return self.chain == other.chain and std.mem.eql(u8, &self.address, &other.address);
    }
};

/// One credential, before or after signing. The fields are exactly what the preimage covers:
/// anything a verifier must trust is signed, and nothing signed is left out of the preimage.
pub const Credential = struct {
    kind: Kind,
    /// Who signed it: Goss's root key, or an organization's delegated key.
    issuer: [32]u8,
    subject: Subject,
    /// The category this credential is for, left-aligned and zero-padded.
    category: [category_max]u8 = [_]u8{0} ** category_max,
    /// Seconds since the epoch. Both are signed, so neither can be stretched after the fact.
    issued_at: i64,
    /// Seconds since the epoch, or zero for a credential that does not expire. An identity does
    /// not lapse on its own; a relationship does, which is why only the staff badge sets this.
    expires_at: i64 = 0,
    /// What names this credential in the log and in a revocation. Random at issuance.
    id: [16]u8,
    /// For a capability, the organization signing key the power is delegated to. Zero for every
    /// other kind. It is signed like everything else, so a delegation cannot be pointed at a
    /// different key after the council approved it.
    delegate: [32]u8 = [_]u8{0} ** 32,

    /// Writes the category from a string, refusing one too long rather than truncating it: a
    /// silently shortened category would verify against a scope it was never granted.
    pub fn withCategory(self: Credential, name: []const u8) error{CategoryTooLong}!Credential {
        if (name.len > category_max) return error.CategoryTooLong;
        var out = self;
        out.category = [_]u8{0} ** category_max;
        @memcpy(out.category[0..name.len], name);
        return out;
    }

    /// The category as it reads, without its padding.
    pub fn categoryName(self: *const Credential) []const u8 {
        const end = std.mem.indexOfScalar(u8, &self.category, 0) orelse category_max;
        return self.category[0..end];
    }

    /// Whether this credential is inside its own window at the moment given. A credential with
    /// no expiry is inside it forever; one issued in the future is not yet inside it at all.
    pub fn live(self: *const Credential, now: i64) bool {
        if (now < self.issued_at) return false;
        return self.expires_at == 0 or now < self.expires_at;
    }
};

/// How many bytes the preimage of a credential takes. Fixed, because every field is fixed:
/// no length-prefixed anything, so two writers cannot disagree about where a field ends.
pub const preimage_len = 1 + 32 + 8 + 20 + category_max + 8 + 8 + 16 + 32;

/// The bytes a signature is made over. Deterministic by construction rather than by convention:
/// fields in a fixed order, fixed widths, integers big-endian, and the kind's domain tag in
/// front. Four SDKs will each rebuild this, and a JSON encoding would have let their key order
/// or their number formatting drift apart without anybody noticing until a signature failed in
/// the field. The frozen vectors hold all four to these exact bytes.
pub fn preimage(cred: *const Credential, out: *[preimage_len]u8) void {
    var at: usize = 0;
    out[at] = @intFromEnum(cred.kind);
    at += 1;
    @memcpy(out[at..][0..32], &cred.issuer);
    at += 32;
    std.mem.writeInt(u64, out[at..][0..8], cred.subject.chain, .big);
    at += 8;
    @memcpy(out[at..][0..20], &cred.subject.address);
    at += 20;
    @memcpy(out[at..][0..category_max], &cred.category);
    at += category_max;
    std.mem.writeInt(i64, out[at..][0..8], cred.issued_at, .big);
    at += 8;
    std.mem.writeInt(i64, out[at..][0..8], cred.expires_at, .big);
    at += 8;
    @memcpy(out[at..][0..16], &cred.id);
    at += 16;
    @memcpy(out[at..][0..32], &cred.delegate);
    at += 32;
    std.debug.assert(at == preimage_len);
}

/// A credential and the signature over it. The pair is what travels and what is stored; neither
/// half means anything alone.
pub const Signed = struct {
    cred: Credential,
    signature: [64]u8,
};

/// Signs a credential with the issuer's key. The issuer field must already name that key, so a
/// credential cannot claim one issuer and be signed by another.
pub fn sign(pair: Ed25519.KeyPair, cred: Credential) error{IssuerMismatch}!Signed {
    if (!std.mem.eql(u8, &cred.issuer, &pair.public_key.bytes)) return error.IssuerMismatch;
    var bytes: [preimage_len]u8 = undefined;
    // The tag goes in front of the fields rather than into them, so a preimage for one kind can
    // never be the preimage for another whatever the fields happen to hold.
    preimage(&cred, &bytes);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(cred.kind.tag());
    hasher.update(&bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const sig = pair.sign(&digest, null) catch unreachable;
    return .{ .cred = cred, .signature = sig.toBytes() };
}

pub const VerifyError = error{BadSignature};

/// Whether this credential was signed by the key it names. Nothing else: a signature that
/// verifies says who issued it, never that the issuer was allowed to, nor that it is still
/// live or unrevoked. Those are the chain's questions and are asked there.
pub fn verify(item: Signed) VerifyError!void {
    var bytes: [preimage_len]u8 = undefined;
    preimage(&item.cred, &bytes);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(item.cred.kind.tag());
    hasher.update(&bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const key = Ed25519.PublicKey.fromBytes(item.cred.issuer) catch return error.BadSignature;
    const sig = Ed25519.Signature.fromBytes(item.signature);
    sig.verify(&digest, key) catch return error.BadSignature;
}

test "a credential verifies under the key that signed it" {
    const pair = try Ed25519.KeyPair.generateDeterministic([_]u8{1} ** 32);
    const base = Credential{
        .kind = .individual,
        .issuer = pair.public_key.bytes,
        .subject = .{ .chain = 1, .address = [_]u8{7} ** 20 },
        .issued_at = 1000,
        .id = [_]u8{3} ** 16,
    };
    const cred = try base.withCategory("journalist");
    const item = try sign(pair, cred);
    try verify(item);
    try std.testing.expectEqualStrings("journalist", item.cred.categoryName());
}

test "a signature does not carry from one kind to another" {
    const pair = try Ed25519.KeyPair.generateDeterministic([_]u8{1} ** 32);
    const cred = Credential{
        .kind = .individual,
        .issuer = pair.public_key.bytes,
        .subject = .{ .chain = 1, .address = [_]u8{1} ** 20 },
        .issued_at = 1000,
        .id = [_]u8{2} ** 16,
    };
    var item = try sign(pair, cred);
    // The same fields, read as an organization badge: the domain tag differs, so the signature
    // is no longer a signature over what is being verified.
    item.cred.kind = .organization;
    try std.testing.expectError(error.BadSignature, verify(item));
}

test "a field changed after signing is a broken signature" {
    const pair = try Ed25519.KeyPair.generateDeterministic([_]u8{1} ** 32);
    const cred = Credential{
        .kind = .staff,
        .issuer = pair.public_key.bytes,
        .subject = .{ .chain = 1, .address = [_]u8{9} ** 20 },
        .issued_at = 100,
        .expires_at = 200,
        .id = [_]u8{4} ** 16,
    };
    var item = try sign(pair, cred);
    try verify(item);
    item.cred.expires_at = 1_000_000;
    try std.testing.expectError(error.BadSignature, verify(item));
}

test "a credential cannot name an issuer it was not signed by" {
    const pair = try Ed25519.KeyPair.generateDeterministic([_]u8{1} ** 32);
    const other = try Ed25519.KeyPair.generateDeterministic([_]u8{2} ** 32);
    const cred = Credential{
        .kind = .organization,
        .issuer = other.public_key.bytes,
        .subject = .{ .chain = 1, .address = [_]u8{5} ** 20 },
        .issued_at = 10,
        .id = [_]u8{6} ** 16,
    };
    try std.testing.expectError(error.IssuerMismatch, sign(pair, cred));
}

test "a category longer than the field is refused rather than cut" {
    const cred = Credential{
        .kind = .individual,
        .issuer = [_]u8{0} ** 32,
        .subject = .{ .chain = 1, .address = [_]u8{0} ** 20 },
        .issued_at = 0,
        .id = [_]u8{0} ** 16,
    };
    try std.testing.expectError(error.CategoryTooLong, cred.withCategory("x" ** (category_max + 1)));
}

test "the window is closed before issuance and open forever without an expiry" {
    const cred = Credential{
        .kind = .individual,
        .issuer = [_]u8{0} ** 32,
        .subject = .{ .chain = 1, .address = [_]u8{0} ** 20 },
        .issued_at = 100,
        .id = [_]u8{0} ** 16,
    };
    try std.testing.expect(!cred.live(99));
    try std.testing.expect(cred.live(100));
    try std.testing.expect(cred.live(1 << 40));
}
