import Foundation
import CGossmark

/// What a badge says once its chain has been walked. Built only by a check, never by hand: a
/// credential that has not been through the chain has not been checked, and this type is the
/// proof that one has.
public struct Badge: Equatable, Sendable {
    /// Which of the four kinds this is.
    public enum Kind: UInt8, Sendable {
        case individual = 1, organization = 2, capability = 3, staff = 4
    }

    /// A wallet-bound identifier. Never a handle: a handle is a display name its owner may change
    /// whenever they like, and nothing in the chain depends on one.
    public struct Subject: Equatable, Sendable {
        public let chain: UInt64
        public let address: Data
    }

    public let kind: Kind
    public let subject: Subject
    public let category: String
    public let issuedAt: Int64
    /// Zero for a badge that does not expire. An identity does not lapse on its own; only a staff
    /// badge, which certifies a relationship, carries a real expiry.
    public let expiresAt: Int64
    /// The key that signed the badge: a root for a direct badge, the organization for a staff one.
    public let issuer: Data
    /// For a staff badge, the organization the capability was granted to. What the panel reads to
    /// say "verified by this organization, itself verified by Goss".
    public let via: Subject?
}

public enum MarkError: Int32, Error, Sendable {
    case badArgument = 1
    case badSignature = 2
    case untrustedIssuer = 3
    case notLive = 4
    case revoked = 5
    case wrongKind = 6
    case outOfScope = 7
    case noDelegate = 8
    case stale = 9
    case outOfMemory = 10
    case internalError = 11

    static func of(_ status: GmStatus) -> MarkError {
        MarkError(rawValue: Int32(status.rawValue)) ?? .internalError
    }
}

/// The engine, as Swift sees it. Every call here is the C surface with the buffer handling done
/// once, so a caller never frees anything and never sees a raw pointer.
public enum Mark {
    /// The ABI the linked library speaks. Checked at startup by anything that cares to.
    public static var abiVersion: UInt32 { gm_abi_version() }

    /// How long the bytes a signature is made over are. Taken from the library rather than
    /// written down here, so this binding cannot carry a stale number.
    public static var preimageLength: Int { gm_preimage_len() }

    public static func publicKey(seed: Data) throws -> Data {
        try call { out in seed.withBytes { gm_public_key($0, seed.count, out) } }
    }

    /// Signs a credential whose preimage is already laid out. The issuer named inside must be the
    /// key the seed belongs to.
    public static func sign(seed: Data, preimage: Data) throws -> Data {
        try call { out in
            seed.withBytes { s in preimage.withBytes { p in gm_sign(s, seed.count, p, preimage.count, out) } }
        }
    }

    /// Checks a badge Goss signed itself. The roots, the revocation list and the moment are all
    /// the caller's, so this answers with no network: a badge checks the same on a plane.
    public static func verifyDirect(signed: Data, roots: [Data], revoked: [Data], now: Int64) throws -> Badge {
        let rootBytes = Self.list(roots, width: 32)
        let revokedBytes = Self.list(revoked, width: 16)
        let out = try call { cell in
            signed.withBytes { s in rootBytes.withBytes { r in revokedBytes.withBytes { v in
                gm_verify_direct(s, signed.count, r, rootBytes.count, v, revokedBytes.count, now, cell)
            } } }
        }
        return try Self.read(out)
    }

    /// Checks a badge an organization issued, walking its capability back to a root. The scope is
    /// the credential's, not a promise: an organization approved for one category cannot issue for
    /// another, and revoking the capability refuses every badge that flowed from it at once.
    public static func verifyStaff(staff: Data, capability: Data, roots: [Data], revoked: [Data], now: Int64) throws -> Badge {
        let rootBytes = Self.list(roots, width: 32)
        let revokedBytes = Self.list(revoked, width: 16)
        let out = try call { cell in
            staff.withBytes { st in capability.withBytes { c in rootBytes.withBytes { r in revokedBytes.withBytes { v in
                gm_verify_staff(st, staff.count, c, capability.count, r, rootBytes.count, v, revokedBytes.count, now, cell)
            } } } }
        }
        return try Self.read(out)
    }

    /// Signs a revocation snapshot over the ids given. What a server does; a client only ever
    /// opens one. Here so that nothing has to reach past this binding into the C surface.
    public static func signSnapshot(seed: Data, seq: UInt64, issuedAt: Int64, ids: [Data]) throws -> Data {
        var flat = Data(capacity: ids.count * 16)
        for id in ids where id.count == 16 { flat.append(id) }
        return try call { out in
            seed.withBytes { s in flat.withBytes { i in
                gm_snapshot_sign(s, seed.count, seq, issuedAt, i, flat.count, out)
            } }
        }
    }

    /// Takes a snapshot newer than the one held and hands back the ids in it. An older or equal
    /// sequence throws `.stale`: replaying an earlier list must never bring a revoked badge back.
    public static func openSnapshot(_ snapshot: Data, roots: [Data], heldSeq: UInt64) throws -> (ids: [Data], seq: UInt64, issuedAt: Int64) {
        let rootBytes = Self.list(roots, width: 32)
        var seq: UInt64 = 0
        var at: Int64 = 0
        let flat = try call { cell in
            snapshot.withBytes { s in rootBytes.withBytes { r in
                gm_snapshot_open(s, snapshot.count, r, rootBytes.count, heldSeq, cell, &seq, &at)
            } }
        }
        var ids: [Data] = []
        ids.reserveCapacity(flat.count / 16)
        var offset = flat.startIndex
        while offset < flat.endIndex {
            ids.append(flat[offset ..< offset + 16])
            offset += 16
        }
        return (ids, seq, at)
    }

    // MARK: - the buffer handling, done once

    private static func call(_ body: (UnsafeMutablePointer<GmBuffer>) -> GmStatus) throws -> Data {
        var cell = GmBuffer(ptr: nil, len: 0)
        let status = body(&cell)
        defer { gm_free(&cell) }
        guard status == GM_OK else { throw MarkError.of(status) }
        guard let ptr = cell.ptr else { return Data() }
        return Data(bytes: ptr, count: cell.len)
    }

    /// A list as the C surface takes it: a big-endian count, then each fixed-width item.
    private static func list(_ items: [Data], width: Int) -> Data {
        var out = Data(capacity: 4 + items.count * width)
        var count = UInt32(items.count).bigEndian
        withUnsafeBytes(of: &count) { out.append(contentsOf: $0) }
        for item in items where item.count == width { out.append(item) }
        return out
    }

    private static func read(_ bytes: Data) throws -> Badge {
        guard bytes.count == gm_verified_len() else { throw MarkError.badArgument }
        let b = [UInt8](bytes)
        var at = 0
        func take(_ n: Int) -> Data { defer { at += n }; return Data(b[at ..< at + n]) }
        func u64() -> UInt64 { take(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) } }
        func i64() -> Int64 { Int64(bitPattern: u64()) }

        guard let kind = Badge.Kind(rawValue: b[at]) else { throw MarkError.wrongKind }
        at += 1
        let subject = Badge.Subject(chain: u64(), address: take(20))
        let category = String(decoding: take(32).prefix { $0 != 0 }, as: UTF8.self)
        let issuedAt = i64()
        let expiresAt = i64()
        let issuer = take(32)
        let hasVia = b[at] == 1
        at += 1
        let viaChain = u64()
        let viaAddress = take(20)
        return Badge(
            kind: kind, subject: subject, category: category,
            issuedAt: issuedAt, expiresAt: expiresAt, issuer: issuer,
            via: hasVia ? Badge.Subject(chain: viaChain, address: viaAddress) : nil
        )
    }
}

private extension Data {
    /// A pointer into the bytes, or a valid pointer to nothing when empty: the C surface reads a
    /// null pointer with a zero length as absent, and an empty Data has no base address at all.
    func withBytes<R>(_ body: (UnsafePointer<UInt8>?) -> R) -> R {
        if isEmpty { return body(nil) }
        return withUnsafeBytes { body($0.bindMemory(to: UInt8.self).baseAddress) }
    }
}
