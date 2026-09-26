import Foundation
import Testing
@testable import Gossmark

// The Swift binding is checked against the same behaviour the core is, so a binding that drifted
// from the engine shows up here rather than on a phone.
@Suite struct MarkTests {
    /// The preimage, laid out the way the engine lays it out. Written here by hand on purpose:
    /// if the layout ever changes, this is one of the places that has to change with it, and a
    /// silent disagreement between a client and the engine is exactly what the vectors exist to
    /// catch. The length itself comes from the library rather than from a number written here.
    func preimage(kind: UInt8, issuer: Data, address: UInt8, category: String, issuedAt: Int64, expiresAt: Int64 = 0, id: UInt8, delegate: Data? = nil) -> Data {
        var body = Data(repeating: 0, count: Mark.preimageLength)
        body[0] = kind
        body.replaceSubrange(1 ..< 33, with: issuer)
        var chain = UInt64(1).bigEndian
        withUnsafeBytes(of: &chain) { body.replaceSubrange(33 ..< 41, with: $0) }
        body.replaceSubrange(41 ..< 61, with: Data(repeating: address, count: 20))
        body.replaceSubrange(61 ..< 61 + category.utf8.count, with: Data(category.utf8))
        var issued = issuedAt.bigEndian
        withUnsafeBytes(of: &issued) { body.replaceSubrange(93 ..< 101, with: $0) }
        var expires = expiresAt.bigEndian
        withUnsafeBytes(of: &expires) { body.replaceSubrange(101 ..< 109, with: $0) }
        body.replaceSubrange(109 ..< 125, with: Data(repeating: id, count: 16))
        if let delegate { body.replaceSubrange(125 ..< 157, with: delegate) }
        return body
    }

    @Test func aBadgeVerifiesUnderItsRoot() throws {
        let seed = Data(repeating: 1, count: 32)
        let root = try Mark.publicKey(seed: seed)
        let signed = try Mark.sign(seed: seed, preimage: preimage(kind: 1, issuer: root, address: 0xA1, category: "journalist", issuedAt: 100, id: 0xD1))
        let badge = try Mark.verifyDirect(signed: signed, roots: [root], revoked: [], now: 500)
        #expect(badge.kind == .individual)
        #expect(badge.category == "journalist")
        #expect(badge.expiresAt == 0)
        #expect(badge.via == nil)
    }

    @Test func aBadgeOutsideTheRootsIsRefused() throws {
        let seed = Data(repeating: 2, count: 32)
        let key = try Mark.publicKey(seed: seed)
        let signed = try Mark.sign(seed: seed, preimage: preimage(kind: 1, issuer: key, address: 0xA2, category: "creator", issuedAt: 100, id: 0xD2))
        #expect(throws: MarkError.untrustedIssuer) {
            _ = try Mark.verifyDirect(signed: signed, roots: [Data(repeating: 9, count: 32)], revoked: [], now: 500)
        }
    }

    @Test func aStaffBadgeWalksItsCapabilityAndItsScopeHolds() throws {
        let rootSeed = Data(repeating: 11, count: 32)
        let orgSeed = Data(repeating: 22, count: 32)
        let root = try Mark.publicKey(seed: rootSeed)
        let org = try Mark.publicKey(seed: orgSeed)

        let capability = try Mark.sign(seed: rootSeed, preimage: preimage(kind: 3, issuer: root, address: 0xB2, category: "journalist", issuedAt: 100, expiresAt: 10_000, id: 0xC3, delegate: org))
        let staff = try Mark.sign(seed: orgSeed, preimage: preimage(kind: 4, issuer: org, address: 0xE4, category: "journalist", issuedAt: 100, expiresAt: 5_000, id: 0xD4))

        let badge = try Mark.verifyStaff(staff: staff, capability: capability, roots: [root], revoked: [], now: 500)
        #expect(badge.kind == .staff)
        #expect(badge.via != nil)

        // Out of the category the organization was approved for.
        let intern = try Mark.sign(seed: orgSeed, preimage: preimage(kind: 4, issuer: org, address: 0xE5, category: "intern", issuedAt: 100, expiresAt: 5_000, id: 0xD5))
        #expect(throws: MarkError.outOfScope) {
            _ = try Mark.verifyStaff(staff: intern, capability: capability, roots: [root], revoked: [], now: 500)
        }
    }

    @Test func pullingTheCapabilityTakesTheStaffBadgeWithIt() throws {
        let rootSeed = Data(repeating: 11, count: 32)
        let orgSeed = Data(repeating: 22, count: 32)
        let root = try Mark.publicKey(seed: rootSeed)
        let org = try Mark.publicKey(seed: orgSeed)
        let capability = try Mark.sign(seed: rootSeed, preimage: preimage(kind: 3, issuer: root, address: 0xB2, category: "journalist", issuedAt: 100, expiresAt: 10_000, id: 0xC3, delegate: org))
        let staff = try Mark.sign(seed: orgSeed, preimage: preimage(kind: 4, issuer: org, address: 0xE4, category: "journalist", issuedAt: 100, expiresAt: 5_000, id: 0xD4))

        #expect(throws: MarkError.revoked) {
            _ = try Mark.verifyStaff(staff: staff, capability: capability, roots: [root], revoked: [Data(repeating: 0xC3, count: 16)], now: 500)
        }
    }

    @Test func anOlderSnapshotCannotBeReplayedOverANewerOne() throws {
        let seed = Data(repeating: 11, count: 32)
        let root = try Mark.publicKey(seed: seed)
        // The snapshot is signed the way a server signs one; a client only ever opens one.
        let signed = try Mark.signSnapshot(seed: seed, seq: 7, issuedAt: 900, ids: [Data(repeating: 0xAB, count: 16)])

        let opened = try Mark.openSnapshot(signed, roots: [root], heldSeq: 0)
        #expect(opened.seq == 7)
        #expect(opened.ids.count == 1)
        #expect(throws: MarkError.stale) {
            _ = try Mark.openSnapshot(signed, roots: [root], heldSeq: 7)
        }
    }
}
