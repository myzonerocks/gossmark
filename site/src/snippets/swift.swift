import Gossmark

// Three inputs and nothing else: the roots you trust, what you know is
// revoked, and the moment to check against.
let badge = try Mark.verifyDirect(
    signed: credential,
    roots: [rootKey],
    revoked: revokedIds,
    now: Int64(Date().timeIntervalSince1970)
)

badge.kind      // .individual, .organization, .capability, .staff
badge.subject   // a wallet-bound identifier, never a handle
badge.via       // the organization, when a staff badge came through one
