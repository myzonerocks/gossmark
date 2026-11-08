import rocks.myzone.gossmark.Mark

// Three inputs and nothing else: the roots you trust, what you know is
// revoked, and the moment to check against.
val badge = Mark.verifyDirect(credential, roots, revoked, now)

badge.kind
badge.subject
badge.via
