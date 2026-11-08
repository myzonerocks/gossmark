import { Mark } from '@myzonerocks/gossmark'

// Three inputs and nothing else: the roots you trust, what you know is
// revoked, and the moment to check against.
const badge = await Mark.verifyDirect(credential, roots, revoked, now)

badge.kind
badge.subject
badge.via
