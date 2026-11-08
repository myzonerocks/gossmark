package badge

import "github.com/myzonerocks/gossmark/sdk/go"

// Three inputs and nothing else: the roots you trust, what you know is
// revoked, and the moment to check against.
badge, err := gossmark.VerifyDirect(credential, roots, revoked, now)
if err != nil {
    return err
}
