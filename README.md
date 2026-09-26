# gossmark

The engine behind the checkmark.

It issues and checks the credentials a badge is made of, and it walks the chain behind one
offline: a staff badge is valid because a key signed it whose power a root key signed, checkable
by anyone with no server in the loop.

## The one rule

Verification never touches a handle. A handle is the person's, permanently, exactly as they chose
it. A badge is metadata beside it, never part of it.

That rule is visible in what this engine does not know: nothing here has a handle in it at all. A
credential's subject is a wallet-bound identifier, so somebody may rename themselves whenever they
like and their badge is untouched, and a badge can never be a reason to rename anybody.

## What it holds

| Kind | Issued by | Validity |
|---|---|---|
| `individual` | a Goss root key | permanent until revoked |
| `organization` | a Goss root key | permanent until revoked |
| `capability` | a Goss root key | re-reviewed periodically |
| `staff` | an organization holding a capability | twelve months, plus instant revocation |

Permanence matches what is certified. An identity does not lapse on its own, so those badges last.
An affiliation can end without anybody reporting it, so that badge alone expires on a cycle.

## How a badge is checked

`verifyDirect` for a badge Goss signed itself: the signature under a trusted root, the window, and
the revocation snapshot the caller holds.

`verifyStaff` for a badge an organization issued: the capability is signed by a root and is live
and unrevoked, the staff badge is signed by the very key that capability delegates to, and the
staff badge's category is the one the capability was granted for. The scope is checked here rather
than trusted, and because every staff badge runs through the capability, revoking that one id is
the kill switch: all of them fall at once, without touching a single staff badge.

Neither call fetches anything. A verifier answers from the newest signed snapshot it has seen, so
a check works offline and a stale snapshot is something the caller can notice rather than a silent
pass.

## The preimage

Signatures are made over fixed-width fields in a fixed order, big-endian, behind a domain tag per
kind. Not JSON: four SDKs will each rebuild these bytes, and a JSON encoding would let their key
order or number formatting drift apart without anyone noticing until a signature failed in the
field. The frozen vectors hold every SDK to the same bytes.

## Building

```
zig build test
```

The compiler is pinned in `.zigversion`; a build with any other version fails closed.
