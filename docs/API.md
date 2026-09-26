# API

One engine, four bindings, the same calls in each. Every binding is a thin layer over the C
surface, so no client carries logic another client would have to match.

Nothing in any of them fetches, and nothing reads a clock. The roots, the revocation list and the
moment to check against are all the caller's. That is what lets a badge be checked offline, and it
is what makes a client with a wrong clock fail the same way everywhere rather than differently.

## The calls

| Call | What it does |
|---|---|
| `publicKey(seed)` | the key a seed belongs to; an issuer names its key inside every credential it signs |
| `sign(seed, preimage)` | signs a credential; the issuer named inside must be the seed's key |
| `verifyDirect(signed, roots, revoked, now)` | a badge Goss signed itself |
| `verifyStaff(staff, capability, roots, revoked, now)` | a badge an organization issued, walked back to a root |
| `signSnapshot(seed, seq, issuedAt, ids)` | what a server does; a client only ever opens one |
| `openSnapshot(snapshot, roots, heldSeq)` | takes a newer snapshot, refuses an older one |

`preimageLength` is read from the library rather than written into a binding, so no binding can
carry a stale one.

## What comes back

A verified badge, and only ever from a check. A credential that has not been through the chain has
not been checked, so no binding gives you one:

- `kind`: individual, organization, capability or staff
- `subject`: a wallet-bound identifier, a chain id and an address. Never a handle.
- `category`: the word it was issued for
- `issuedAt`, `expiresAt`: zero expiry means it does not expire
- `issuer`: the key that signed it, root for a direct badge, the organization for a staff badge
- `via`: for a staff badge, the organization the capability was granted to

## Statuses

`badArgument`, `badSignature`, `untrustedIssuer`, `notLive`, `revoked`, `wrongKind`,
`outOfScope`, `noDelegate`, `stale`, `outOfMemory`, `internal`.

`outOfScope` is the one worth knowing: an organization approved for one category signed a badge
for another, and the credential refused it rather than a policy document.

`stale` is the other: a snapshot older than or equal to the one already held. Replaying an earlier
list must never bring a revoked badge back.

## Swift

```swift
let root = try Mark.publicKey(seed: seed)
let badge = try Mark.verifyDirect(signed: signed, roots: [root], revoked: [], now: now)
```

Buffers are handled once inside the binding: a caller never frees anything and never sees a raw
pointer.

## Kotlin

```kotlin
val root = Mark.publicKey(seed)
val badge = Mark.verifyDirect(signed, listOf(root), emptyList(), now)
```

One JNI entry under it, so there is no per-call signature to keep in step with C.

## TypeScript

```ts
const engine = await Mark.load(await fetch(url).then((r) => r.arrayBuffer()))
const root = engine.publicKey(seed)
const badge = engine.verifyDirect(signed, [root], [], now)
```

The wasm core allocates its own outputs; the binding borrows input room from it and hands it back
at the end of every call, whether the call succeeded or not.

## C

```c
GmBuffer seen = {0};
if (gm_verify_direct(signed, len, roots, roots_len, revoked, revoked_len, now, &seen) == GM_OK) {
    /* seen.len == gm_verified_len() */
}
gm_free(&seen);
```

Inputs are a pointer and a length. Byte outputs are cells the library fills and the caller frees
once. On any status but `GM_OK` every output cell is left empty.
