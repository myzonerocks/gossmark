# Architecture

```
core/            the engine: credentials, the chain, revocation, the wire
  cred.zig       the four kinds, the signed preimage, sign and verify
  chain.zig      the offline walk, the roots, the scope
  revoke.zig     the signed snapshot and the holder that refuses to go backwards
  wire.zig       what crosses a boundary, fixed-width and big-endian
abi/             the C surface, and the JNI and wasm roots over it
include/         gossmark.h
sdk/             c, swift, kotlin, ts: thin bindings, no logic of their own
conformance/     one operation per run, and the frozen vectors every binding is held to
```

## Why the preimage is not JSON

Four SDKs each rebuild the bytes a signature is made over. A JSON encoding would let their key
order or their number formatting drift apart, and nothing would notice until a signature failed in
the field for one client and not another. So the preimage is fixed-width fields in a fixed order,
big-endian, behind a domain tag per kind, and the frozen vectors hold every binding to the same
bytes.

## Why the engine never fetches

A verifier is handed its roots, its revocation snapshot and the moment. It asks for nothing else.
That is what makes an offline check a real check rather than a degraded one, and it means a stale
snapshot is something a caller can see and show rather than a silent pass.

The holder in `revoke.zig` is what makes it safe: a snapshot is signed, so nobody can hand a client
a shorter list, and it is sequenced, so an older one cannot be replayed over a newer one.

## Why the scope lives in the credential

An organization's capability names the one category it was approved for, and the staff badge's
category must equal it. That check is in the walk, not in a console and not in a policy document.
An organization cannot issue outside its scope whatever its own software would let it try.

And because every staff badge runs through the capability, revoking that one id refuses all of
them at once, without touching a single staff badge. That is the kill switch, and it is one write.

## What is not here

No handle, anywhere. Not a field, not a lookup, not a code path. A credential's subject is a
wallet-bound identifier, so somebody may rename themselves whenever they like and their badge is
untouched, and a badge can never be a reason to rename anybody. Writing it this way is cheaper
than promising it.
