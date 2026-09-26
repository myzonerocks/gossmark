# Provenance

This project is an original implementation. It is not a port, translation, modification or
derivative distribution of any other codebase.

The design it implements is this project's own and is written down in
[docs/DESIGN.md](docs/DESIGN.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The credential
layout, the domain separation between kinds, the wire shapes, the chain walk and the revocation
snapshot were all designed here; none of them is a copy of a published credential format, and the
engine deliberately does not implement one, because the formats in common use are JSON-shaped and
this engine's whole argument for fixed-width bytes is that four SDKs rebuilding a JSON preimage
will eventually disagree without anybody noticing.

All implementation code, tests, documentation and build tooling in this repository were
independently authored for this project or contributed under the Apache License, Version 2.0. The
only external code the implementation uses is the Zig standard library, whose notice is in
[NOTICE.md](NOTICE.md); the signature scheme is Ed25519 and the hash is SHA-256, both taken from
that standard library rather than reimplemented here.

Where the four SDKs must agree, they agree on bytes. The preimage layout, the wire shapes and the
status codes are fixed by this engine, and the frozen vectors under `conformance/vectors` are what
holds every binding to them. A binding that rebuilds a preimage differently fails the replay
rather than failing later, in the field, for one client and not another.

No part of this engine knows what anybody is called. That is a design position rather than an
omission, and it is stated here because it is the one property somebody auditing this code should
be able to check quickly: search the tree for a handle and there is nothing to find.
