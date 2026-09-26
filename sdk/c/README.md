# The C SDK

The header and the library, and nothing else. Every other SDK in this repo is a thin binding over
exactly these symbols, so no client carries logic another client would have to match.

```
zig build c            # stages gossmark.h, the shared library and the static archive in zig-out/c
sh sdk/c/example/build.sh
```

Inputs are a pointer and a length. Byte outputs are `GmBuffer` cells the library fills and the
caller frees once with `gm_free`. Every call answers a `GmStatus`, and on any status but `GM_OK`
every output cell is left empty.

Nothing here fetches and nothing here reads a clock: the roots, the revocation list and the moment
are all the caller's, which is what lets a badge be checked offline.
