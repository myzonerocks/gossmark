# The Go SDK

The engine in Go, for the api: it signs credentials and publishes revocation snapshots, so the
server needs the engine as well as the clients do.

This is a fifth implementation of the same bytes rather than a binding over the C surface. A Go
service linking cgo pays for it in the build, in cross-compilation for the deployment image, and
in every test run, and none of that buys anything here: the engine is a few hundred lines of
fixed-width encoding over Ed25519 and SHA-256, both of which are in the Go standard library.

What makes that safe is `vectors_test.go`. Every case the Zig core recorded is replayed through
this code and compared byte for byte. A field laid out differently, an integer written the wrong
way round, a domain tag missed: all of them fail there rather than in the field, for one client
and not another.

```
cd sdk/go && go test ./...
```
