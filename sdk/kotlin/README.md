# The Kotlin SDK

A thin binding over one JNI entry. Every operation is a number and its inputs are byte arrays, so
there is no per-call JNI signature to keep in step with the C surface; the typing is in `Mark.kt`
where it can be read.

```
zig build jni                      # the host JVM, for a desktop test run
zig build android -Dndk=<ndk root> # arm64-v8a and x86_64 for the app
```

The library is loaded as `gossmark_jni`. Put the staged `.so` files under the app's `jniLibs` the
way the other engines are wired in.

Nothing here fetches and nothing here reads a clock: the roots, the revocation list and the moment
are all the caller's.

## If you turn minification on

The JNI layer looks up `rocks.myzone.gossmark.MarkException` by name to throw a refusal across the
boundary. A build that renames or strips that class finds nothing, and the refusal degrades to a
plain `RuntimeException` carrying the status as its message: still a refusal, but no longer a
typed one. Keep the class if you want the type:

```
-keep class rocks.myzone.gossmark.MarkException { *; }
```

The app does not minify today, so nothing is stripped and this costs nothing to ignore. It is
written down because the day somebody turns it on is the day it starts mattering, and the failure
it used to produce before the fallback existed was a null pointer exception with nothing in it.

## Proving the boundary works

```
tools/jni-check.sh
```

Signs a credential, verifies it, refuses one signed under a root it does not trust, and opens an
empty snapshot, against the real library. Java rather than Kotlin on purpose: the entry is one JNI
symbol, so a Java class declaring the same native method binds to it exactly as Kotlin's does, and
it needs no Gradle and no Android.
