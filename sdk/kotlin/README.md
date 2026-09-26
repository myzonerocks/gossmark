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
