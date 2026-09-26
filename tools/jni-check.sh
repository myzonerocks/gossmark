#!/bin/sh
# Runs the JNI surface against the real library: sign, verify, refuse a stranger, open an empty
# snapshot. The Kotlin binding compiles inside the app, so it is known to build; this is what
# knows whether a call across the boundary comes back with the right bytes.
#
# Java rather than Kotlin on purpose. The entry is one JNI symbol, so a Java class declaring the
# same native method binds to it exactly as Kotlin's does, and this needs no Gradle, no Android
# and no toolchain beyond the JDK the jni step already found.
set -eu
cd "$(dirname "$0")/.."
[ -f zig-out/jni/libgossmark_jni.dylib ] || [ -f zig-out/jni/libgossmark_jni.so ] || zig build jni

out=zig-out/jni-check
rm -rf "$out" && mkdir -p "$out"
javac -d "$out" sdk/kotlin/check/rocks/myzone/gossmark/*.java sdk/kotlin/check/Check.java
exec java --enable-native-access=ALL-UNNAMED -Djava.library.path=zig-out/jni -cp "$out" Check
