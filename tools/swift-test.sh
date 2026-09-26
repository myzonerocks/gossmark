#!/bin/sh
# Runs the Swift binding's tests against the staged C library.
#
# The rpath is absolute and given here rather than left to the environment: dyld ignores
# DYLD_LIBRARY_PATH for the test helper under system integrity protection, so a run that relied
# on the environment failed to load the bundle with a message about a missing dylib and nothing
# about why.
set -eu
cd "$(dirname "$0")/.."
zig build c
exec swift test \
    -Xlinker -L"$PWD/zig-out/c" \
    -Xlinker -lgossmark \
    -Xlinker -rpath -Xlinker "$PWD/zig-out/c" "$@"
