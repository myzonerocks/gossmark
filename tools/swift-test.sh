#!/bin/sh
# Runs the Swift binding's tests against the xcframework the checkout built.
#
# No linker flags and no rpath: the kit is a binary target, so SwiftPM knows where it is and the
# test bundle finds it without the environment being told anything. That was not true of the
# system-library shape this replaced, where dyld ignored DYLD_LIBRARY_PATH for the test helper
# under system integrity protection and the failure read as a missing dylib with no reason given.
set -eu
cd "$(dirname "$0")/.."
[ -d zig-out/GossmarkKit.xcframework ] || tools/build-xcframework.sh
exec swift test "$@"
