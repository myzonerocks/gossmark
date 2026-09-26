#!/usr/bin/env bash
# Builds the Apple slices in release mode, merges the simulator and macOS architectures, wraps
# each platform as a static framework with the C header as its umbrella and a module map, and
# folds them into zig-out/GossmarkKit.xcframework with a zip and a checksum for SwiftPM.
set -euo pipefail
cd "$(dirname "$0")/.."

zig build apple -Doptimize=ReleaseFast

out=zig-out
lib=libgossmark_static.a
stage="$out/apple-stage"
rm -rf "$stage" "$out/GossmarkKit.xcframework" "$out/GossmarkKit.xcframework.zip"
mkdir -p "$stage"

lipo -create "$out/ios-simulator/$lib" "$out/ios-simulator-x86_64/$lib" -output "$stage/sim.a"
lipo -create "$out/macos/$lib" "$out/macos-x86_64/$lib" -output "$stage/mac.a"

wrap() {
  local name="$1" archive="$2" dir="$stage/$1/GossmarkKit.framework"
  mkdir -p "$dir/Headers" "$dir/Modules"
  cp "$archive" "$dir/GossmarkKit"
  cp include/gossmark.h "$dir/Headers/gossmark.h"
  cat > "$dir/Modules/module.modulemap" <<'MAP'
framework module GossmarkKit {
    umbrella header "gossmark.h"
    export *
}
MAP
  # A device refuses a framework whose plist does not name its executable, and the simulator does
  # not, so this is only ever caught on a phone.
  cat > "$dir/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.myzonerocks.gossmark.GossmarkKit</string>
<key>CFBundleName</key><string>GossmarkKit</string>
<key>CFBundleExecutable</key><string>GossmarkKit</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>MinimumOSVersion</key><string>17.0</string>
</dict></plist>
PLIST
}
wrap ios "$out/ios/$lib"
wrap ios-simulator "$stage/sim.a"
wrap macos "$stage/mac.a"

xcodebuild -create-xcframework \
  -framework "$stage/ios/GossmarkKit.framework" \
  -framework "$stage/ios-simulator/GossmarkKit.framework" \
  -framework "$stage/macos/GossmarkKit.framework" \
  -output "$out/GossmarkKit.xcframework" >/dev/null

( cd "$out" && zip -qr GossmarkKit.xcframework.zip GossmarkKit.xcframework )
checksum=$(swift package compute-checksum "$out/GossmarkKit.xcframework.zip")
echo "$checksum" > "$out/GossmarkKit.checksum.txt"
rm -rf "$stage"
echo "build-xcframework: $out/GossmarkKit.xcframework $(du -sh "$out/GossmarkKit.xcframework" | cut -f1), checksum $checksum"
