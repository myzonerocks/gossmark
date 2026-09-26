#!/bin/sh
# Moves Unreleased under a tag with today's date and prints that section, which is what a release
# is published with. A release whose notes are written separately drifts from what shipped.
set -eu
cd "$(dirname "$0")/.."
version="${1:?usage: changelog-cut.sh <vX.Y.Z>}"
today=$(date +%Y-%m-%d)
awk -v v="$version" -v d="$today" '
  /^## Unreleased$/ { print "## Unreleased"; print ""; print "## " v " (" d ")"; seen=1; next }
  { print }
  END { if (!seen) exit 1 }
' CHANGELOG.md > CHANGELOG.md.next
mv CHANGELOG.md.next CHANGELOG.md
awk -v v="$version" '
  $0 == "## " v " (" substr($0, index($0, "(")+1) { inside=1; next }
  inside && /^## / { exit }
  inside { print }
' CHANGELOG.md | sed '/^$/d'
