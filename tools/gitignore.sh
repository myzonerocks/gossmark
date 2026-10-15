#!/usr/bin/env bash
# Fail if a top-level source directory (one that holds tracked files) is missing its
# !dir/** re-include in .gitignore, so a contributor's global ignore can never silently
# drop owned source. The owned-source list is derived from the tree itself.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
missing=""
for d in $(git ls-files | awk -F/ 'NF>1{print $1}' | sort -u); do
  case "$d" in .*) continue;; esac
  grep -qxF "!$d/**" .gitignore || missing="$missing $d"
done
if [ -n "$missing" ]; then
  echo "gitignore: owned source dir(s) missing a '!<dir>/**' re-include:$missing" >&2
  exit 1
fi
echo "gitignore: ok"
