#!/bin/sh
# Builds the example against the staged shared library, the way an adopter would.
set -eu
cd "$(dirname "$0")/../../.."
zig build c
cc -std=c11 -Wall -Wextra -Werror \
    sdk/c/example/main.c \
    -I zig-out/c \
    -L zig-out/c -lgossmark \
    -o zig-out/c/example
DYLD_LIBRARY_PATH=zig-out/c LD_LIBRARY_PATH=zig-out/c exec zig-out/c/example
