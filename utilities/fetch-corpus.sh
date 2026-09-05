#!/bin/sh
# Fetch the AFF4 reference containers the corpus tests read.
#
# aff4tools does not redistribute these; they belong to upstream projects
# This script downloads them at pinned commits so a corpus run is reproducible.
#
#   ./utilities/fetch-corpus.sh [DEST]
#
# DEST defaults to ~/.cache/aff4tools/corpus. When it finishes it prints the
# one command needed to run the corpus suite.

set -eu

DEST="${1:-$HOME/.cache/aff4tools/corpus}"

# Pinned so results stay comparable over time. A corpus that moves underneath
# the suite makes a passing run mean something different from one to the next.
PYAFF4_REPO="https://github.com/aff4/pyaff4.git"
PYAFF4_COMMIT="6a91158661edec6ed8a865a09e28dbf30d487e38"
CPPLITE_REPO="https://github.com/aff4/aff4-cpp-lite.git"
CPPLITE_COMMIT="22e57b658b1d0e9eefe4bdfb64a7132590a65dd3"

command -v git >/dev/null 2>&1 || {
    echo "error: git is required" >&2
    exit 1
}

# Sparse checkout: these repos are ~70 MB each, the fixtures ~62 MB total.
# Only the test-image directories are ever fetched.
fetch() {
    repo="$1" commit="$2" subdir="$3" dir="$4"

    if [ -e "$dir/.git" ]; then
        have=$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo none)
        if [ "$have" = "$commit" ]; then
            echo "  already at pinned commit, skipping"
            return 0
        fi
    fi

    # Only ever removes a directory this script created under $DEST, never a
    # path the caller named directly.
    case "$dir" in
        "$DEST"/*) rm -rf "$dir" ;;
        *) echo "error: refusing to remove $dir" >&2; exit 1 ;;
    esac
    git clone --filter=blob:none --no-checkout --quiet "$repo" "$dir"
    git -C "$dir" sparse-checkout set --no-cone "$subdir"
    git -C "$dir" checkout --quiet "$commit"
}

echo "Fetching AFF4 reference containers into $DEST"
mkdir -p "$DEST"

echo "pyaff4 (Apache-2.0) ..."
fetch "$PYAFF4_REPO" "$PYAFF4_COMMIT" "test_images" "$DEST/pyaff4"

echo "aff4-cpp-lite (LGPL-3.0) ..."
fetch "$CPPLITE_REPO" "$CPPLITE_COMMIT" "tests/resources" "$DEST/aff4-cpp-lite"

# Verify the layout the tests expect actually materialized, rather than
# reporting success on an empty directory.
missing=""
for p in \
    "pyaff4/test_images/AFF4Std/Base-Linear.aff4" \
    "pyaff4/test_images/AFF4-L/dream.aff4" \
    "aff4-cpp-lite/tests/resources/Base-Linear.aff4"
do
    [ -f "$DEST/$p" ] || missing="$missing  $p\n"
done

if [ -n "$missing" ]; then
    printf "error: fetch completed but these are missing:\n%b" "$missing" >&2
    exit 1
fi

count=$(find "$DEST" -name '*.aff4' -o -name '*.af4' | wc -l | tr -d ' ')

# Phase 2 needs a v2.1 container to read, and none is published anywhere: the
# AFF4-L Standard v1.0-ALPHA reference images do not exist yet. These are
# generated rather than downloaded, and are NOT canonical reference images.
if command -v python3 >/dev/null 2>&1; then
    python3 "$(dirname "$0")/make_v21_container.py" "$DEST/aff4tools-v2.1"
    count=$((count + 2))
else
    echo "warning: python3 not found; v2.1 test containers were not generated" >&2
    echo "         the corpus suite's v2.1 tests will fail until they exist" >&2
fi

DEFAULT="$HOME/.cache/aff4tools/corpus"

echo
echo "Done. $count containers in $DEST"
echo
if [ "$DEST" = "$DEFAULT" ]; then
    # The default location is where the tests already look.
    echo "Run the corpus suite with:"
    echo
    echo "  cargo test --features corpus"
else
    echo "Run the corpus suite with:"
    echo
    echo "  AFF4_TEST_IMAGES=$DEST cargo test --features corpus"
fi
cat <<'EOF'

These containers belong to their upstream projects: pyaff4 is Apache-2.0,
aff4-cpp-lite is LGPL-3.0. aff4tools redistributes neither.
EOF
