#!/bin/bash
# Native static build of nftables for the host it runs on.
# Intended targets: Ubuntu Server 24.04 and Rocky Linux 9.
#
# Minimum host requirements:
#   - gcc (plus binutils: ld, ar, ranlib)
#   - make
#   - libc headers, kernel headers (linux/*.h)
#
# NOT required: bison, flex, pkg-config, autoconf, automake, libtool,
# libmnl-dev, libnftnl-dev, libedit-dev, libgmp-dev. Everything needed
# beyond a bare C toolchain is vendored in this repo.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="$REPO_DIR/output"
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"

export CPPFLAGS="-I$OUTPUT/include"
export CFLAGS="-Os -I$OUTPUT/include"
export LDFLAGS="-L$OUTPUT/lib"

for tool in gcc make ar ld; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: '$tool' not found in PATH. A C toolchain is required." >&2
        exit 1
    fi
done

# Touch autotools-generated files in dependency order so make won't try
# to regenerate them (which would require aclocal/autoconf/automake).
# Order matters: sources first, then generated files newer than sources.
fix_autotools_timestamps() {
    find . -name 'configure.ac' -exec touch {} +
    find . -name 'Makefile.am'  -exec touch {} +
    find . -name 'acinclude.m4' -exec touch {} + 2>/dev/null || true
    find . -name 'aclocal.m4'   -exec touch {} +
    find . -name 'configure'    -exec touch {} +
    find . -name 'config.h.in'  -exec touch {} +
    find . -name 'Makefile.in'  -exec touch {} +
}

build() {
    local dir=$1; shift
    cd "$REPO_DIR/$dir"
    make distclean >/dev/null 2>&1 || true
    fix_autotools_timestamps
    ./configure --prefix="$OUTPUT" --enable-static --disable-shared "$@"
    make -j"$(nproc)"
    make install
}

echo "[1/3] libmnl"
build libmnl-1.0.5

echo "[2/3] libnftnl"
# libnftnl's configure uses pkg-config for libmnl by default; bypass it by
# passing LIBMNL_CFLAGS/LIBMNL_LIBS explicitly so we don't need pkg-config.
cd "$REPO_DIR/libnftnl-1.2.6"
make distclean >/dev/null 2>&1 || true
fix_autotools_timestamps
./configure --prefix="$OUTPUT" --enable-static --disable-shared \
    LIBMNL_CFLAGS="-I$OUTPUT/include" \
    LIBMNL_LIBS="-L$OUTPUT/lib -lmnl"
make -j"$(nproc)"
make install

echo "[3/3] nftables"
cd "$REPO_DIR/nftables-1.0.9"
make distclean >/dev/null 2>&1 || true
fix_autotools_timestamps

# Mark pre-generated parser/scanner files as up-to-date so make never
# tries to regenerate them from the .y/.l sources. This eliminates the
# build-time dependency on bison and flex. Must come AFTER
# fix_autotools_timestamps so these stay the newest files in the tree.
touch src/parser_bison.c src/parser_bison.h src/scanner.c

./configure --prefix="$OUTPUT" \
    --enable-static --disable-shared --disable-json \
    --with-mini-gmp --without-cli \
    LIBMNL_CFLAGS="-I$OUTPUT/include"   LIBMNL_LIBS="-L$OUTPUT/lib -lmnl" \
    LIBNFTNL_CFLAGS="-I$OUTPUT/include" LIBNFTNL_LIBS="-L$OUTPUT/lib -lnftnl"

# Build only src/ — we want the nft binary, nothing else. Skips doc/
# (man pages via a2x/asciidoc), examples/, py/, etc.
# -all-static forces libtool to produce a fully static final executable.
make -C src -j"$(nproc)" LDFLAGS="-all-static -L$OUTPUT/lib"

# Drop the finished binary in the repo root. It's fully static — no
# other files are needed alongside it.
cp src/nft "$REPO_DIR/nft"

echo
echo "Built: $REPO_DIR/nft"
file "$REPO_DIR/nft" || true
ls -lh "$REPO_DIR/nft"
"$REPO_DIR/nft" --version || true

rm -rf "$REPO_DIR/output"
