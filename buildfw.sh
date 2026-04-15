#!/bin/bash
# Native static build of nftables for the host it runs on.
# depends on gcc, make and libc

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

touch src/parser_bison.c src/parser_bison.h src/scanner.c

./configure --prefix="$OUTPUT" \
    --enable-static --disable-shared --disable-json \
    --with-mini-gmp --without-cli \
    LIBMNL_CFLAGS="-I$OUTPUT/include"   LIBMNL_LIBS="-L$OUTPUT/lib -lmnl" \
    LIBNFTNL_CFLAGS="-I$OUTPUT/include" LIBNFTNL_LIBS="-L$OUTPUT/lib -lnftnl"

make -C src -j"$(nproc)" LDFLAGS="-all-static -L$OUTPUT/lib"

cp src/nft "$REPO_DIR/nft"

echo
echo "Built: $REPO_DIR/nft"
file "$REPO_DIR/nft" || true
ls -lh "$REPO_DIR/nft"
"$REPO_DIR/nft" --version || true

rm -rf "$REPO_DIR/output"
