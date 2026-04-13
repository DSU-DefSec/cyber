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

build() {
    local dir=$1; shift
    cd "$REPO_DIR/$dir"
    make distclean >/dev/null 2>&1 || true
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
./configure --prefix="$OUTPUT" --enable-static --disable-shared \
    LIBMNL_CFLAGS="-I$OUTPUT/include" \
    LIBMNL_LIBS="-L$OUTPUT/lib -lmnl"
make -j"$(nproc)"
make install

echo "[3/3] nftables"
cd "$REPO_DIR/nftables-1.0.9"
make distclean >/dev/null 2>&1 || true

# Mark pre-generated parser/scanner files as up-to-date so make never
# tries to regenerate them from the .y/.l sources. This eliminates the
# build-time dependency on bison and flex.
touch src/parser_bison.c src/parser_bison.h src/scanner.c

./configure --prefix="$OUTPUT" \
    --enable-static --disable-shared --disable-json \
    --with-mini-gmp --without-cli \
    LIBMNL_CFLAGS="-I$OUTPUT/include"   LIBMNL_LIBS="-L$OUTPUT/lib -lmnl" \
    LIBNFTNL_CFLAGS="-I$OUTPUT/include" LIBNFTNL_LIBS="-L$OUTPUT/lib -lnftnl"

# -all-static tells libtool to produce a fully static final executable.
make -j"$(nproc)" LDFLAGS="-all-static -L$OUTPUT/lib"
make install

echo
echo "Built: $OUTPUT/sbin/nft"
file "$OUTPUT/sbin/nft" || true
ls -lh "$OUTPUT/sbin/nft"
"$OUTPUT/sbin/nft" --version || true
