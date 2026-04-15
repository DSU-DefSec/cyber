#!/bin/bash
# backup.sh — full /etc snapshot + per-service data dirs (Ubuntu 24.04 / Rocky 9)
# Usage: sudo ./backup.sh [destination-dir]   (default: /opt)

set -e
(( EUID == 0 )) || { echo "must run as root"; exit 1; }

DEST="${1:-/opt}"
mkdir -p "$DEST"
[[ -d $DEST ]] || { echo "not a directory: $DEST"; exit 1; }

STAMP=$(date +%Y%m%d_%H%M%S)
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
OUT="$DEST/backup_$(hostname)_${STAMP}.tar.gz"

# /etc in full + service data trees + unit files + TLS + user ssh dirs.
# Safe superset of Ubuntu 24.04 and Rocky 9 paths — nonexistent entries are skipped.
PATHS=(
    /etc
    /usr/lib/systemd/system
    # apache / web
    /var/www
    # ftp
    /srv/ftp /var/ftp
    # samba
    /var/lib/samba
    # dns
    /var/named /var/lib/bind
    # postgres
    /var/lib/postgresql /var/lib/pgsql
    # tls
    /etc/pki
    # root ssh
    /root/.ssh
)

KEEP=()
for p in "${PATHS[@]}"; do
    [[ -e $p ]] && KEEP+=("$p")
done

# Per-user .ssh dirs (UIDs >=1000)
while IFS=: read -r user _ uid _ _ home _; do
    (( uid >= 1000 )) || continue
    [[ -d $home/.ssh ]] && KEEP+=("$home/.ssh")
done </etc/passwd

# Manifest so restore knows what's in here
MANIFEST="$WORK/MANIFEST"
{ echo "# backup $(date -Iseconds) on $(hostname)"; printf '%s\n' "${KEEP[@]}"; } >"$MANIFEST"

# Postgres logical dump — survives datadir corruption / version mismatch
if command -v pg_dumpall &>/dev/null && systemctl is-active postgresql &>/dev/null; then
    sudo -u postgres pg_dumpall 2>/dev/null >"$WORK/pg_dumpall.sql" && \
        echo "wrote pg_dumpall.sql ($(du -h "$WORK/pg_dumpall.sql" | cut -f1))"
fi

# Installed package list for reprovisioning
if command -v dpkg &>/dev/null; then
    dpkg --get-selections 2>/dev/null >"$WORK/packages.dpkg" || true
elif command -v rpm &>/dev/null; then
    rpm -qa 2>/dev/null >"$WORK/packages.rpm" || true
fi

systemctl list-unit-files --state=enabled 2>/dev/null >"$WORK/enabled.units" || true

EXTRAS=()
for f in MANIFEST pg_dumpall.sql packages.dpkg packages.rpm enabled.units; do
    [[ -f "$WORK/$f" ]] && EXTRAS+=("$f")
done

tar -czpf "$OUT" --xattrs --acls \
    -C "$WORK" "${EXTRAS[@]}" \
    "${KEEP[@]}" 2>/dev/null

echo "wrote $OUT ($(du -h "$OUT" | cut -f1)) — ${#KEEP[@]} paths"
