#!/bin/bash
# restore.sh — extract a backup.sh tarball back over the filesystem
# NON-DESTRUCTIVE: files in the tarball overwrite their counterparts, but nothing
# outside the tarball is deleted. Attacker drops in backed-up dirs will remain;
# diff against the tarball manually if you need to find them.
# Usage: sudo ./restore.sh <backup_*.tar.gz>

set -e
(( EUID == 0 )) || { echo "must run as root"; exit 1; }
[[ -f ${1:-} ]] || { echo "usage: $0 <backup_*.tar.gz>"; exit 1; }

BK=$(readlink -f "$1")
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# Peek at extras without touching the real fs
tar -xzf "$BK" -C "$TMP" --xattrs --acls \
    MANIFEST pg_dumpall.sql packages.dpkg packages.rpm enabled.units 2>/dev/null || true

if [[ -f "$TMP/MANIFEST" ]]; then
    echo "manifest:"
    grep -vE '^\s*(#|$)' "$TMP/MANIFEST" | sed 's/^/  /'
fi

# Extract the real filesystem paths directly onto / (overwrite, never delete)
# -p preserves perms, --xattrs/--acls preserve extended attrs
tar -xzpf "$BK" -C / --xattrs --acls --overwrite --keep-directory-symlink \
    --exclude=MANIFEST --exclude=pg_dumpall.sql \
    --exclude=packages.dpkg --exclude=packages.rpm --exclude=enabled.units \
    --exclude=etc/hostname --exclude=etc/hosts --exclude=etc/resolv.conf
echo "files extracted"

# Postgres logical restore if present
if [[ -f "$TMP/pg_dumpall.sql" ]] && systemctl is-active postgresql &>/dev/null; then
    echo "restoring postgres from pg_dumpall.sql…"
    sudo -u postgres psql -f "$TMP/pg_dumpall.sql" postgres >/dev/null 2>&1 \
        && echo "  postgres restored" || echo "  postgres restore had errors (review manually)"
fi

systemctl daemon-reload 2>/dev/null || true
echo
echo "restore complete — reload affected services manually, e.g.:"
echo "  systemctl reload sshd apache2 nginx vsftpd smbd named postgresql"
