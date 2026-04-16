#!/bin/bash
# Restore example: cp -a /opt/.backups/2026-04-15_12-00-00/etc/ssh /etc/ssh
set -euo pipefail

[ "$EUID" -eq 0 ] || { echo "Run as root"; exit 1; }

BACKUP_ROOT="/opt/.backups"
STAMP=$(date +"%F_%H-%M-%S")
DEST="$BACKUP_ROOT/$STAMP"
mkdir -p "$DEST"

# Copy a path into the backup, preserving directory structure
backup() {
    for p in "$@"; do
        [ -e "$p" ] || continue
        mkdir -p "$DEST$(dirname "$p")"
        cp -a "$p" "$DEST$p"
    done
}

# Copy a binary by name (resolves via which)
backup_bin() {
    for b in "$@"; do
        local path
        path=$(which "$b" 2>/dev/null) || continue
        backup "$path"
    done
}

echo "[*] Backing up to $DEST"

# backup /etc
echo "[*] /etc"
backup /etc

# backup service data directories
echo "[*] Service data"
backup /var/www
backup /srv/ftp
backup /var/cache/bind /var/named
backup /var/lib/postgresql /var/lib/pgsql

# backup postgresql data
if command -v pg_dumpall >/dev/null 2>&1 && systemctl is-active --quiet postgresql 2>/dev/null; then
    echo "[*] pg_dumpall"
    sudo -u postgres pg_dumpall -c > "$DEST/postgres_dump.sql" 2>/dev/null || echo "[!] pg_dumpall failed"
fi

# backup service binaries
echo "[*] Service binaries"
backup_bin sshd ssh
backup_bin named
backup_bin vsftpd
backup_bin smbd nmbd smbclient
backup_bin postgres pg_dump pg_dumpall psql
backup_bin apache2 httpd apachectl
backup_bin nginx

echo "[+] Backup complete: $DEST"
