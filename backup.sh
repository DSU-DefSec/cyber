#!/usr/bin/env bash
# backup_fixed.sh
# Safer system backup for Ubuntu 24.04 / Rocky 9 style hosts.
#
# Default behavior:
#   - writes to /var/backups/system-snapshots, not /
#   - creates a timestamped tar.gz plus sha256
#   - stores useful metadata for auditing and restore planning
#   - does NOT hide all tar errors
#
# Usage:
#   sudo ./backup_fixed.sh
#   sudo ./backup_fixed.sh /path/to/backup-dir

set -Eeuo pipefail
umask 077

log() { printf '[backup] %s\n' "$*"; }
die() { printf '[backup] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  (( EUID == 0 )) || die 'must run as root'
}

is_systemd_active() {
  command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1 || command -v systemctl >/dev/null 2>&1
}

postgres_is_running() {
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl is-active --quiet postgresql 2>/dev/null || \
  systemctl is-active --quiet postgresql.service 2>/dev/null
}

collect_paths() {
  local -a raw_paths=(
    /etc
    /usr/lib/systemd/system
    /etc/systemd/system
    /var/www
    /srv/ftp
    /var/ftp
    /var/lib/samba
    /var/named
    /var/lib/bind
    /var/lib/postgresql
    /var/lib/pgsql
    /etc/pki
    /root/.ssh
  )

  KEEP=()
  local p
  for p in "${raw_paths[@]}"; do
    [[ -e "$p" ]] && KEEP+=("$p")
  done

  # Add per-user ssh directories for "real" users.
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    (( uid >= 1000 )) || continue
    [[ -d "$home/.ssh" ]] || continue
    KEEP+=("$home/.ssh")
  done < /etc/passwd
}

write_metadata() {
  local meta_dir="$1"
  mkdir -p "$meta_dir"

  {
    echo "created_at=$(date -Iseconds)"
    echo "hostname=$(hostname -f 2>/dev/null || hostname)"
    echo "kernel=$(uname -srmo 2>/dev/null || uname -a)"
    echo "backup_destination=$DEST"
    echo "archive_name=$(basename "$OUT")"
  } > "$meta_dir/backup.env"

  if [[ -f /etc/os-release ]]; then
    cp /etc/os-release "$meta_dir/os-release"
  fi

  if command -v dpkg >/dev/null 2>&1; then
    dpkg --get-selections > "$meta_dir/packages.dpkg" || true
  elif command -v rpm >/dev/null 2>&1; then
    rpm -qa > "$meta_dir/packages.rpm" || true
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files --state=enabled > "$meta_dir/enabled.units" 2>/dev/null || true
  fi

  mount > "$meta_dir/mounts.txt" 2>/dev/null || true
  df -h > "$meta_dir/disk-usage.txt" 2>/dev/null || true

  {
    echo "# included paths"
    printf '%s\n' "${KEEP[@]}"
  } > "$meta_dir/MANIFEST"

  if command -v pg_dumpall >/dev/null 2>&1 && postgres_is_running; then
    if sudo -u postgres pg_dumpall > "$meta_dir/pg_dumpall.sql" 2> "$meta_dir/pg_dumpall.stderr"; then
      log "postgres logical dump created"
      rm -f "$meta_dir/pg_dumpall.stderr"
    else
      log "postgres logical dump failed, see metadata/pg_dumpall.stderr"
    fi
  fi
}

create_archive() {
  local meta_root="$1"
  local tar_err="$2"
  local -a tar_args=(
    --create
    --gzip
    --file "$OUT"
    --preserve-permissions
    --acls
    --xattrs
    --numeric-owner
    --warning=no-file-ignored
    --directory /
  )

  local -a relative_keep=()
  local item
  for item in "${KEEP[@]}"; do
    relative_keep+=("${item#/}")
  done

  # metadata goes in as relative content from the temporary workdir
  tar "${tar_args[@]}" \
    --transform 's,^,metadata/,' \
    --directory "$meta_root" . \
    --directory / "${relative_keep[@]}" \
    2> "$tar_err"
}

main() {
  require_root

  DEST="${1:-/var/backups/system-snapshots}"
  [[ -n "$DEST" ]] || die 'destination cannot be empty'

  mkdir -p "$DEST"
  [[ -d "$DEST" ]] || die "not a directory: $DEST"
  [[ -w "$DEST" ]] || die "destination not writable: $DEST"

  DEST="$(readlink -f "$DEST")"
  [[ "$DEST" != "/" ]] || die 'refusing to write backups directly into /'

  STAMP="$(date +%Y%m%d_%H%M%S)"
  HOST="$(hostname -s 2>/dev/null || hostname)"
  OUT="$DEST/backup_${HOST}_${STAMP}.tar.gz"
  SUM="$OUT.sha256"

  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT

  collect_paths
  ((${#KEEP[@]} > 0)) || die 'no paths found to back up'

  write_metadata "$WORK/metadata"
  create_archive "$WORK" "$WORK/tar.stderr"

  sha256sum "$OUT" > "$SUM"

  if [[ -s "$WORK/tar.stderr" ]]; then
    log 'tar emitted warnings:'
    sed 's/^/[backup]   /' "$WORK/tar.stderr" >&2
  fi

  log "archive: $OUT"
  log "sha256 : $SUM"
  log "paths  : ${#KEEP[@]}"
  log "size   : $(du -h "$OUT" | cut -f1)"
}

main "$@"
