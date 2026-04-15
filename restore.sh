qracced
qracced
Online

The Oracle — 11:41
Yeah, I'll do something after my exam today
Professor Nyanstein — 11:44
Image
us rn yall
qracced — 11:45
nah bruh
we are not scripting any service configs like the other teams always try to do
just threat hunting
which bro the entire world of threat hunting meta now is just trying to automate everything
why not do it
plus firewall deploy but why would i not script that
Professor Nyanstein — 11:46
ikrrrrrrrrrr..
Professor Nyanstein — 11:46
trueeeeeeee
also we shall have a meeting with everyone today or tmr evening so i can give everyone there shirts. Mary bell said that i will be ale to pick them up today
qracced — 11:48
tomorrow and thursday
Professor Nyanstein — 15:36
@qracced
Image
qracced — 15:37
yeah we have to finish our crap before we do that
last task of today will be to add it
Professor Nyanstein — 15:41
Image
@qracced are we meeting at 4 if yes where
Also @The Oracle are u joining
qracced — 15:46
library
gonna be slightly delayed cause i need to finish uploading the ctf challenges
The Oracle — 16:00
Yh
Professor Nyanstein — 17:19
@qracced hola senor. donde estan\
qracced — 17:22
Scheiße
I will be there soon lol
Professor Nyanstein — 17:23
we are in the room in TC
qracced — 17:23
I had to do a rare dsu student activity of taking a shower
Professor Nyanstein — 17:23
wow
The Oracle — 18:47
@qracced can you forward the message that we went over during our last NCAE meeting to this group chat
qracced — 18:48
Forwarded
Hiya! I'm Kavan and I can give some insights on the strats we used. So for me, I was mainly on threat hunting (I also kept DNS up) for our team and found some really cool backdoors. One surefire way to find backdoors are modified packages, so checking package integrity is huge. Running debsums or rpm -Va is super important, but also just having a lot of foundational OS knowledge helps because you know what's not normal, and you can get that just by using linux a lot. I am not a rocky daily user obviously but still use variants of gnu/linux basically daily.

Also ps aux was like my default fallback when I wasn't threat hunting or keeping DNS up. There were so many malicious binaries it was hard to count. One such was a shell I'm pretty sure was present called watershell which bypassed host based firewalls entirely. Another shell was /sbin/nologin, which looks like normal nologin but actually drops any users with nologin in /etc/passwd into a shell 💀. Checking for malicious binaries is SO huge.

I was checking for network connections a LOT. If you have an open port you shouldn't have open you probably should look for a malicious process. Additionally, researching the processes running is huge. There's this really cool tool that I did not get around to using in comp but have experimented with before that helps with this. https://github.com/DominicBreuker/pspy. 

Some other things:
Learning to red team helps with the mentality of defending against red team.
Remove avenues of privilege escalation to root.
Keep backups of some kind. One time I had someone ask if they could make backups after their configs were already deleted. They are meant to be there BEFORE they are nuked lol.
Try writing backdoors of your own.
Watch for file modifications and what process modified your files. inotifywait can help
Script out as much as you can beforehand, but knowledge always beats pre-written scripts.

Let me know if you have more questions for us! Thanks, Kavan

NCAE Cyber Games  •  4/14/2025
The Oracle — 20:14
@qracced is there anything I should know b4 pushing the pspy binary highlighted in this message?
qracced — 20:17
uhhh
can you let me push first, then you can push
The Oracle — 20:18
So there's the binary that watches for file changes on selected directories. I want to add that but you were talking about licenses
qracced — 20:18
yeah
just push it in a sec i will handle license compliance
wait til i tell you, we are about to push
The Oracle — 20:19
Okay
qracced — 20:27
@The Oracle pull and then you can push now
The Oracle — 20:27
Bet
qracced — 20:27
put the file inside the /open3 directory
it doesnt show up there yet cause theres nothing there but just create it and then put it there 
Professor Nyanstein — 20:28
@The Oracle just get your lazy ass to TC underground
The Oracle — 20:29
Nah
Professor Nyanstein — 20:39
oyyyeeeeeeeeeeeeeeeeeee push rnnnnnnnnnnn
Professor Nyanstein — 20:42
yo benji the black king we have a problem
come to T CCCCCC
What I fixed:


restore no longer writes to / by default


restore stages into a preview directory unless you explicitly use --apply


restoring to / now also requires --force-overwrite


postgres restore is now opt-in, not automatic


backup now defaults to /var/backups/system-snapshots


backup refuses to write directly into /


added set -Eeuo pipefail and tighter permissions


added checksum output with .sha256


added metadata folder inside the archive, including manifest, package list, enabled units, OS info


stopped hiding all tar warnings/errors


excluded volatile host-specific files during restore like hostname, hosts, resolv.conf, and machine-id


How to use them:
Backup:
sudo ./backup_fixed.sh
Backup to a custom directory:
sudo ./backup_fixed.sh /path/to/backups
Preview restore safely:
sudo ./restore_fixed.sh backup_HOST_TIMESTAMP.tar.gz
Restore into a separate directory:
sudo ./restore_fixed.sh backup_HOST_TIMESTAMP.tar.gz --apply --target-root /tmp/restore-tree
Restore onto the real system root, only if you truly want that:
sudo ./restore_fixed.sh backup_HOST_TIMESTAMP.tar.gz --apply --target-root / --force-overwrite
Verify checksum during restore:
sudo ./restore_fixed.sh backup_HOST_TIMESTAMP.tar.gz --verify
Restore postgres too:
sudo ./restore_fixed.sh backup_HOST_TIMESTAMP.tar.gz --apply --target-root / --force-overwrite --restore-postgres
One important note: I syntax-checked both rewritten scripts, but I did not run a full live backup/restore in this environment because that would act on the container’s real filesystem.
If you want, I can also make you a third version that is even better for production, with exclusions, logging to a file, retention cleanup, and optional rsync-based restores.
#!/usr/bin/env bash
# backup_fixed.sh
# Safer system backup for Ubuntu 24.04 / Rocky 9 style hosts.
#
# Default behavior:
#   - writes to /var/backups/system-snapshots, not /

backup_fixed.sh
5 KB
#!/usr/bin/env bash
# restore_fixed.sh
# Safer restore companion for backup_fixed.sh.
#
# Default behavior:
#   - never writes to / unless you explicitly request it

restore_fixed.sh
6 KB
The Oracle — 20:48
it's all still vibecoded
The Oracle — 20:48
I've put it there
qracced — 20:48
yeah i know its cooked bro
claude screwed everything up
The Oracle — 20:51
I'm just gonna wrap everything into a tarball...
qracced — 20:52
what do you mean by everything
The Oracle — 20:53
that's for me to decide
qracced — 21:01
benji are you gonna push more
Professor Nyanstein — 21:02
# Help Guide for `backup_fixed.sh` and `restore_fixed.sh`

This guide explains how to use the safer backup and restore scripts.

## What these scripts do

help.md
9 KB
The Oracle — 21:02
Nope
qracced — 21:02
k
﻿
#!/usr/bin/env bash
# restore_fixed.sh
# Safer restore companion for backup_fixed.sh.
#
# Default behavior:
#   - never writes to / unless you explicitly request it
#   - defaults to staging extraction under ./restore-preview-<timestamp>
#   - only overwrites existing files when --force-overwrite is supplied
#   - postgres restore is opt-in, never automatic
#
# Usage examples:
#   sudo ./restore_fixed.sh backup.tar.gz
#   sudo ./restore_fixed.sh backup.tar.gz --target-root /tmp/restore-tree
#   sudo ./restore_fixed.sh backup.tar.gz --apply --target-root / --force-overwrite
#   sudo ./restore_fixed.sh backup.tar.gz --apply --target-root /mnt/recovery-root --restore-postgres

set -Eeuo pipefail
umask 077

log() { printf '[restore] %s\n' "$*"; }
die() { printf '[restore] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  (( EUID == 0 )) || die 'must run as root'
}

usage() {
  cat <<'USAGE'
Usage:
  sudo ./restore_fixed.sh <backup.tar.gz> [options]

Options:
  --target-root DIR      Extract into DIR. Default: ./restore-preview-<timestamp>
  --apply                Actually perform extraction into target root
  --force-overwrite      Allow restore to overwrite existing files
  --restore-postgres     Restore metadata/pg_dumpall.sql into local postgres after extraction
  --verify               Verify the archive with a sibling .sha256 file if present
  --list-only            Show manifest and archive contents, then exit
  -h, --help             Show this help

Safety defaults:
  - Without --apply, the script only stages files into a preview directory.
  - Writing directly into / requires --apply and should usually also use --force-overwrite.
  - Postgres restore is never automatic.
USAGE
}

BACKUP=''
TARGET_ROOT=''
APPLY=0
FORCE_OVERWRITE=0
RESTORE_POSTGRES=0
VERIFY=0
LIST_ONLY=0

parse_args() {
  [[ $# -gt 0 ]] || { usage; exit 1; }

  BACKUP="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target-root)
        [[ $# -ge 2 ]] || die '--target-root requires a value'
        TARGET_ROOT="$2"
        shift 2
        ;;
      --apply)
        APPLY=1
        shift
        ;;
      --force-overwrite)
        FORCE_OVERWRITE=1
        shift
        ;;
      --restore-postgres)
        RESTORE_POSTGRES=1
        shift
        ;;
      --verify)
        VERIFY=1
        shift
        ;;
      --list-only)
        LIST_ONLY=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done
}

verify_archive() {
  local sum_file="${BACKUP}.sha256"
  if [[ -f "$sum_file" ]]; then
    (cd "$(dirname "$sum_file")" && sha256sum -c "$(basename "$sum_file")")
    log 'checksum verified'
  else
    log 'no sibling .sha256 file found, skipping checksum verification'
  fi
}

extract_metadata() {
  tar -xzf "$BACKUP" -C "$TMP" \
    metadata/MANIFEST \
    metadata/backup.env \
    metadata/os-release \
    metadata/packages.dpkg \
    metadata/packages.rpm \
    metadata/enabled.units \
    metadata/pg_dumpall.sql \
    2>/dev/null || true
}

print_manifest() {
  if [[ -f "$TMP/metadata/MANIFEST" ]]; then
    log 'manifest:'
    grep -vE '^[[:space:]]*(#|$)' "$TMP/metadata/MANIFEST" | sed 's/^/[restore]   /'
  else
    log 'no manifest found in archive'
  fi
}

print_archive_paths() {
  log 'archive contents:'
  tar -tzf "$BACKUP" | sed 's/^/[restore]   /'
}

extract_archive() {
  mkdir -p "$TARGET_ROOT"
  TARGET_ROOT="$(readlink -f "$TARGET_ROOT")"

  local -a tar_args=(
    -xzpf "$BACKUP"
    -C "$TARGET_ROOT"
    --acls
    --xattrs
    --numeric-owner
    --keep-directory-symlink
    --exclude=metadata
    --exclude=etc/hostname
    --exclude=etc/hosts
    --exclude=etc/resolv.conf
    --exclude=etc/machine-id
  )

  if (( FORCE_OVERWRITE )); then
    tar_args+=(--overwrite)
  else
    tar_args+=(--keep-old-files)
  fi

  tar "${tar_args[@]}"
}

restore_postgres_dump() {
  [[ -f "$TMP/metadata/pg_dumpall.sql" ]] || {
    log 'no postgres dump found, skipping postgres restore'
    return 0
  }

  command -v psql >/dev/null 2>&1 || die 'psql is not installed but --restore-postgres was requested'
  command -v systemctl >/dev/null 2>&1 || die 'systemctl is not available but --restore-postgres was requested'

  if systemctl is-active --quiet postgresql 2>/dev/null || systemctl is-active --quiet postgresql.service 2>/dev/null; then
    log 'restoring postgres from metadata/pg_dumpall.sql'
    if sudo -u postgres psql -f "$TMP/metadata/pg_dumpall.sql" postgres; then
      log 'postgres restore completed'
    else
      die 'postgres restore failed, review output above'
    fi
  else
    die 'postgres service is not active but --restore-postgres was requested'
  fi
}

main() {
  require_root
  parse_args "$@"

  [[ -f "$BACKUP" ]] || die "backup file not found: $BACKUP"
  BACKUP="$(readlink -f "$BACKUP")"

  if (( VERIFY )); then
    verify_archive
  fi

  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  extract_metadata
  print_manifest

  if (( LIST_ONLY )); then
    print_archive_paths
    exit 0
  fi

  if [[ -z "$TARGET_ROOT" ]]; then
    TARGET_ROOT="$(pwd)/restore-preview-$(date +%Y%m%d_%H%M%S)"
  fi

  if (( APPLY == 0 )); then
    log "staging restore into $TARGET_ROOT"
    extract_archive
    log 'preview extraction complete'
    log 'nothing was written to the live filesystem unless your target root was /'
    exit 0
  fi

  TARGET_ROOT="$(readlink -m "$TARGET_ROOT")"
  if [[ "$TARGET_ROOT" == "/" && "$FORCE_OVERWRITE" -eq 0 ]]; then
    die 'refusing to restore to / without --force-overwrite'
  fi

  log "applying restore into $TARGET_ROOT"
  extract_archive
  log 'file restore complete'

  if (( RESTORE_POSTGRES )); then
    restore_postgres_dump
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
  fi

  log 'done'
  log 'reload or restart affected services manually after review'
}

main "$@"
