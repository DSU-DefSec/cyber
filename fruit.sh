#!/bin/bash
# find backdoors on services

BODY=""; _VAL=""; COUNT_CRIT=0; COUNT_HIGH=0; COUNT_MED=0

load_configs() {
    BODY=""
    local f pat found=1
    shopt -s nullglob
    for pat in "$@"; do
        for f in $pat; do
            [[ -f $f ]] || continue
            BODY+=$'\n'"$(cat "$f" 2>/dev/null)"
            found=0
        done
    done
    shopt -u nullglob
    return $found
}

get_dir() {
    _VAL=$(printf '%s\n' "$BODY" \
        | grep -iE "^[[:space:]]*$1[[:space:]]+" | grep -v '^[[:space:]]*#' | head -1 \
        | sed -E "s/^[[:space:]]*$1[[:space:]]+//i; s/[[:space:]]*#.*//; s/['\"]//g" \
        | xargs 2>/dev/null) || true
}

get_eq() {
    _VAL=$(printf '%s\n' "$BODY" \
        | grep -iE "^[[:space:]]*$1[[:space:]]*=" | grep -v '^[[:space:]]*#' | head -1 \
        | sed -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//i; s/[[:space:]]*#.*//; s/['\"]//g" \
        | xargs 2>/dev/null) || true
}

body_has() { printf '%s\n' "$BODY" | grep -qiE "$1"; }

hit() {
    printf '  [%-8s] %s\n             fix: %s\n' "$1" "$2" "$3"
    case "$1" in CRITICAL) COUNT_CRIT=$((COUNT_CRIT+1)) ;;
                 HIGH)     COUNT_HIGH=$((COUNT_HIGH+1)) ;;
                 MEDIUM)   COUNT_MED=$((COUNT_MED+1))  ;; esac
}

# apache2 web server
check_apache2() {
    load_configs \
        '/etc/apache2/apache2.conf' '/etc/apache2/conf-enabled/*.conf' \
        '/etc/apache2/sites-enabled/*.conf' '/etc/httpd/conf/httpd.conf' \
        '/etc/httpd/conf.d/*.conf' || { echo "  (not installed)"; return; }
    local proto clean

    # Directory listing - exposes files/backups/creds in docroot
    body_has 'Options[[:space:]][^#]*\bIndexes\b' && \
        hit HIGH 'Directory listing enabled (Options Indexes)' \
            'remove "Indexes" from all Options directives'

    # FollowSymLinks without SymLinksIfOwnerMatch - docroot escape
    if body_has 'Options[[:space:]][^#]*\bFollowSymLinks\b' && \
       ! body_has 'Options[[:space:]][^#]*\bSymLinksIfOwnerMatch\b'; then
        hit MEDIUM 'FollowSymLinks without SymLinksIfOwnerMatch (docroot escape risk)' \
            'replace FollowSymLinks with SymLinksIfOwnerMatch'
    fi

    # AllowOverride All - .htaccess can override security directives
    body_has '^[[:space:]]*AllowOverride[[:space:]]+All\b' && \
        hit MEDIUM 'AllowOverride All - .htaccess can override security rules' \
            'AllowOverride None  (or only the directives you need)'

    # TRACE method - XST cookie theft
    get_dir TraceEnable
    [[ -z $_VAL || ${_VAL,,} != off ]] && \
        hit MEDIUM 'HTTP TRACE enabled (XST cookie theft)' \
            'TraceEnable Off'

    # Weak TLS protocols - downgrade
    for proto in SSLv2 SSLv3 'TLSv1 ' 'TLSv1\.1'; do
        body_has "SSLProtocol[[:space:]][^#]*${proto}" || continue
        clean="${proto// /}"
        hit HIGH "Weak TLS protocol permitted: $clean" \
            'SSLProtocol TLSv1.2 TLSv1.3'
    done

    # /server-status without IP restriction - internals/URIs exposed
    if body_has '<Location[[:space:]][^>]*/server-status' && \
       ! body_has 'Require[[:space:]]+(ip|local|host)'; then
        hit HIGH '/server-status exposed without IP restriction' \
            'add "Require ip 127.0.0.1" inside the <Location /server-status>'
    fi

    # ExecCGI in Options - enables CGI script execution (RCE if dir is writable)
    body_has 'Options[[:space:]][^#]*\bExecCGI\b' && \
        hit HIGH 'Options ExecCGI enabled - CGI execution allowed in directory (RCE if writable)' \
            'Remove ExecCGI from Options; use ScriptAlias only for trusted CGI dirs'

    # Includes in Options - enables Server-Side Include exec directives
    body_has 'Options[[:space:]][^#]*\bIncludes\b' && \
        hit HIGH 'Options Includes enabled - SSI exec directives allowed (RCE vector)' \
            'Remove Includes from Options; use IncludesNOEXEC if SSI output is needed'
}

# nginx web server/proxy
check_nginx() {
    load_configs \
        '/etc/nginx/nginx.conf' '/etc/nginx/conf.d/*.conf' \
        '/etc/nginx/sites-enabled/*.conf' || { echo "  (not installed)"; return; }
    local proto_line proto clean

    # autoindex on - directory listing
    body_has '^[[:space:]]*autoindex[[:space:]]+on[[:space:]]*;' && \
        hit HIGH 'Directory listing enabled (autoindex on)' \
            'autoindex off;'

    # Weak SSL protocols
    proto_line=$(printf '%s\n' "$BODY" | grep -iE 'ssl_protocols[[:space:]]+' | head -1)
    if [[ -n $proto_line ]]; then
        for proto in SSLv2 SSLv3 'TLSv1 ' 'TLSv1\.1'; do
            printf '%s\n' "$proto_line" | grep -qiE "$proto" || continue
            clean="${proto// /}"
            hit HIGH "Weak TLS protocol in ssl_protocols: $clean" \
                'ssl_protocols TLSv1.2 TLSv1.3;'
        done
    fi

    # Weak cipher groups explicitly in ssl_ciphers
    local cipher
    for cipher in RC4 '3DES' 'NULL' EXPORT aNULL ADH; do
        body_has "ssl_ciphers[^;]*${cipher}" || continue
        hit HIGH "Weak cipher group in ssl_ciphers: $cipher" \
            'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!RC4:!3DES:!aNULL;'
        break
    done
}

# openssh ssh server
check_openssh() {
    load_configs '/etc/ssh/sshd_config' '/etc/ssh/sshd_config.d/*.conf' \
        || { echo "  (not installed)"; return; }
    local v c

    # Root login
    get_dir PermitRootLogin; v="${_VAL,,}"
    [[ -z $v || ( $v != no && $v != prohibit-password && $v != forced-commands-only ) ]] && \
        hit CRITICAL "Root SSH login permitted (PermitRootLogin=${_VAL:-yes})" \
            'PermitRootLogin no'

    # Empty passwords
    get_dir PermitEmptyPasswords
    [[ ${_VAL,,} == yes ]] && \
        hit CRITICAL 'Empty passwords permitted over SSH' \
            'PermitEmptyPasswords no'

    # Protocol 1
    get_dir Protocol
    [[ -n $_VAL && $_VAL == *1* ]] && \
        hit CRITICAL "SSHv1 enabled (Protocol=$_VAL)" \
            'Protocol 2'

    # Password auth (brute force surface)
    get_dir PasswordAuthentication; v="${_VAL,,}"
    [[ -z $v || $v == yes ]] && \
        hit HIGH 'Password authentication enabled (brute-force exposure)' \
            'PasswordAuthentication no  (deploy SSH keys)'

    # MaxAuthTries (brute force aid)
    get_dir MaxAuthTries; v="${_VAL:-6}"
    if ! [[ $v =~ ^[0-9]+$ ]] || (( v > 4 )); then
        hit MEDIUM "MaxAuthTries=${_VAL:-6} - too many attempts per connection" \
            'MaxAuthTries 3'
    fi

    # Weak Ciphers
    get_dir Ciphers; v="${_VAL,,}"
    if [[ -n $v ]]; then
        for c in arcfour 3des-cbc blowfish-cbc cast128-cbc aes128-cbc aes192-cbc aes256-cbc; do
            [[ $v == *"$c"* ]] || continue
            hit HIGH "Weak cipher in SSH Ciphers list: $c" \
                'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com'
            break
        done
    fi

    # AllowUsers/AllowGroups (reduces attack surface)
    body_has '^[[:space:]]*(AllowUsers|AllowGroups)[[:space:]]+' || \
        hit MEDIUM 'No AllowUsers/AllowGroups - every system account can authenticate' \
            'AllowUsers <user1> <user2>'

    # Backdoored AuthorizedKeysFile
    get_dir AuthorizedKeysFile
    # Default is usually .ssh/authorized_keys or .ssh/authorized_keys .ssh/authorized_keys2
    if [[ -n $_VAL && $_VAL != ".ssh/authorized_keys" && $_VAL != ".ssh/authorized_keys .ssh/authorized_keys2" ]]; then
        hit CRITICAL "Non-standard AuthorizedKeysFile defined: $_VAL" \
            'Remove AuthorizedKeysFile directive to restore default behavior'
    fi

    # AuthorizedKeysCommand - external binary can inject arbitrary public keys
    get_dir AuthorizedKeysCommand
    [[ -n $_VAL && ${_VAL,,} != none ]] && \
        hit CRITICAL "AuthorizedKeysCommand=$_VAL - external program provides authorized keys (backdoor if tampered)" \
            'Remove AuthorizedKeysCommand unless intentional; verify the binary is trusted and unmodified'

    # StrictModes no - SSH will accept world-writable authorized_keys files
    get_dir StrictModes; v="${_VAL,,}"
    [[ $v == no ]] && \
        hit CRITICAL 'StrictModes no - SSH accepts world-writable authorized_keys (trivial key injection)' \
            'StrictModes yes'

    # AllowTcpForwarding - turns SSH into a TCP pivot / tunnel
    get_dir AllowTcpForwarding; v="${_VAL,,}"
    [[ -z $v || $v == yes ]] && \
        hit HIGH 'AllowTcpForwarding enabled - SSH can be used as a TCP tunnel or pivot point' \
            'AllowTcpForwarding no'

    # GatewayPorts - remote port-forwards bind on 0.0.0.0 instead of 127.0.0.1
    get_dir GatewayPorts; v="${_VAL,,}"
    [[ $v == yes || $v == clientspecified ]] && \
        hit HIGH "GatewayPorts=$_VAL - remote port-forwards accessible on all interfaces" \
            'GatewayPorts no'

    # PermitTunnel - tun/tap VPN-style device tunneling
    get_dir PermitTunnel; v="${_VAL,,}"
    [[ -n $v && $v != no ]] && \
        hit HIGH "PermitTunnel=$_VAL - VPN-style tun/tap tunneling allowed over SSH" \
            'PermitTunnel no'

    # HostbasedAuthentication - auth based on hostname (spoofable)
    get_dir HostbasedAuthentication; v="${_VAL,,}"
    [[ $v == yes ]] && \
        hit HIGH 'HostbasedAuthentication yes - host-based auth enabled (hostname is spoofable)' \
            'HostbasedAuthentication no'

    # X11Forwarding - X11 connections tunneled over SSH
    get_dir X11Forwarding; v="${_VAL,,}"
    [[ -z $v || $v == yes ]] && \
        hit MEDIUM 'X11Forwarding enabled - X11 connections can be tunneled over SSH' \
            'X11Forwarding no'

    # UsePAM no - bypasses PAM stack (account lockout, MFA, etc.)
    get_dir UsePAM; v="${_VAL,,}"
    [[ $v == no ]] && \
        hit MEDIUM 'UsePAM no - PAM modules bypassed (account lockout and MFA checks skipped)' \
            'UsePAM yes'
}

# vsftpd ftp server
check_vsftpd() {
    load_configs '/etc/vsftpd.conf' '/etc/vsftpd/vsftpd.conf' \
        || { echo "  (not installed)"; return; }
    local v d

    # Anonymous access
    get_eq anonymous_enable; v="${_VAL^^}"
    [[ -z $v || $v == YES ]] && \
        hit CRITICAL "Anonymous FTP enabled (anonymous_enable=${_VAL:-YES})" \
            'anonymous_enable=NO'

    # Anonymous upload - webshell drop
    get_eq anon_upload_enable
    [[ ${_VAL^^} == YES ]] && \
        hit CRITICAL 'Anonymous uploads enabled (webshell drop vector)' \
            'anon_upload_enable=NO'

    get_eq anon_mkdir_write_enable
    [[ ${_VAL^^} == YES ]] && \
        hit HIGH 'Anonymous directory creation enabled' \
            'anon_mkdir_write_enable=NO'

    # Local users not chrooted - filesystem traversal
    get_eq chroot_local_user; v="${_VAL^^}"
    [[ -z $v || $v != YES ]] && \
        hit HIGH 'Local users not chrooted - full FS traversal via FTP' \
            'chroot_local_user=YES'

    # Cleartext credentials
    get_eq ssl_enable; v="${_VAL^^}"
    if [[ -z $v || $v != YES ]]; then
        hit HIGH 'SSL/TLS disabled - FTP creds+data in cleartext' \
            'ssl_enable=YES + rsa_cert_file/rsa_private_key_file'
    else
        get_eq allow_anon_ssl
        [[ ${_VAL^^} == YES ]] && \
            hit MEDIUM 'allow_anon_ssl=YES - SSL for anonymous sessions' \
                'allow_anon_ssl=NO'
        for d in force_local_data_ssl force_local_logins_ssl; do
            get_eq "$d"; v="${_VAL^^}"
            [[ -z $v || $v != YES ]] && \
                hit MEDIUM "$d not enforced - plaintext fallback" "$d=YES"
        done
    fi
}

# samba smb server
get_global_smb() {
    _VAL=$(printf '%s\n' "$BODY" | awk -v key="${1,,}" '
        /^\[global\]/                   { in_g=1; next }
        /^\[[^]]+\]/ && !/^\[global\]/  { in_g=0 }
        in_g {
            line = tolower($0); gsub(/^[[:space:]]+/, "", line)
            if (line ~ ("^" key "[[:space:]]*=")) {
                sub(/^[^=]+=[[:space:]]*/, "", line); sub(/[[:space:]]*#.*$/, "", line)
                print line; exit
            }
        }') || true
}

check_samba() {
    load_configs '/etc/samba/smb.conf' '/etc/smb.conf' \
        || { echo "  (not installed)"; return; }
    local v key

    # Null passwords
    get_global_smb 'null passwords'; v="${_VAL,,}"
    [[ $v == yes || $v == true || $v == 1 ]] && \
        hit CRITICAL 'null passwords = yes - empty-password accounts accepted' \
            'null passwords = no'

    # Guest access
    body_has '^[[:space:]]*guest ok[[:space:]]*=[[:space:]]*yes' && \
        hit HIGH 'guest ok = yes on one or more shares - unauthenticated share access' \
            'guest ok = no  (on every share)'

    get_global_smb 'map to guest'; v="${_VAL,,}"
    [[ $v == 'bad user' || $v == 'bad password' ]] && \
        hit HIGH "map to guest = $_VAL - failed logins fall back to guest" \
            'map to guest = never'

    # SMB signing / MITM
    get_global_smb 'server signing'; v="${_VAL,,}"
    [[ -z $v || $v == auto || $v == disabled || $v == no ]] && \
        hit HIGH "server signing=${_VAL:-auto} - SMB packets MITM-tamperable" \
            'server signing = mandatory'

    # SMBv1 / EternalBlue
    for key in 'client min protocol' 'server min protocol'; do
        get_global_smb "$key"; v="${_VAL^^}"
        [[ -z $v || $v == NT1 || $v == LANMAN1 || $v == LANMAN2 || $v == CORE || $v == COREPLUS ]] && \
            hit HIGH "$key=${_VAL:-unset} - SMBv1 (EternalBlue/MS17-010)" \
                "$key = SMB2"
    done

    # Encryption
    get_global_smb 'smb encrypt'; v="${_VAL,,}"
    [[ -z $v || $v == auto || $v == disabled || $v == no ]] && \
        hit MEDIUM "smb encrypt=${_VAL:-auto} - SMB traffic not end-to-end encrypted" \
            'smb encrypt = required'

    # Anonymous enumeration (share/user discovery)
    get_global_smb 'restrict anonymous'; v="${_VAL:-0}"
    [[ -z ${_VAL:-} || $v == 0 ]] && \
        hit MEDIUM 'Anonymous share/user enumeration allowed' \
            'restrict anonymous = 2'
}

# named dns server
check_bind() {
    load_configs \
        '/etc/bind/named.conf' '/etc/bind/named.conf.options' \
        '/etc/named.conf' '/etc/named/named.conf' '/etc/named/named.conf.options' \
        || { echo "  (not installed)"; return; }

    # Open recursion - amplification DDoS, cache poisoning
    if body_has 'recursion[[:space:]]+yes[[:space:]]*;' && \
       ! body_has 'allow-recursion[[:space:]]*\{'; then
        hit CRITICAL 'Open recursive resolver (recursion yes; no allow-recursion)' \
            'allow-recursion { 127.0.0.1; <internal>; };'
    fi

    # Zone transfer open - full zone dump
    if body_has 'allow-transfer[[:space:]]*\{[^}]*\bany\b[^}]*\}'; then
        hit CRITICAL 'Zone transfers open to any host (allow-transfer { any; })' \
            'allow-transfer { <secondary_ns_ip>; };'
    elif ! body_has 'allow-transfer[[:space:]]*\{'; then
        hit HIGH 'allow-transfer not configured - may default to open' \
            'allow-transfer { none; };  globally'
    fi

    # allow-query not set
    body_has 'allow-query[[:space:]]*\{' || \
        hit MEDIUM 'allow-query not configured - answers any source' \
            'allow-query { your_network; };'

    # allow-update open to any - attackers can modify zone records
    body_has 'allow-update[[:space:]]*\{[^}]*\bany\b[^}]*\}' && \
        hit CRITICAL 'Dynamic DNS updates open to any host (allow-update { any; }) - zone poisoning' \
            'allow-update { none; };  (or restrict to specific DDNS IPs)'

    # BIND version string not hidden - fingerprintable via DNS query
    body_has 'version[[:space:]]*"' || \
        hit MEDIUM 'BIND version string not hidden - reveals exact version via DNS CHAOS query' \
            'Add: version "not disclosed";  inside options { } block'
}

# postgresql
check_postgres() {
    local pg_body="" pg_path="" hba_body="" hba_path="" f pat
    shopt -s nullglob
    for pat in '/etc/postgresql/*/main/postgresql.conf' \
               '/var/lib/pgsql/data/postgresql.conf' \
               '/var/lib/postgresql/*/data/postgresql.conf'; do
        for f in $pat; do [[ -f $f ]] && pg_body=$(cat "$f") && pg_path=$f && break 2; done
    done
    for pat in '/etc/postgresql/*/main/pg_hba.conf' \
               '/var/lib/pgsql/data/pg_hba.conf' \
               '/var/lib/postgresql/*/data/pg_hba.conf'; do
        for f in $pat; do [[ -f $f ]] && hba_body=$(cat "$f") && hba_path=$f && break 2; done
    done
    shopt -u nullglob

    [[ -z $pg_body && -z $hba_body ]] && { echo "  (not installed)"; return; }

    local v line parts method trust_lines=() md5_lines=() conn_type db user

    if [[ -n $pg_body ]]; then
        BODY="$pg_body"

        get_eq listen_addresses
        [[ $_VAL == '*' ]] && \
            hit HIGH "listen_addresses='*' - DB port exposed on every interface" \
                "listen_addresses = 'localhost'"

        get_eq ssl; v="${_VAL,,}"
        [[ -z $v || $v =~ ^(off|false|0|no)$ ]] && \
            hit HIGH "ssl=${_VAL:-off} - cleartext credentials+data" \
                'ssl = on + ssl_cert_file/ssl_key_file'

        get_eq password_encryption; v="${_VAL,,}"
        [[ $v == md5 ]] && \
            hit MEDIUM 'password_encryption = md5 (offline-crackable)' \
                "password_encryption = 'scram-sha-256'"
    fi

    if [[ -n $hba_body ]]; then
        BODY="$hba_body"

        while IFS= read -r line; do
            line="${line%%#*}"
            [[ -z ${line//[[:space:]]/} ]] && continue
            read -ra parts <<< "$line"
            (( ${#parts[@]} < 4 )) && continue
            method="${parts[-1],,}"
            [[ $method == trust ]] && trust_lines+=("$line")
            [[ $method == md5 ]]   && md5_lines+=("$line")
        done < <(printf '%s\n' "$hba_body")

        # trust auth
        if (( ${#trust_lines[@]} )); then
            local trust_all=0 tl
            for tl in "${trust_lines[@]}"; do [[ $tl == *all* ]] && trust_all=1 && break; done
            local tsev=HIGH; (( trust_all )) && tsev=CRITICAL
            hit "$tsev" "pg_hba.conf: ${#trust_lines[@]} trust entry/entries (no password required)" \
                'replace "trust" with "scram-sha-256"'
        fi

        # md5 auth
        (( ${#md5_lines[@]} )) && \
            hit MEDIUM "pg_hba.conf: ${#md5_lines[@]} md5 entry/entries (deprecated)" \
                'use scram-sha-256 + password_encryption=scram-sha-256'

        # Broad remote access rule - superuser / all users over network
        while IFS= read -r line; do
            line="${line%%#*}"
            [[ -z ${line//[[:space:]]/} ]] && continue
            read -ra parts <<< "$line"
            (( ${#parts[@]} < 4 )) && continue
            conn_type="${parts[0],,}"; db="${parts[1],,}"; user="${parts[2],,}"
            if [[ $conn_type == host && $db == all && \
                  ( $user == all || $user == postgres ) ]]; then
                hit HIGH "Broad remote rule in pg_hba.conf: ${parts[2]} to all DBs" \
                    'restrict to specific users/DBs/CIDRs; postgres superuser local-only'
                break
            fi
        done < <(printf '%s\n' "$hba_body")
    fi
}

# mysql / mariadb database server
check_mysql() {
    load_configs \
        '/etc/mysql/my.cnf' '/etc/mysql/mysql.conf.d/mysqld.cnf' \
        '/etc/mysql/conf.d/mysqld.cnf' \
        '/etc/mysql/mariadb.conf.d/50-server.cnf' \
        '/etc/my.cnf' '/etc/my.cnf.d/*.cnf' \
        || { echo "  (not installed)"; return; }
    local v

    # skip-grant-tables - completely disables all authentication
    body_has '^[[:space:]]*skip[-_]grant[-_]tables' && \
        hit CRITICAL 'skip-grant-tables is set - ALL MySQL/MariaDB authentication bypassed' \
            'Remove skip-grant-tables from [mysqld] and restart the service'

    # local-infile - read arbitrary server-side files via SQL
    get_eq local-infile; v="${_VAL,,}"
    [[ -z $v ]] && { get_eq local_infile; v="${_VAL,,}"; }
    [[ $v == 1 || $v == on || $v == true ]] && \
        hit HIGH 'local-infile=1 - arbitrary server file read via LOAD DATA LOCAL INFILE' \
            'local-infile=0  in [mysqld] section'

    # bind-address exposed to all interfaces
    get_eq bind-address; v="$_VAL"
    [[ -z $v ]] && { get_eq bind_address; v="$_VAL"; }
    if [[ $v == '0.0.0.0' || $v == '::' || $v == '*' ]]; then
        hit HIGH "bind-address=$v - MySQL/MariaDB port exposed on all network interfaces" \
            'bind-address=127.0.0.1'
    elif [[ -z $v ]]; then
        hit MEDIUM 'bind-address not set - MySQL/MariaDB may be listening on all interfaces' \
            'bind-address=127.0.0.1  in [mysqld] section'
    fi

    # secure-file-priv not set - SELECT INTO OUTFILE can write to any path
    get_eq secure-file-priv; v="$_VAL"
    [[ -z $v ]] && { get_eq secure_file_priv; v="$_VAL"; }
    [[ -z $v || $v == '""' || $v == "''" ]] && \
        hit HIGH 'secure-file-priv not set - INTO OUTFILE / LOAD DATA can access any filesystem path' \
            'secure-file-priv=/var/lib/mysql-files  in [mysqld] section'
}

# php interpreter
check_php() {
    load_configs \
        '/etc/php/*/apache2/php.ini' '/etc/php/*/cli/php.ini' \
        '/etc/php/*/fpm/php.ini' '/etc/php.ini' '/usr/local/lib/php.ini' \
        || { echo "  (not installed)"; return; }
    local v

    # allow_url_include - Remote File Inclusion via require/include
    get_eq allow_url_include; v="${_VAL,,}"
    [[ $v == on || $v == 1 || $v == true ]] && \
        hit CRITICAL 'allow_url_include=On - Remote File Inclusion (RFI) via require/include' \
            'allow_url_include=Off'

    # allow_url_fopen - PHP can fetch arbitrary remote URLs (SSRF, remote payload)
    get_eq allow_url_fopen; v="${_VAL,,}"
    [[ -z $v || $v == on || $v == 1 ]] && \
        hit HIGH 'allow_url_fopen=On - PHP can open remote URLs (SSRF / remote payload fetch)' \
            'allow_url_fopen=Off'

    # disable_functions empty - exec/system/shell_exec/passthru all available
    get_eq disable_functions; v="$_VAL"
    [[ -z $v ]] && \
        hit HIGH 'disable_functions is empty - exec,system,shell_exec,passthru etc. all callable' \
            'disable_functions=exec,passthru,shell_exec,system,proc_open,popen,show_source'
}

# cron job backdoor detection
check_cron() {
    load_configs '/etc/crontab' '/etc/cron.d/*' '/var/spool/cron/crontabs/*' \
        || { echo "  (no cron files found)"; return; }
    local f fperms

    # Cron files that are group/world-writable - anyone can plant a job
    shopt -s nullglob
    for f in /etc/crontab /etc/cron.d/*; do
        [[ -f $f ]] || continue
        fperms=$(stat -c '%a' "$f" 2>/dev/null) || continue
        (( 8#$fperms & 022 )) && \
            hit CRITICAL "Cron file is group/world-writable: $f (mode $fperms)" \
                "chmod 644 \"$f\"; chown root:root \"$f\""
    done
    shopt -u nullglob

    # Netcat reverse shell pattern
    body_has '\bnc\b.+-[el][[:space:]]|\bncat\b|\bnetcat\b.+-[el][[:space:]]' && \
        hit CRITICAL 'Possible netcat reverse shell in a cron job' \
            'Audit /etc/crontab and /etc/cron.d/*; remove suspicious entries'

    # Script executed from /tmp - common backdoor staging area
    body_has '[[:space:]]/tmp/' && \
        hit CRITICAL 'Cron job executes a file from /tmp (common backdoor staging path)' \
            'Remove cron entries that reference /tmp'

    # base64 decode piped to shell
    body_has 'base64.*(--decode|-d[[:space:]])' && \
        hit HIGH 'Cron job base64-decodes a payload - likely obfuscated command execution' \
            'Audit cron files for base64-encoded commands'

    # Download from raw IP address (not hostname) - C2 callback
    body_has '(wget|curl)[[:space:]].*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' && \
        hit HIGH 'Cron job fetches content from a raw IP address (possible C2 callback)' \
            'Remove cron entries downloading from IP addresses'

    # Interpreter one-liner with network/exec (python/perl reverse shell)
    body_has '(python[23]?|perl|ruby|php)[[:space:]].*-[ce][[:space:]]' && \
        hit HIGH 'Cron job runs interpreter one-liner - possible scripted reverse shell' \
            'Audit cron entries for python/perl/ruby -e/-c one-liners'
}

# sudoers privilege escalation checks
check_sudoers() {
    load_configs '/etc/sudoers' '/etc/sudoers.d/*' \
        || { echo "  (not accessible)"; return; }
    local f fperms

    # NOPASSWD - passwordless privilege escalation
    body_has 'NOPASSWD' && \
        hit HIGH 'NOPASSWD found in sudoers - privilege escalation without a password' \
            'Remove NOPASSWD or restrict to specific safe, non-shell commands'

    # Full unrestricted NOPASSWD: ALL
    body_has 'NOPASSWD[[:space:]]*:[[:space:]]*ALL[[:space:]]*$' && \
        hit CRITICAL 'sudoers: unrestricted NOPASSWD: ALL - trivial full root access' \
            'Remove the rule or restrict to a specific whitelisted command'

    # !authenticate tag - equivalent bypass
    body_has '!authenticate' && \
        hit HIGH 'sudoers: !authenticate tag found - password check bypassed for affected rule' \
            'Remove !authenticate from sudoers'

    # World-/group-writable files in sudoers.d
    shopt -s nullglob
    for f in /etc/sudoers.d/*; do
        [[ -f $f ]] || continue
        fperms=$(stat -c '%a' "$f" 2>/dev/null) || continue
        (( 8#$fperms & 022 )) && \
            hit CRITICAL "sudoers.d file is group/world-writable: $f (mode $fperms)" \
                "chmod 440 \"$f\"; chown root:root \"$f\""
    done
    shopt -u nullglob
}

# script starts running from here
ALL=(apache2 nginx openssh vsftpd samba bind postgres mysql php cron sudoers)

if (( $# == 0 )); then
    echo "usage: $0 <service|all> [service ...]"
    echo "services: ${ALL[*]}"
    exit 1
fi

SERVICES=()
for a in "$@"; do
    if [[ ${a,,} == all ]]; then SERVICES=("${ALL[@]}"); break; fi
    SERVICES+=("${a,,}")
done

printf '\n== fruit.sh - service config audit - %s ==\n' "$(date '+%F %T')"

for svc in "${SERVICES[@]}"; do
    fn="check_$svc"
    echo
    printf '>> %s\n' "$svc"
    if declare -f "$fn" >/dev/null; then
        "$fn"
    else
        echo "  unknown service (try: ${ALL[*]})"
    fi
done

echo
printf 'summary: %d critical / %d high / %d medium\n' \
    "$COUNT_CRIT" "$COUNT_HIGH" "$COUNT_MED"
