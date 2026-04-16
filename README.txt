a mix of custom and open source software/scripts for automatically securing ncae cyber games machines

Repo Directories:
/ - custom scripts
/open2 - open source components (GPLv2), for which the below notice applies.
/open3 - open source components (GPLv3), for which the below notice applies.
/open4 - open source components (BSD 2-Clause License) for which the below notice applies.

Included custom scripts:
• tables.sh - nft firewall autodeployment and remote access hardening
• fruit.sh - checks for vulnerable misconfigurations in common service config files
• detective.sh - checks for backdoors and network exposure
• buildfw.sh - builds a statically linked nft binary from source

NOTICE - This repository redistributes the following open-source components in the /open2, /open3, and /open4 directories:

/open2 (GPLv2 Licensed)
• BusyBox (unmodified static binary) - obtained from https://busybox.net/
• nft (statically built binary) with unmodified source for the following, obtained from https://www.netfilter.org/pub/:
  - libmnl 1.0.5
  - libnftnl 1.2.6
  - nftables 1.0.9
• linpeas.sh (unmodified script) - obtained from https://github.com/peass-ng/PEASS-ng/

/open3 (GPLv3 Licensed)
• lynis project (unmodified source code) - obtained from https://github.com/CISOfy/lynis
• pspy64 (unmodified binary) - obtained from https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1

/open4 (BSD 2-Clause License)
• restic (unmodified static binary) - obtained from https://github.com/restic/restic
• rest-server (unmodified static binary) - obtained from https://github.com/restic/rest-server

For any GPL-licensed binary included in this repository for which complete source code is not included, source code is available upon written request.

A copy of the GNU General Public License v2.0 is included in the /open2 directory, and a copy of the GNU General Public License v3.0 is included in the /open3 directory. A copy of the BSD 2-Clause License is included in the /open4 directory. These licenses apply solely to the contents of their respective directories.
