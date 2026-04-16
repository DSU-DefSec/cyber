#!/bin/bash

# Usage: ./change.sh <secret>
# Output: passwords.txt (username:newpassword format for chpasswd)

SECRET="$1"

if [ -z "$SECRET" ]; then
    echo "Usage: $0 <secret>"
    exit 1
fi

OUTPUT="passwords.txt"
> "$OUTPUT"

while IFS=: read -r username _ _ _ _ _ shell; do
    [ "$username" = "root" ] && continue

	case "$username" in
		*black*|*orange*|postgres) continue ;;
	esac

    case "$shell" in
        */nologin|*/false|*/sync|"") continue ;;
    esac

    newpass=$(echo -n "${username}${SECRET}" | md5sum | cut -d' ' -f1)
    echo "${username}:${newpass}" >> "$OUTPUT"
done < /etc/passwd

chmod 600 "$OUTPUT"
echo "Generated passwords for $(wc -l < "$OUTPUT") accounts -> $OUTPUT"
echo "Review the file, then run: chpasswd < $OUTPUT, Then, please delete the password file and this script."
