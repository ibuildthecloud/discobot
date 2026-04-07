#!/bin/bash
#---
# name: Map authservice localhost host
# type: session
# run_as: root
# description: Add the current session authservice *.localhost hostname to /etc/hosts for local loopback routing.
#---

set -euo pipefail

if [ -z "${DISCOBOT_SESSION_ID:-}" ]; then
	printf '%s\n' "DISCOBOT_SESSION_ID is not set; skipping authservice hosts entry"
	exit 0
fi

SESSION_ID_LOWER="$(printf '%s' "$DISCOBOT_SESSION_ID" | tr '[:upper:]' '[:lower:]')"
HOSTNAME_ENTRY="${SESSION_ID_LOWER}-svc-authservice.localhost"
HOSTS_LINE="127.0.0.1 ${HOSTNAME_ENTRY}"
TMP_FILE="$(mktemp)"

if grep -Eq "^[[:space:]]*127\.0\.0\.1[[:space:]]+${HOSTNAME_ENTRY}([[:space:]]|$)" /etc/hosts; then
	printf '%s\n' "Authservice hosts entry already present: ${HOSTNAME_ENTRY}"
	rm -f "$TMP_FILE"
	exit 0
fi

grep -Ev "(^|[[:space:]])${HOSTNAME_ENTRY}([[:space:]]|$)" /etc/hosts > "$TMP_FILE" || true
printf '%s\n' "$HOSTS_LINE" >> "$TMP_FILE"
cat "$TMP_FILE" > /etc/hosts
rm -f "$TMP_FILE"

printf '%s\n' "Added authservice hosts entry: ${HOSTS_LINE}"
