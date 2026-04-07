#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

if [ -f "${ENV_FILE}" ]; then
	read -r -p ".env already exists. Overwrite it? [y/N]: " overwrite
	case "${overwrite}" in
		[yY][eE][sS]|[yY]) ;;
		*)
			printf '%s\n' "Aborting without changing ${ENV_FILE}"
			exit 0
			;;
	esac
fi

generate_hex() {
	local bytes="$1"
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex "${bytes}"
		return 0
	fi
	if command -v python3 >/dev/null 2>&1; then
		python3 -c 'import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))' "${bytes}"
		return 0
	fi
	if command -v xxd >/dev/null 2>&1; then
		head -c "${bytes}" /dev/urandom | xxd -p -c 9999
		return 0
	fi
	printf '%s\n' "Could not find a secure random generator. Install openssl, python3, or xxd." >&2
	exit 1
}

prompt_nonempty() {
	local prompt="$1"
	local value=""
	while [ -z "${value}" ]; do
		read -r -p "${prompt}" value
	done
	printf '%s' "${value}"
}

prompt_yes_no() {
	local prompt="$1"
	local default="$2"
	local reply=""
	while true; do
		read -r -p "${prompt}" reply
		if [ -z "${reply}" ]; then
			reply="${default}"
		fi
		case "${reply}" in
			[yY][eE][sS]|[yY])
				printf 'yes'
				return 0
				;;
			[nN][oO]|[nN])
				printf 'no'
				return 0
				;;
		esac
		printf '%s\n' "Please answer y or n."
	done
}

sanitize_hostname() {
	local value="$1"
	value="${value#http://}"
	value="${value#https://}"
	value="${value%%/*}"
	printf '%s' "${value}"
}

printf '%s\n' "Discobot authservice production configuration"
printf '%s\n' ""

raw_hostname="$(prompt_nonempty 'Public hostname (example: auth.example.com): ')"
HOSTNAME_VALUE="$(sanitize_hostname "${raw_hostname}")"
if [ -z "${HOSTNAME_VALUE}" ]; then
	printf '%s\n' "Hostname cannot be empty" >&2
	exit 1
fi

ENABLE_GITHUB="$(prompt_yes_no 'Enable GitHub login? [Y/n]: ' 'y')"
ENABLE_GOOGLE="$(prompt_yes_no 'Enable Google login? [y/N]: ' 'n')"

if [ "${ENABLE_GITHUB}" = "no" ] && [ "${ENABLE_GOOGLE}" = "no" ]; then
	printf '%s\n' "At least one upstream provider must be enabled." >&2
	exit 1
fi

GITHUB_CLIENT_ID=""
GITHUB_CLIENT_SECRET=""
GOOGLE_CLIENT_ID=""
GOOGLE_CLIENT_SECRET=""

if [ "${ENABLE_GITHUB}" = "yes" ]; then
	printf '%s\n' ""
	printf '%s\n' "GitHub OAuth settings"
	printf '%s\n' "  Homepage URL: https://${HOSTNAME_VALUE}"
	printf '%s\n' "  Callback URL: https://${HOSTNAME_VALUE}/login/github/callback"
	GITHUB_CLIENT_ID="$(prompt_nonempty 'GitHub client ID: ')"
	GITHUB_CLIENT_SECRET="$(prompt_nonempty 'GitHub client secret: ')"
fi

if [ "${ENABLE_GOOGLE}" = "yes" ]; then
	printf '%s\n' ""
	printf '%s\n' "Google OAuth settings"
	printf '%s\n' "  Authorized redirect URI: https://${HOSTNAME_VALUE}/login/google/callback"
	GOOGLE_CLIENT_ID="$(prompt_nonempty 'Google client ID: ')"
	GOOGLE_CLIENT_SECRET="$(prompt_nonempty 'Google client secret: ')"
fi

ENCRYPTION_KEY="$(generate_hex 32)"
POSTGRES_PASSWORD="$(generate_hex 24)"

cat > "${ENV_FILE}" <<EOF
CADDY_SITE_ADDRESS=${HOSTNAME_VALUE}
PORT=3010
PUBLIC_HOSTNAME=https://${HOSTNAME_VALUE}
ENCRYPTION_KEY=${ENCRYPTION_KEY}
POSTGRES_DB=authservice
POSTGRES_USER=authservice
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DATABASE_DSN=postgres://authservice:${POSTGRES_PASSWORD}@postgres:5432/authservice?sslmode=disable
BROWSER_SESSION_TTL=24h
AUTHORIZATION_CODE_TTL=5m
ACCESS_TOKEN_TTL=15m
GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
EOF

chmod 600 "${ENV_FILE}"

printf '%s\n' ""
printf '%s\n' "Wrote ${ENV_FILE}"
printf '%s\n' ""
printf '%s\n' "Next step:"
printf '%s\n' "  ./deploy.sh"
printf '%s\n' ""
printf '%s\n' "Keep this server backed up, including:"
printf '%s\n' "  - ${ENV_FILE}"
printf '%s\n' "  - the PostgreSQL data volume"
