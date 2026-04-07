#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${SCRIPT_DIR}/docker-compose.rolling.yml}"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-120}"
GRACE_SECONDS="${GRACE_SECONDS:-5}"
SERVICES=(authservice-a authservice-b)

if [ ! -f "${ENV_FILE}" ]; then
	printf '%s\n' "Missing env file: ${ENV_FILE}" >&2
	exit 1
fi

set -a
# shellcheck disable=SC1090
. "${ENV_FILE}"
set +a

if docker compose version >/dev/null 2>&1; then
	COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
	COMPOSE=(docker-compose)
else
	printf '%s\n' "docker compose is not available" >&2
	exit 1
fi

wait_for_service() {
	local service="$1"
	local container_id=""
	for _ in $(seq 1 10); do
		container_id="$("${COMPOSE[@]}" -f "${COMPOSE_FILE}" ps -q "${service}")"
		if [ -n "${container_id}" ]; then
			break
		fi
		sleep 1
	done

	if [ -z "${container_id}" ]; then
		printf '%s\n' "Could not determine container ID for ${service}" >&2
		exit 1
	fi

	printf '%s\n' "Waiting for ${service} to become healthy..."
	local start_time
	start_time="$(date +%s)"
	while true; do
		local status
		status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}")"
		if [ "${status}" = "healthy" ]; then
			return 0
		fi
		if [ "${status}" = "exited" ] || [ "${status}" = "dead" ]; then
			printf '%s\n' "${service} failed with status ${status}" >&2
			exit 1
		fi
		local now
		now="$(date +%s)"
		if [ $((now - start_time)) -ge "${HEALTH_TIMEOUT_SECONDS}" ]; then
			printf '%s\n' "Timed out waiting for ${service} health; last status: ${status}" >&2
			exit 1
		fi
		sleep 2
	done
}

printf '%s\n' "Using compose file: ${COMPOSE_FILE}"
printf '%s\n' "Using env file: ${ENV_FILE}"

printf '%s\n' "Ensuring PostgreSQL and Caddy are running..."
"${COMPOSE[@]}" -f "${COMPOSE_FILE}" up -d postgres caddy

printf '%s\n' "Building updated authservice image..."
"${COMPOSE[@]}" -f "${COMPOSE_FILE}" build --pull "${SERVICES[@]}"

for service in "${SERVICES[@]}"; do
	printf '%s\n' "Rolling ${service}..."
	"${COMPOSE[@]}" -f "${COMPOSE_FILE}" up -d --no-deps --force-recreate "${service}"
	wait_for_service "${service}"
	printf '%s\n' "Waiting ${GRACE_SECONDS}s before continuing..."
	sleep "${GRACE_SECONDS}"
done

printf '%s\n' "Rolling deployment complete."
