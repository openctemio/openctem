#!/usr/bin/env bash
# create-repositories.sh <nexus-url>: creates the Nexus Repository 3
# repositories of this folder through the REST API.
# Guide: api/docs/deployment/air-gapped.md ("Nexus proxies").
#
#   NEXUS_USER=admin NEXUS_PASSWORD_FILE=/run/secrets/nexus ./create-repositories.sh https://nexus.example.internal
#
# The password is read from a file (never an argument). Review each JSON first:
# blob store, the Docker connector ports (each Docker repository needs its own
# port, or a reverse proxy in front), the cleanup policy. Existing
# repositories are left alone (HTTP 400 is reported).
#
# Also adds the "Docker Bearer Token Realm" (DockerToken) to the active realms,
# keeping the realms you have; Docker clients need it. Tested with Nexus
# Repository 3.70: cosign finds the release signatures through the proxy and
# in the hosted repository (the referrers tag schema; Nexus answers 404 on the
# referrers API and clients fall back). The hosted repository must allow
# redeploy (writePolicy ALLOW): with ALLOW_ONCE a second mirror run, or two
# images sharing a signature tag, fail.
set -euo pipefail
die() { echo "create-repositories: $*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: create-repositories.sh <nexus-url>"
url="${1%/}"
case "$url" in https://*) ;; *) die "use the https:// URL of Nexus" ;; esac
: "${NEXUS_USER:?}" "${NEXUS_PASSWORD_FILE:?}"
[ -r "$NEXUS_PASSWORD_FILE" ] || die "$NEXUS_PASSWORD_FILE is not readable"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
netrc="$(mktemp)"
trap 'rm -f "$netrc"' EXIT
chmod 0600 "$netrc"
host="${url#https://}"
host="${host%%/*}"
printf 'machine %s login %s password %s\n' "${host%%:*}" "$NEXUS_USER" "$(cat "$NEXUS_PASSWORD_FILE")" >"$netrc"

create() { # create <api path> <json>
	local code
	code="$(curl -sS -o /dev/null -w '%{http_code}' --netrc-file "$netrc" -H 'Content-Type: application/json' \
		-X POST --data @"$here/$2" "$url/service/rest/v1/repositories/$1")"
	case "$code" in
	201) echo "created $(basename "$2" .json)" ;;
	400) echo "not created $(basename "$2" .json): HTTP 400 (exists already, or invalid: check it in the UI)" ;;
	*) die "$2: HTTP $code" ;;
	esac
}
realms="$(curl -fsS --netrc-file "$netrc" "$url/service/rest/v1/security/realms/active")"
if ! jq -e 'index("DockerToken")' <<<"$realms" >/dev/null; then
	jq -c '. + ["DockerToken"]' <<<"$realms" |
		curl -fsS --netrc-file "$netrc" -H 'Content-Type: application/json' -X PUT --data @- \
			"$url/service/rest/v1/security/realms/active"
	echo "added the DockerToken realm"
fi
create docker/proxy docker-proxy-ghcr.json
create docker/hosted docker-hosted-openctem.json
create raw/proxy raw-proxy-github-releases.json
create raw/proxy raw-proxy-github-api.json
create helm/proxy helm-proxy-openctem.json
