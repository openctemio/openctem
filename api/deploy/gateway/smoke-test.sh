#!/usr/bin/env bash
# Smoke test for the OpenCTEM gateway: validates the Caddyfile in every TLS
# mode, checks the entrypoint's refusals, then runs the gateway (TLS mode
# `internal`) against two stub upstreams that answer "api" or "web", and checks
# where each request lands. Needs only Docker.
#
#   deploy/gateway/smoke-test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="caddy:${CADDY_VERSION:-2.11.4-alpine}"
run="gwsmoke-$$"
net="$run-net"
fail=0

cleanup() {
	docker rm -f "$run-gw" "$run-api" "$run-web" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	rm -rf "${certs:-}"
}
trap cleanup EXIT

ok() { printf '  ok    %s\n' "$*"; }
bad() {
	printf '  FAIL  %s\n' "$*"
	fail=1
}

echo "== Caddyfile validates in every TLS mode"
certs="$(mktemp -d)"
chmod 0755 "$certs"
docker run --rm -v "$certs:/c" --entrypoint sh "$image" -c \
	'apk add -q --no-cache openssl >/dev/null 2>&1 || true; command -v openssl >/dev/null && openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=t -keyout /c/tls.key -out /c/tls.crt 2>/dev/null; chmod 0644 /c/*' ||
	true
for mode in internal acme files http; do
	if [ "$mode" = files ] && [ ! -s "$certs/tls.crt" ]; then
		echo "  skip  files (no openssl available to make a test certificate)"
		continue
	fi
	if docker run --rm -e OPENCTEM_TLS_MODE="$mode" -e OPENCTEM_HOSTNAME=203.0.113.10 \
		-e ACME_EMAIL=ops@example.com -v "$here:/etc/caddy:ro" -v "$certs:/certs:ro" "$image" \
		caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
		ok "$mode"
	else
		bad "$mode does not validate"
	fi
done

echo "== Entrypoint refuses unsafe or incomplete settings"
refuses() {
	local what="$1"
	shift
	if docker run --rm "$@" -v "$here:/etc/caddy:ro" --entrypoint sh "$image" /etc/caddy/entrypoint.sh true >/dev/null 2>&1; then
		bad "$what was accepted"
	else
		ok "$what"
	fi
}
refuses "no TLS mode" -e OPENCTEM_HOSTNAME=x
refuses "unknown TLS mode" -e OPENCTEM_TLS_MODE=tls -e OPENCTEM_HOSTNAME=x
refuses "internal without hostname" -e OPENCTEM_TLS_MODE=internal
refuses "acme without ACME_EMAIL" -e OPENCTEM_TLS_MODE=acme -e OPENCTEM_HOSTNAME=x
refuses "files without a certificate" -e OPENCTEM_TLS_MODE=files -e OPENCTEM_HOSTNAME=x
refuses "plain http without opt-in" -e OPENCTEM_TLS_MODE=http
if docker run --rm -e OPENCTEM_TLS_MODE=http -e OPENCTEM_ALLOW_PLAIN_HTTP=true -v "$here:/etc/caddy:ro" \
	--entrypoint sh "$image" /etc/caddy/entrypoint.sh true >/dev/null 2>&1; then
	ok "plain http with OPENCTEM_ALLOW_PLAIN_HTTP=true is accepted"
else
	bad "plain http with opt-in was refused"
fi

echo "== Routing (TLS mode internal, stub upstreams)"
docker network create "$net" >/dev/null
# Each stub echoes which upstream it is and the client-address headers it got.
stub() {
	docker run -d --name "$run-$1" --network "$net" --network-alias "$1" "$image" \
		caddy respond --listen :8000 --body "$1 xrealip={http.request.header.X-Real-IP}" >/dev/null
}
stub api
stub web
docker run -d --name "$run-gw" --network "$net" \
	-e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=gateway.test \
	-e OPENCTEM_API_UPSTREAM=api:8000 -e OPENCTEM_WEB_UPSTREAM=web:8000 \
	-v "$here:/etc/caddy:ro" --entrypoint sh "$image" /etc/caddy/entrypoint.sh >/dev/null

probe() { # probe <expected api|web|404> <method> <path> [curl args...]
	local want="$1" method="$2" path="$3"
	shift 3
	local got
	got="$(docker run --rm --network "$net" curlimages/curl:latest -sk -m 5 -X "$method" \
		--resolve "gateway.test:443:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gw")" \
		-w ' %{http_code}' "$@" "https://gateway.test$path" 2>/dev/null || true)"
	local label
	case "$got" in
	api*" 200") label=api ;;
	web*" 200") label=web ;;
	*" 404") label=404 ;;
	*) label="?($got)" ;;
	esac
	if [ "$label" = "$want" ]; then ok "$method $path $* -> $want"; else bad "$method $path $* -> $label, want $want"; fi
}

for _ in $(seq 1 30); do
	docker run --rm --network "$net" curlimages/curl:latest -sk -m 2 -o /dev/null \
		--resolve "gateway.test:443:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gw")" \
		https://gateway.test/health >/dev/null 2>&1 && break
	sleep 1
done

probe api GET /api/v1/agent/heartbeat
probe api PUT /api/v2/sensor/results/r1/segments/0
probe api POST /api/v1/platform/poll
probe api GET /scim/v2/Users
probe api POST /api/v1/mcp
probe api POST /api/v1/webhooks/incoming/github
probe api POST /api/v1/auth/saml/acme/acs
probe api POST /api/v1/auth/backchannel-logout
probe api GET /api/v1/ws
probe api GET /health
probe api GET /api/v1/findings -H "Authorization: Bearer oct_example"
probe api GET /api/v1/findings -H "X-API-Key: oct_example"
probe api GET /api/v1/findings -H "Authorization: Bearer eyJ.token"
probe web GET /api/v1/findings -H "Authorization: Bearer eyJ.token" -H "Cookie: auth_token=abc"
probe web GET /api/v1/findings -H "Cookie: auth_token=abc"
probe web GET /api/v1/agents
probe web GET /api/auth/refresh
probe web GET /
probe web GET /login
probe 404 GET /metrics
probe 404 GET /ready
probe 404 GET /debug/pprof/

echo "== The access log never records an invitation token"
# Links emailed before RFC-041 and the deprecated API aliases carry the token
# in the path; the gateway's access log replaces it.
invtok="Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8"
probe web GET "/invitations/$invtok"
probe web GET "/api/v1/invitations/$invtok/preview"
probe web POST /api/v1/invitations/lookup
sleep 1
gwlog="$(docker logs "$run-gw" 2>&1)"
if grep -q "$invtok" <<<"$gwlog"; then
	bad "an invitation token reached the access log"
else
	ok "no invitation token in the access log"
fi
if grep -q "/invitations/REDACTED" <<<"$gwlog" && grep -q "/api/v1/invitations/REDACTED/preview" <<<"$gwlog"; then
	ok "token paths logged as REDACTED"
else
	bad "token paths not logged as REDACTED"
fi
if grep -q "/api/v1/invitations/lookup" <<<"$gwlog"; then
	ok "body routes logged as is"
else
	bad "/api/v1/invitations/lookup missing from the access log"
fi

echo "== Client address is set by the gateway, not the client"
body="$(docker run --rm --network "$net" curlimages/curl:latest -sk -m 5 \
	--resolve "gateway.test:443:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gw")" \
	-H 'X-Real-IP: 6.6.6.6' -H 'X-Forwarded-For: 6.6.6.6' https://gateway.test/health)"
case "$body" in
*"xrealip=6.6.6.6"*) bad "client-supplied X-Real-IP reached the API: $body" ;;
*"xrealip="[0-9]*) ok "X-Real-IP overwritten ($body)" ;;
*) bad "unexpected: $body" ;;
esac

echo "== Response headers"
hdrs="$(docker run --rm --network "$net" curlimages/curl:latest -skI -m 5 \
	--resolve "gateway.test:443:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gw")" \
	https://gateway.test/login | tr -d '\r')"
header_present() { grep -qi "^$1" <<<"$hdrs"; }
if header_present 'strict-transport-security: max-age=31536000'; then ok "HSTS"; else bad "HSTS missing"; fi
if header_present 'x-content-type-options: nosniff'; then ok "nosniff"; else bad "nosniff missing"; fi
if header_present 'server:'; then bad "Server header present"; else ok "no Server header"; fi
if header_present 'via:'; then bad "Via header present"; else ok "no Via header"; fi

echo "== Plain HTTP only redirects to HTTPS"
gwip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gw")"
for path in /login /api/v1/agent/heartbeat; do
	got="$(docker run --rm --network "$net" curlimages/curl:latest -s -m 5 -o /dev/null \
		--resolve "gateway.test:80:$gwip" -w '%{http_code} %{redirect_url}' "http://gateway.test$path" 2>/dev/null || true)"
	if [ "$got" = "308 https://gateway.test$path" ]; then ok "http $path -> $got"; else bad "http $path -> '$got', want 308 https://gateway.test$path"; fi
done

echo "== Internal CA created"
ca="$(docker exec "$run-gw" sh -c 'ls -l /data/caddy/pki/authorities/local/root.crt' 2>/dev/null || true)"
if [ -n "$ca" ]; then ok "root CA created"; else bad "root CA not created"; fi

if [ "$fail" -ne 0 ]; then
	echo "gateway smoke test FAILED"
	docker logs "$run-gw" 2>&1 | tail -20
	exit 1
fi
echo "gateway smoke test passed"
