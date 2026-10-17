#!/usr/bin/env bash
# Smoke test for the OpenCTEM gateway: validates the Caddyfile in every TLS
# mode, checks the entrypoint's refusals, then runs the gateway (TLS mode
# `internal`) against stub upstreams that answer "api", "web" or "console", and checks
# where each request lands. Then builds the gateway image with the layer4
# module (deploy/gateway/Dockerfile; or uses GATEWAY_L4_IMAGE) and checks the
# sensor ALPN and SNI routing next to the normal routing. Needs only Docker
# (and network access for the image build and openssl from apk).
#
#   deploy/gateway/smoke-test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="caddy:${CADDY_VERSION:-2.11.4-alpine}"
run="${SMOKE_PREFIX:-gwsmoke}-$$"
net="$run-net"
fail=0

cleanup() {
	docker rm -f "$run-gw" "$run-gwh" "$run-gwc" "$run-gwu" "$run-gwl4" "$run-gwa" "$run-gwb" "$run-api" "$run-web" "$run-mtls" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	if [ -z "${GATEWAY_L4_IMAGE:-}" ]; then docker rmi "$run-l4" >/dev/null 2>&1 || true; fi
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

echo "== Caddyfile validates with the console's own site, in every TLS mode"
for mode in internal acme files http; do
	if [ "$mode" = files ] && [ ! -s "$certs/tls.crt" ]; then continue; fi
	addr="https://203.0.113.10:8443"
	[ "$mode" != http ] || addr="http://:8443"
	for a in "$addr" "https://admin.example.test"; do
		[ "$mode" != http ] || [ "$a" = "$addr" ] || a="http://admin.example.test"
		if docker run --rm -e OPENCTEM_TLS_MODE="$mode" -e OPENCTEM_HOSTNAME=203.0.113.10 -e ACME_EMAIL=ops@example.com \
			-e OPENCTEM_ADMIN_SITE_FILE=on -e OPENCTEM_ADMIN_ADDRESS="$a" \
			-v "$here:/etc/caddy:ro" -v "$certs:/certs:ro" "$image" \
			caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
			ok "$mode, console at $a"
		else
			bad "$mode with the console at $a does not validate"
		fi
	done
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
refuses "unknown sensor gateway mode" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_SENSOR_GATEWAY=tcp
refuses "sensor passthrough without its host name" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_SENSOR_GATEWAY=passthrough
refuses "sensor passthrough with a port in the host name" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_SENSOR_GATEWAY=passthrough -e SENSOR_PUBLIC_HOSTNAME=s.x:443
refuses "sensor passthrough on the platform host name" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_SENSOR_GATEWAY=passthrough -e SENSOR_PUBLIC_HOSTNAME=x
refuses "sensor passthrough without the layer4 module" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_SENSOR_GATEWAY=passthrough -e SENSOR_PUBLIC_HOSTNAME=s.x
refuses "unknown console site mode" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_ADMIN_SITE=public
refuses "console host mode without its host name" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_ADMIN_SITE=host
refuses "console host name equal to the main one" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_ADMIN_SITE=host -e OPENCTEM_ADMIN_HOST=x
refuses "console host name with a port" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_ADMIN_SITE=host -e OPENCTEM_ADMIN_HOST=admin.x:8443
refuses "console on the main port" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_ADMIN_SITE=port -e OPENCTEM_ADMIN_PORT=443
refuses "console on the main site's published port" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_ADMIN_SITE=port -e GATEWAY_HTTPS_PORT=8443
refuses "console port out of range" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_ADMIN_SITE=port -e OPENCTEM_ADMIN_PORT=70000
refuses "console allow-list that is not CIDRs" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_ADMIN_SITE=port -e "OPENCTEM_ADMIN_ALLOWED_CIDRS=10.0.0.0/8 office"
if docker run --rm -e OPENCTEM_TLS_MODE=http -e OPENCTEM_ALLOW_PLAIN_HTTP=true -v "$here:/etc/caddy:ro" \
	--entrypoint sh "$image" /etc/caddy/entrypoint.sh true >/dev/null 2>&1; then
	ok "plain http with OPENCTEM_ALLOW_PLAIN_HTTP=true is accepted"
else
	bad "plain http with opt-in was refused"
fi

echo "== Routing (TLS mode internal, stub upstreams)"
docker network create "$net" >/dev/null
# Each stub echoes which upstream it is and the client-address headers it got.
# The padding makes the body long enough for the gateway to compress it.
pad="$(printf 'p%.0s' $(seq 1 1024))"
stub() {
	docker run -d --name "$run-$1" --network "$net" --network-alias "$1" "$image" \
		caddy respond --listen :8000 --header "Content-Type: application/json" \
		--body "$1 xrealip={http.request.header.X-Real-IP}| xff={http.request.header.X-Forwarded-For}| cfip={http.request.header.Cf-Connecting-Ip}| $pad" >/dev/null
}
stub api
stub web
stub console
docker run -d --name "$run-gw" --network "$net" \
	-e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=gateway.test \
	-e OPENCTEM_API_UPSTREAM=api:8000 -e OPENCTEM_WEB_UPSTREAM=web:8000 \
	-v "$here:/etc/caddy:ro" --entrypoint sh "$image" /etc/caddy/entrypoint.sh >/dev/null

probe() { # probe <expected api|web|404> <method> <path> [curl args...]
	local want="$1" method="$2" path="$3"
	shift 3
	local got
	got="$(docker run --rm --network "$net" curlimages/curl:latest -sk -m 5 -X "$method" \
		--resolve "gateway.test:443:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${GW:-$run-gw}")" \
		-w ' %{http_code}' "$@" "https://gateway.test$path" 2>/dev/null || true)"
	local label
	case "$got" in
	api*" 200") label=api ;;
	web*" 200") label=web ;;
	*" 404") label=404 ;;
	*) label="?($got)" ;;
	esac
	if [ "$label" = "$want" ]; then ok "${GW:+[l4] }$method $path $* -> $want"; else bad "${GW:+[l4] }$method $path $* -> $label, want $want"; fi
}

for _ in $(seq 1 30); do
	docker run --rm --network "$net" curlimages/curl:latest -sk -m 2 -o /dev/null \
		--resolve "gateway.test:443:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gw")" \
		https://gateway.test/health >/dev/null 2>&1 && break
	sleep 1
done

# Each plane the gateway sends straight to the API (planes.caddy, generated
# from the API's plane table).
probe api GET /api/v1/agent/heartbeat
probe api PUT /api/v2/sensor/results/r1/segments/0
probe api POST /api/v3/sensor/openctem.sensor.v3.SensorService/Heartbeat
probe api POST /api/v1/validation/evidence
probe api GET /scim/v2/Users
probe api POST /api/v1/mcp
probe api POST /api/v1/webhooks/incoming/github
probe api POST /hooks/github
probe api POST /api/v1/auth/saml/acme/acs
probe api GET /api/v1/auth/saml/acme/metadata
probe api POST /api/v1/auth/backchannel-logout
probe api GET /api/v1/ws
probe api GET /health
probe api GET /openapi.yaml
probe api GET /docs
# Browser planes reach the API only by credential, never by path.
probe web GET /api/v1/validation/coverage -H "Cookie: auth_token=abc"
probe web POST /api/v1/auth/login
probe web GET /api/v1/me/permissions -H "Cookie: auth_token=abc"
probe web GET /api/v1/admin/tenants
probe web GET /api/v1/admin/tenants -H "Cookie: admin_session=abc"
# The stale protocol-v0 rule is gone (the API serves none of these).
probe web POST /api/v1/platform/poll
probe web GET /api/v1/platform/stats -H "Cookie: auth_token=abc"
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
probe 404 GET /metrics -H "Authorization: Bearer oct_example"
probe 404 GET /ready
probe 404 GET /ready/detail
probe 404 GET /debug/pprof/
probe 404 GET /debug

echo "== Client address is set by the gateway, not the client"
body="$(docker run --rm --network "$net" curlimages/curl:latest -sk -m 5 \
	--resolve "gateway.test:443:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gw")" \
	-H 'X-Real-IP: 6.6.6.6' -H 'X-Forwarded-For: 6.6.6.6' https://gateway.test/health)"
case "$body" in
*"xrealip=6.6.6.6"*) bad "client-supplied X-Real-IP reached the API: $body" ;;
*"xrealip="[0-9]*) ok "X-Real-IP overwritten ($body)" ;;
*) bad "unexpected: $body" ;;
esac

echo "== The console on its own site (OPENCTEM_ADMIN_SITE=port), private networks only"
subnet="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$net")"
docker run -d --name "$run-gwa" --network "$net" \
	-e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=gateway.test \
	-e OPENCTEM_API_UPSTREAM=api:8000 -e OPENCTEM_WEB_UPSTREAM=web:8000 -e OPENCTEM_CONSOLE_UPSTREAM=console:8000 \
	-e OPENCTEM_ADMIN_SITE=port -e OPENCTEM_ADMIN_ALLOWED_CIDRS="$subnet" \
	-v "$here:/etc/caddy:ro" --entrypoint sh "$image" /etc/caddy/entrypoint.sh >/dev/null
# Same network, but an allow-list the test client is not in.
docker run -d --name "$run-gwb" --network "$net" \
	-e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=gateway.test \
	-e OPENCTEM_API_UPSTREAM=api:8000 -e OPENCTEM_WEB_UPSTREAM=web:8000 -e OPENCTEM_CONSOLE_UPSTREAM=console:8000 \
	-e OPENCTEM_ADMIN_SITE=port -e OPENCTEM_ADMIN_ALLOWED_CIDRS="192.0.2.0/24" \
	-v "$here:/etc/caddy:ro" --entrypoint sh "$image" /etc/caddy/entrypoint.sh >/dev/null
console() { # console <gateway> <port> <method> <path> [curl args...]: prints "<body> <code>"
	local gw="$1" port="$2" method="$3" path="$4"
	shift 4
	docker run --rm --network "$net" curlimages/curl:latest -sk -m 5 -X "$method" \
		--resolve "gateway.test:$port:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$gw")" \
		-w ' %{http_code}' "$@" "https://gateway.test:$port$path" 2>/dev/null || true
}
for _ in $(seq 1 30); do
	case "$(console "$run-gwa" 8443 GET /)" in *" 200") break ;; esac
	sleep 1
done
expect() { # expect <label> <glob> <got>
	# shellcheck disable=SC2254 # the pattern is the point
	case "$3" in $2) ok "$1" ;; *) bad "$1: got ${3%% p*}" ;; esac
}
expect "console site serves the console service at its root" "console *200" "$(console "$run-gwa" 8443 GET /)"
expect "console site serves the console's pages" "console *200" "$(console "$run-gwa" 8443 GET /organizations)"
expect "console site proxies the console API through the console service" "console *200" "$(console "$run-gwa" 8443 POST /api/v1/admin/auth/login)"
expect "console site passes the client address on" "console xrealip=*200" "$(console "$run-gwa" 8443 GET /)"
expect "console site never serves /metrics" "* 404" "$(console "$run-gwa" 8443 GET /metrics)"
expect "main site never reaches the console service" "web *200" "$(console "$run-gwa" 443 GET /organizations)"
expect "main site has no console API" "* 404" "$(console "$run-gwa" 443 GET /api/v1/admin/tenants -H 'Cookie: admin_session=abc')"
expect "main site has no console API, even for a token client" "* 404" "$(console "$run-gwa" 443 GET /api/v1/admin/tenants -H 'Authorization: Bearer eyJ.token')"
for p in "/api/v1//admin/tenants" "/api/v1/./admin/tenants" "/api/v1/x/../admin/tenants" "/api/v1%2Fadmin/tenants"; do
	expect "main site has no console API as $p either" "* 404" "$(console "$run-gwa" 443 GET "$p" --path-as-is)"
done
expect "main site still serves the tenant UI" "web *200" "$(console "$run-gwa" 443 GET /login)"
expect "console site refuses a network outside the allow-list" "* 403" "$(console "$run-gwb" 8443 GET /)"
expect "the allow-list does not apply to the main site" "web *200" "$(console "$run-gwb" 443 GET /login)"

echo "== Behind a trusted front proxy, the client is the right-most untrusted X-Forwarded-For entry"
# TLS mode http, with the whole test network as the "front proxy". A front
# proxy that appends keeps whatever the client typed on the left; only the
# entry the proxy appended (right-most) may become X-Real-IP.
docker run -d --name "$run-gwh" --network "$net" \
	-e OPENCTEM_TLS_MODE=http -e OPENCTEM_ALLOW_PLAIN_HTTP=true -e OPENCTEM_TRUSTED_PROXIES="$subnet" \
	-e OPENCTEM_API_UPSTREAM=api:8000 -e OPENCTEM_WEB_UPSTREAM=web:8000 \
	-v "$here:/etc/caddy:ro" --entrypoint sh "$image" /etc/caddy/entrypoint.sh >/dev/null
gwhip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gwh")"
body=""
for _ in $(seq 1 30); do
	body="$(docker run --rm --network "$net" curlimages/curl:latest -s -m 2 \
		-H 'X-Real-IP: 6.6.6.6' -H 'X-Forwarded-For: 6.6.6.6, 198.51.100.9' "http://$gwhip/health" 2>/dev/null || true)"
	[ -n "$body" ] && break
	sleep 1
done
case "$body" in
*"xrealip=198.51.100.9|"*) ok "X-Real-IP is the proxy-appended client" ;;
*) bad "X-Real-IP should be 198.51.100.9 (right-most untrusted), got: ${body%% p*}" ;;
esac
# The API reads X-Forwarded-For first and knows only the gateway, not the
# proxies in front of it: the gateway must hand it the resolved client alone,
# not the front proxy's list with that proxy's address appended (which made
# every request look like it came from the proxy).
case "$body" in
*"xff=198.51.100.9|"*) ok "X-Forwarded-For to the API is the resolved client alone" ;;
*) bad "X-Forwarded-For to the API should be 198.51.100.9 alone, got: ${body%% p*}" ;;
esac

echo "== OPENCTEM_CLIENT_IP_HEADERS=Cf-Connecting-Ip (Cloudflare Tunnel)"
refuses "an unknown client address header" -e OPENCTEM_TLS_MODE=http -e OPENCTEM_ALLOW_PLAIN_HTTP=true -e OPENCTEM_CLIENT_IP_HEADERS="X-Client-Ip"
# gwc trusts the test network (the tunnel connector); gwu trusts nobody, so
# every peer is untrusted there.
cfgw() { # cfgw <name> <trusted proxies>
	docker run -d --name "$run-$1" --network "$net" \
		-e OPENCTEM_TLS_MODE=http -e OPENCTEM_ALLOW_PLAIN_HTTP=true -e OPENCTEM_TRUSTED_PROXIES="$2" \
		-e OPENCTEM_CLIENT_IP_HEADERS=Cf-Connecting-Ip \
		-e OPENCTEM_API_UPSTREAM=api:8000 -e OPENCTEM_WEB_UPSTREAM=web:8000 \
		-v "$here:/etc/caddy:ro" --entrypoint sh "$image" /etc/caddy/entrypoint.sh >/dev/null
	docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-$1"
}
viacf() { # viacf <gateway ip> <headers...>: what the API stub got
	local ip="$1" out=""
	shift
	for _ in $(seq 1 30); do
		out="$(docker run --rm --network "$net" curlimages/curl:latest -s -m 2 "$@" "http://$ip/health" 2>/dev/null || true)"
		[ -n "$out" ] && break
		sleep 1
	done
	printf '%s' "${out%% p*}"
}
gwcip="$(cfgw gwc "$subnet")"
gwuip="$(cfgw gwu 127.0.0.1/32)"
# What the Cloudflare edge sends through the tunnel when the visitor typed its
# own X-Forwarded-For: the edge appends the visitor, and sets Cf-Connecting-Ip.
body="$(viacf "$gwcip" -H 'Cf-Connecting-Ip: 203.0.113.7' -H 'X-Forwarded-For: 6.6.6.6, 203.0.113.7' -H 'Cf-Ray: 0-TEST')"
case "$body" in
*"xrealip=203.0.113.7| xff=203.0.113.7| cfip=|"*) ok "tunnel: the visitor address reaches the API, Cf-Connecting-Ip not passed on" ;;
*) bad "tunnel: want xrealip=xff=203.0.113.7 and no cfip, got: $body" ;;
esac
body="$(viacf "$gwcip" -H 'X-Forwarded-For: 6.6.6.6')"
case "$body" in
*"xrealip=6.6.6.6"* | *"xff=6.6.6.6"*) bad "tunnel without Cf-Connecting-Ip: X-Forwarded-For was believed: $body" ;;
*"xrealip="[0-9]*) ok "tunnel without Cf-Connecting-Ip: the peer address, not X-Forwarded-For" ;;
*) bad "unexpected: $body" ;;
esac
body="$(viacf "$gwuip" -H 'Cf-Connecting-Ip: 6.6.6.6' -H 'True-Client-Ip: 6.6.6.6' -H 'X-Forwarded-For: 6.6.6.6' -H 'X-Real-IP: 6.6.6.6')"
case "$body" in
*6.6.6.6*) bad "untrusted peer: a spoofed client address reached the API: $body" ;;
*"xrealip="[0-9]*"| cfip=|"*) ok "untrusted peer: spoofed Cf-Connecting-Ip/X-Forwarded-For ignored and not passed on" ;;
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

echo "== Compression"
encoding() { # encoding <method> <path>: the Content-Encoding the gateway answers with
	docker run --rm --network "$net" curlimages/curl:latest -sk -m 5 -o /dev/null -X "$1" \
		-H 'Accept-Encoding: zstd, gzip' -H 'Authorization: Bearer x' -w '%header{content-encoding}' \
		--resolve "gateway.test:443:$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gw")" \
		"https://gateway.test$2" 2>/dev/null || true
}
got="$(encoding GET /api/v1/findings)"
if [ "$got" = zstd ]; then ok "GET JSON compressed ($got)"; else bad "GET JSON not compressed ('$got')"; fi
for req in "POST /api/v1/findings" "GET /api/v1/auth/me" "GET /api/v2/sensor/hello" "GET /oauth/authorize"; do
	got="$(encoding ${req% *} ${req#* })"
	if [ -z "$got" ]; then ok "$req not compressed"; else bad "$req compressed ($got)"; fi
done

echo "== The access log never records an invitation token"
# Links emailed before RFC-041 and the deprecated API aliases carry the token
# in the path; the gateway's access log replaces it.
invtok="Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8"
probe web GET "/invitations/$invtok"
probe web GET "/api/v1/invitations/$invtok/preview"
probe web POST /api/v1/invitations/lookup
probe api GET "/api/v1/ws?ticket=$invtok&x=1"
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
if grep -q "/api/v1/ws?ticket=REDACTED&x=1" <<<"$gwlog"; then
	ok "WebSocket ticket logged as REDACTED"
else
	bad "WebSocket ticket not logged as REDACTED"
fi
if grep -q "/api/v1/invitations/lookup" <<<"$gwlog"; then
	ok "body routes logged as is"
else
	bad "/api/v1/invitations/lookup missing from the access log"
fi

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

echo "== Gateway image with the layer4 module: sensor ALPN and SNI routing (RFC-059 §5)"
l4image="${GATEWAY_L4_IMAGE:-}"
if [ -z "$l4image" ]; then
	l4image="$run-l4"
	docker build -q -t "$l4image" "$here" >/dev/null
fi
for sg in alpn passthrough; do
	if docker run --rm -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=203.0.113.10 \
		-e OPENCTEM_SENSOR_GATEWAY="$sg" -e SENSOR_PUBLIC_HOSTNAME=sensors.example.test \
		-v "$here:/etc/caddy:ro" "$l4image" caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
		ok "OPENCTEM_SENSOR_GATEWAY=$sg validates"
	else
		bad "OPENCTEM_SENSOR_GATEWAY=$sg does not validate"
	fi
done
refuses "sensor alpn without the layer4 module" -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_SENSOR_GATEWAY=alpn
if docker run --rm -e OPENCTEM_TLS_MODE=http -e OPENCTEM_ALLOW_PLAIN_HTTP=true -e OPENCTEM_SENSOR_GATEWAY=alpn \
	-v "$here:/etc/caddy:ro" --entrypoint sh "$l4image" /etc/caddy/entrypoint.sh true >/dev/null 2>&1; then
	bad "sensor alpn in plain HTTP mode was accepted"
else
	ok "sensor alpn in plain HTTP mode"
fi
if docker run --rm -e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=x -e OPENCTEM_SENSOR_GATEWAY=alpn \
	-v "$here:/etc/caddy:ro" --entrypoint sh "$l4image" /etc/caddy/entrypoint.sh true >/dev/null 2>&1; then
	ok "sensor alpn on the layer4 image is accepted"
else
	bad "sensor alpn on the layer4 image was refused"
fi

# A stand-in for the API's mTLS listener: records the raw bytes it receives
# (one file per connection), so a passed-through connection shows the PROXY
# protocol v2 signature (it ends in "QUIT") and the untouched ClientHello.
docker run -d --name "$run-mtls" --network "$net" --network-alias mtls --entrypoint sh "$image" -c \
	'i=0; while :; do i=$((i+1)); nc -l -p 9443 -w 3 >"/tmp/conn.$i" 2>/dev/null; done' >/dev/null
# Run as api/deploy/docker-compose.yml runs it: non-root, no capability,
# no-new-privileges, ports below 1024 opened by the namespaced sysctl.
docker run -d --name "$run-gwl4" --network "$net" \
	--cap-drop ALL --security-opt no-new-privileges:true --sysctl net.ipv4.ip_unprivileged_port_start=0 \
	-e OPENCTEM_TLS_MODE=internal -e OPENCTEM_HOSTNAME=gateway.test \
	-e OPENCTEM_SENSOR_GATEWAY=passthrough -e SENSOR_PUBLIC_HOSTNAME=sensors.gateway.test -e SENSOR_MTLS_UPSTREAM=mtls:9443 \
	-e OPENCTEM_API_UPSTREAM=api:8000 -e OPENCTEM_WEB_UPSTREAM=web:8000 \
	-e OPENCTEM_ADMIN_SITE=port -e OPENCTEM_ADMIN_ALLOWED_CIDRS="$subnet" \
	-v "$here:/etc/caddy:ro" --entrypoint sh "$l4image" /etc/caddy/entrypoint.sh >/dev/null
l4ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-gwl4")"
for _ in $(seq 1 30); do
	docker run --rm --network "$net" curlimages/curl:latest -sk -m 2 -o /dev/null \
		--resolve "gateway.test:443:$l4ip" https://gateway.test/health >/dev/null 2>&1 && break
	sleep 1
done
# Browsers and token clients are served exactly as by the stock gateway,
# over HTTP/2 and HTTP/1.1.
GW="$run-gwl4"
probe web GET / --http2
probe web GET / --http1.1
probe web GET /login
probe api GET /health --http2
probe api GET /health --http1.1
probe api GET /api/v1/ws --http1.1
probe api POST /api/v3/sensor/openctem.sensor.v3.SensorService/Heartbeat
probe api GET /api/v1/findings -H "Authorization: Bearer oct_example"
probe 404 GET /metrics
unset GW
got="$(docker run --rm --network "$net" curlimages/curl:latest -sk -m 5 -o /dev/null -w '%{http_version}' \
	--resolve "gateway.test:443:$l4ip" --http2 https://gateway.test/ 2>/dev/null || true)"
if [ "$got" = 2 ]; then ok "[l4] browser request negotiated HTTP/2"; else bad "[l4] HTTP version '$got', want 2"; fi

# hello <label> <openssl s_client args...>: a raw TLS ClientHello to the l4 gateway
# (HELLO_PORT, default the main HTTPS port).
hello() {
	local label="$1"
	shift
	docker run --rm --network "$net" --entrypoint sh "$image" -c \
		"apk add -q --no-cache openssl >/dev/null 2>&1; echo | timeout 4 openssl s_client -connect $l4ip:${HELLO_PORT:-443} $* 2>&1" | tr -d '\000' || true
}
captured() { docker exec "$run-mtls" sh -c 'cat /tmp/conn.* 2>/dev/null' | tr -c '[:print:]' '.' || true; }
passed_through() { captured | { grep -o 'QUIT' || true; } | wc -l; }
seen_before="$(passed_through)"
hello alpn -alpn openctem-sensor/3,h2 >/dev/null
sleep 1
after="$(captured)"
if [ "$({ grep -o 'QUIT' || true; } <<<"$after" | wc -l)" -gt "$seen_before" ] && grep -q 'openctem-sensor/3' <<<"$after"; then
	ok "[l4] ClientHello offering the sensor ALPN id (no SNI) passed through with PROXY v2"
else
	bad "[l4] sensor ALPN id was not passed through to the mTLS listener"
fi
seen_before="$(passed_through)"
hello sni -servername sensors.gateway.test >/dev/null
sleep 1
if [ "$(passed_through)" -gt "$seen_before" ]; then
	ok "[l4] ClientHello for the dedicated sensor host (SNI) passed through"
else
	bad "[l4] dedicated sensor host was not passed through"
fi
seen_before="$(passed_through)"
out="$(hello web -servername gateway.test -alpn h2,http/1.1)"
sleep 1
if [ "$(passed_through)" -eq "$seen_before" ] && grep -q 'ALPN protocol: h2' <<<"$out"; then
	ok "[l4] ClientHello without the sensor id is terminated by the gateway (h2)"
else
	bad "[l4] a browser ClientHello reached the mTLS listener or did not negotiate h2"
fi

# The sensor ALPN routing belongs to the main HTTPS listener only. On the
# console's site a sensor hello must be terminated by the gateway like any
# other (and so meet that site's client-network gate), never passed to the API.
for _ in $(seq 1 30); do
	HELLO_PORT=8443 hello wait -servername gateway.test -alpn h2 | grep -q 'ALPN protocol: h2' && break
	sleep 1
done
seen_before="$(passed_through)"
out="$(HELLO_PORT=8443 hello console -alpn openctem-sensor/3,h2)"
sleep 1
if [ "$(passed_through)" -eq "$seen_before" ] && grep -q 'ALPN protocol: h2' <<<"$out"; then
	ok "[l4] sensor ALPN hello on the console's port is terminated by the gateway, not passed to the API"
else
	bad "[l4] sensor ALPN hello on the console's port was passed through or the port did not answer"
fi

if [ "$fail" -ne 0 ]; then
	echo "gateway smoke test FAILED"
	docker logs "$run-gw" 2>&1 | tail -20
	exit 1
fi
echo "gateway smoke test passed"
