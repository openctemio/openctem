#!/usr/bin/env bash
# smoke-dist.sh <dist-dir> <version>
#
# Smoke test of the linux/amd64 release archives built by build-dist.sh (the
# Release archives workflow runs it on every pull request that touches them;
# run it locally the same way). It checks that:
#   - the server, signer, openctem-migrate and the operator command links run and
#     report the version;
#   - the server accepts the shipped example settings (-check-config, with
#     generated secrets);
#   - the systemd units verify and keep their hardening (systemd-analyze);
#   - the gateway's Caddy has the layer4 module and the shipped Caddyfile
#     validates through the shipped entrypoint, with the systemd unit's paths;
#   - the web and console servers start and answer /api/health;
#   - the image kit's Dockerfiles build from the archives and the images run
#     (when docker buildx is available; SKIP_IMAGE_KIT=1 skips it).
set -euo pipefail

dist="$(cd "$1" && pwd)"
version="$2"
arch=amd64
fail() { echo "smoke-dist: FAIL: $*" >&2; exit 1; }
ok() { echo "smoke-dist: ok: $*"; }
# prints <pattern> <command...>: the command's output (stdout and stderr,
# whatever its exit code) contains the fixed string or regex <pattern>.
# Output is captured first: `cmd | grep -q` fails under pipefail when grep
# exits early.
prints() {
	local pattern="$1" out
	shift
	out="$("$@" 2>&1)" || true
	grep -qE -- "$pattern" <<<"$out"
}

work="$(mktemp -d "${TMPDIR:-/tmp}/openctem-smoke.XXXXXX")"
pids=()
images=()
cleanup() {
	for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done
	for i in ${images[@]+"${images[@]}"}; do docker rmi -f "$i" >/dev/null 2>&1 || true; done
	chmod -R u+w "$work" 2>/dev/null || true
	find "$work" -mindepth 1 -delete 2>/dev/null || true
	rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

unpack() { # unpack <archive> <dir>
	[ -r "$dist/$1" ] || fail "$1 is missing from $dist"
	mkdir -p "$2"
	tar -C "$2" --strip-components=1 -xzf "$dist/$1"
}

opt="$work/opt/openctem"
unpack "openctem-server-${version}-linux-${arch}.tar.gz" "$opt/server"
unpack "openctem-gateway-${version}-linux-${arch}.tar.gz" "$opt/gateway"
unpack "openctem-web-${version}-linux-${arch}.tar.gz" "$opt/web"
unpack "openctem-console-${version}-linux-${arch}.tar.gz" "$opt/console"
unpack "bootstrap-admin-${version}-linux-${arch}.tar.gz" "$work/bootstrap-admin"

# --- server -----------------------------------------------------------------
s="$opt/server"
prints "openctem-server ${version} " "$s/bin/openctem-server" -version || fail "openctem-server -version"
prints "openctem-signer ${version} " "$s/bin/openctem-signer" version || fail "openctem-signer version"
prints "^${version}\$" "$s/bin/openctem-migrate" -version || fail "openctem-migrate -version"
prints 'Usage of bootstrap-admin' "$s/bin/bootstrap-admin" -h || fail "bootstrap-admin link does not run the command"
prints 'Usage of bootstrap-admin' "$work/bootstrap-admin/bootstrap-admin" -h || fail "standalone bootstrap-admin"
[ -s "$s/api/openapi/swagger.yaml" ] || fail "OpenAPI spec missing"
ls "$s"/migrations/*_baseline.up.sql >/dev/null 2>&1 || fail "migrations missing"
ok "server, signer, migrate, operator commands report ${version}"

env_file="$work/server.env"
grep -v '^#' "$s/env/server.env.example" | grep . |
	sed "s/^APP_ENCRYPTION_KEY=.*/APP_ENCRYPTION_KEY=$(openssl rand -hex 32)/;
	     s/^FINGERPRINT_KEY=.*/FINGERPRINT_KEY=$(openssl rand -hex 32)/;
	     s/^DB_PASSWORD=.*/DB_PASSWORD=$(openssl rand -hex 24)/;
	     s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$(openssl rand -hex 24)/" >"$env_file"
mapfile -t env_vars <"$env_file"
out="$(cd "$s" && env -i PATH=/usr/bin:/bin "${env_vars[@]}" ./bin/openctem-server -check-config 2>&1)" ||
	fail "server.env.example does not pass -check-config: $out"
ok "server.env.example passes -check-config"

# --- systemd units ----------------------------------------------------------
if command -v systemd-analyze >/dev/null 2>&1; then
	units="$work/units"
	mkdir -p "$units"
	node_bin="$(command -v node)"
	for comp in server gateway web console; do
		for u in "$opt/$comp"/systemd/*.service; do
			sed "s|/opt/openctem|$opt|g; s|/usr/bin/node|$node_bin|g" "$u" >"$units/$(basename "$u")"
		done
	done
	systemd-analyze verify "$units"/*.service || fail "systemd-analyze verify"
	for u in "$units"/*.service; do
		systemd-analyze security --offline=true --threshold=25 "$u" >/dev/null ||
			fail "$(basename "$u") exposure is above 2.5 (systemd-analyze security)"
	done
	ok "systemd units verify, exposure at most 2.5"
else
	echo "smoke-dist: systemd-analyze not found, units not checked"
fi

# --- gateway ----------------------------------------------------------------
g="$opt/gateway"
prints '^layer4$' "$g/bin/caddy" list-modules || fail "caddy has no layer4 module"
mkdir -p "$work/gw/data" "$work/gw/config"
(
	set -a
	# shellcheck disable=SC1091
	. "$g/env/gateway.env.example"
	set +a
	PATH="$g/bin:$PATH" OPENCTEM_GATEWAY_DIR="$g/etc" XDG_DATA_HOME="$work/gw/data" \
		XDG_CONFIG_HOME="$work/gw/config" OPENCTEM_CA_EXPORT_DIR="$work/gw/no-export" \
		OPENCTEM_HOSTNAME=localhost \
		sh "$g/etc/entrypoint.sh" caddy validate --config "$g/etc/Caddyfile" --adapter caddyfile
) >"$work/gw.log" 2>&1 || { tail -n 20 "$work/gw.log" >&2; fail "gateway Caddyfile does not validate"; }
ok "gateway: layer4 module, Caddyfile validates through the entrypoint"

# --- web and console --------------------------------------------------------
health() { # health <port>
	for _ in $(seq 1 60); do
		curl -fsS "http://127.0.0.1:$1/api/health" >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}
(cd "$opt/web/app" && PORT=13900 HOSTNAME=127.0.0.1 NODE_ENV=production BACKEND_API_URL=http://127.0.0.1:9 \
	node server-with-ws.mjs >"$work/web.log" 2>&1) &
pids+=($!)
(cd "$opt/console/app" && PORT=13901 HOSTNAME=127.0.0.1 NODE_ENV=production BACKEND_API_URL=http://127.0.0.1:9 \
	ADMIN_API_URL=http://127.0.0.1:9 node console/server.js >"$work/console.log" 2>&1) &
pids+=($!)
health 13900 || { tail -n 20 "$work/web.log" >&2; fail "web does not answer /api/health"; }
health 13901 || { tail -n 20 "$work/console.log" >&2; fail "console does not answer /api/health"; }
ok "web and console answer /api/health"

# --- image kit --------------------------------------------------------------
if [ "${SKIP_IMAGE_KIT:-}" = 1 ] || ! docker buildx version >/dev/null 2>&1; then
	echo "smoke-dist: image kit not built (SKIP_IMAGE_KIT=1 or no docker buildx)"
	exit 0
fi
kit="$work/kit"
mkdir -p "$kit"
tar -C "$kit" --strip-components=1 -xzf "$dist/openctem-image-kit-${version}.tar.gz"
mkdir -p "$kit/image-kit/dist/$arch"
for comp in server gateway web console; do cp -a "$opt/$comp" "$kit/image-kit/dist/$arch/$comp"; done
cp -a "$work/bootstrap-admin" "$kit/image-kit/dist/$arch/bootstrap-admin"
tag="openctem-smoke-kit-$$"
for c in api migrations seed admin-cli gateway web console; do
	docker buildx build --quiet --load --platform "linux/$arch" --build-arg "TARGETARCH=$arch" \
		-f "$kit/image-kit/Dockerfile.$c" -t "$tag-$c" "$kit/image-kit" >/dev/null ||
		fail "image kit: Dockerfile.$c does not build"
	images+=("$tag-$c")
done
prints "openctem-server ${version} " docker run --rm "$tag-api" -version || fail "kit api image"
prints "${version}" docker run --rm --entrypoint /app/openctem-signer "$tag-api" version || fail "kit api image: signer"
prints '^v4\.' docker run --rm "$tag-migrations" -version || fail "kit migrations image"
prints 'Usage of bootstrap-admin' docker run --rm "$tag-admin-cli" -h || fail "kit admin-cli image"
prints '^layer4$' docker run --rm "$tag-gateway" caddy list-modules || fail "kit gateway image"
prints 'Available seed files' docker run --rm "$tag-seed" || fail "kit seed image"
[ "$(docker image inspect -f '{{.Config.User}}' "$tag-api")" = "1000:1000" ] || fail "kit api image user"
[ "$(docker image inspect -f '{{.Config.User}}' "$tag-web")" = "1001:1001" ] || fail "kit web image user"
cid="$(docker run -d --rm -p 127.0.0.1:13902:3000 -e BACKEND_API_URL=http://127.0.0.1:9 "$tag-web")"
health 13902 || { docker logs "$cid" 2>&1 | tail -n 20 >&2; docker rm -f "$cid" >/dev/null; fail "kit web image does not answer /api/health"; }
docker rm -f "$cid" >/dev/null
cid="$(docker run -d --rm -p 127.0.0.1:13903:3000 -e BACKEND_API_URL=http://127.0.0.1:9 "$tag-console")"
health 13903 || { docker logs "$cid" 2>&1 | tail -n 20 >&2; docker rm -f "$cid" >/dev/null; fail "kit console image does not answer /api/health"; }
docker rm -f "$cid" >/dev/null
ok "image kit: every Dockerfile builds and its image runs"
