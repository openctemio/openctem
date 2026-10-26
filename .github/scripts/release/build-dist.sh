#!/usr/bin/env bash
# build-dist.sh <component>...
#
# Builds the release archives for installs without containers
# (api/docs/deployment/binary-install.md) and for private registries
# (api/docs/deployment/air-gapped.md). The Release workflow and its pull
# request dry run call this script, so what a pull request tests is what a tag
# publishes. Run it from any directory; it works on a checkout of this
# repository.
#
# Components:
#   server           openctem-server-<v>-linux-<arch>.tar.gz: the API server
#                    (with its operator commands as links), the job signer,
#                    golang-migrate with the migration files, the OpenAPI spec,
#                    the sensor config templates, systemd units, env examples
#   bootstrap-admin  bootstrap-admin-<v>-<os>-<arch>.tar.gz (.zip on windows):
#                    the first-administrator CLI as a standalone binary
#   gateway          openctem-gateway-<v>-linux-<arch>.tar.gz: Caddy with the
#                    layer4 module and the gateway configuration
#   web              openctem-web-<v>-linux-<arch>.tar.gz: the web console
#                    (Next.js standalone; needs Node.js, see web/.nvmrc)
#   console          openctem-console-<v>-linux-<arch>.tar.gz: the platform console
#   image-kit        openctem-image-kit-<v>.tar.gz: deploy/airgap (Dockerfiles
#                    that build the images from these archives, the mirror
#                    script, CI and configuration templates)
#
# Environment:
#   VERSION      release version, e.g. v0.13.0 (default: dev)
#   COMMIT       commit SHA (default: git rev-parse HEAD)
#   TARGET_OS    GOOS (default linux)
#   TARGET_ARCH  GOARCH (default: the host's)
#   OUT_DIR      where archives go (default: <repo>/dist)
#
# Reproducible: Go builds use CGO_ENABLED=0 and -trimpath; the build time and
# every archive's file times are the commit time (SOURCE_DATE_EPOCH); archives
# are sorted, owned by 0:0 and gzipped without a name or time stamp. The
# third-party tools (golang-migrate, Caddy, swag) are built at the versions the
# images pin, read from their Dockerfiles, so binaries and images never drift.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="${VERSION:-dev}"
COMMIT="${COMMIT:-$(git -C "$ROOT" rev-parse HEAD)}"
TARGET_OS="${TARGET_OS:-linux}"
TARGET_ARCH="${TARGET_ARCH:-$(go env GOARCH 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH GOWORK=off GOFLAGS="${GOFLAGS:-} -mod=readonly"
BUILD_TIME="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"

case "$VERSION" in
dev | v[0-9]*) ;;
*) echo "build-dist: VERSION=$VERSION is not vX.Y.Z[-pre] or dev" >&2; exit 64 ;;
esac

die() { echo "build-dist: $*" >&2; exit 1; }

# dockerfile_arg <file> <name>: the default of `ARG <name>=<value>` in a Dockerfile.
dockerfile_arg() {
	local v
	v="$(sed -n "s/^ARG $2=\"\{0,1\}\([^\"]*\)\"\{0,1\}$/\1/p" "$1" | head -n 1)"
	[ -n "$v" ] || die "ARG $2 not found in $1"
	printf '%s' "$v"
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/openctem-dist.XXXXXX")"
trap 'chmod -R u+w "$WORK" 2>/dev/null; find "$WORK" -mindepth 1 -delete 2>/dev/null; rmdir "$WORK" 2>/dev/null || true' EXIT
mkdir -p "$OUT_DIR"

# pack <staging parent> <dir name> <archive>: a reproducible tar.gz of one directory.
pack() {
	find "$1/$2" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
	tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
		--mode='u+rwX,go+rX,go-w' \
		--format=gnu -C "$1" -cf - "$2" | gzip -n -9 >"$OUT_DIR/$3"
	echo "build-dist: $OUT_DIR/$3"
}

GO_LDFLAGS="-s -w \
 -X github.com/openctemio/openctem/api/pkg/version.Version=${VERSION} \
 -X github.com/openctemio/openctem/api/pkg/version.Commit=${COMMIT} \
 -X github.com/openctemio/openctem/api/pkg/version.BuildTime=${BUILD_TIME}"

gobuild() { # gobuild <out> <pkg>... (in api/)
	local out="$1"; shift
	(cd "$ROOT/api" && CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" \
		go build -trimpath -ldflags="$GO_LDFLAGS" -o "$out" "$@")
}

# gotool <out> <module>@<version> <package> [build tags] [ldflags]: a third-party tool
# built from its module at a pinned version, checked against the Go checksum
# database like every other dependency.
gotool() {
	local out="$1" modver="$2" pkg="$3" tags="${4:-}" ldx="${5:-}" d
	d="$(mktemp -d "$WORK/tool.XXXX")"
	(cd "$d" && go mod init openctem.local/tool >/dev/null 2>&1 &&
		GOFLAGS=-mod=mod go get "$modver" >/dev/null 2>&1 &&
		CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" GOFLAGS=-mod=mod \
			go build -trimpath -ldflags="-s -w $ldx" ${tags:+-tags "$tags"} -o "$out" "$pkg")
}

common_files() { # common_files <dir>
	cp "$ROOT/LICENSE" "$1/LICENSE"
	sed "s/@VERSION@/${VERSION}/g" "$ROOT/deploy/binary/README.md" >"$1/README.md"
	printf '%s\n' "version: ${VERSION}" "commit: ${COMMIT}" "built: ${BUILD_TIME}" \
		"target: ${TARGET_OS}/${TARGET_ARCH}" >"$1/VERSION"
}

build_server() {
	[ "$TARGET_OS" = linux ] || die "server is built for linux only"
	local name="openctem-server-${VERSION}-linux-${TARGET_ARCH}" d
	d="$WORK/$name"
	mkdir -p "$d/bin" "$d/api/openapi" "$d/systemd" "$d/env"
	gobuild "$WORK/gobin/" ./cmd/server ./cmd/signer
	install -m 0755 "$WORK/gobin/server" "$d/bin/openctem-server"
	install -m 0755 "$WORK/gobin/signer" "$d/bin/openctem-signer"
	# The operator commands: links to the server binary (api/cmd/server/tools.go).
	for t in bootstrap-admin refingerprint repomerge ci-trust-scope-plan; do
		ln -s openctem-server "$d/bin/$t"
	done
	# golang-migrate at the version the migrations image ships, and the same wrapper.
	local mv
	mv="$(sed -n 's|.*golang-migrate/migrate/v4/cmd/migrate@\(v[0-9.]*\).*|\1|p' "$ROOT/api/Dockerfile.migrations" | head -n 1)"
	[ -n "$mv" ] || die "golang-migrate version not found in api/Dockerfile.migrations"
	gotool "$d/bin/migrate" "github.com/golang-migrate/migrate/v4@$mv" \
		github.com/golang-migrate/migrate/v4/cmd/migrate postgres "-X main.Version=$mv"
	install -m 0755 "$ROOT/api/scripts/migrate-entrypoint.sh" "$d/bin/openctem-migrate"
	cp -R "$ROOT/api/migrations" "$d/migrations"
	cp -R "$ROOT/api/configs" "$d/configs"
	# The OpenAPI spec the server serves at /openapi.yaml (path relative to its
	# working directory, as in the image).
	if [ ! -s "$ROOT/api/api/openapi/swagger.yaml" ]; then
		make -s -C "$ROOT/api" swagger SWAG_VERSION="$(dockerfile_arg "$ROOT/api/Dockerfile" SWAG_VERSION)" >/dev/null
	fi
	install -m 0644 "$ROOT/api/api/openapi/swagger.yaml" "$d/api/openapi/swagger.yaml"
	install -m 0644 "$ROOT"/deploy/binary/systemd/openctem-server.service \
		"$ROOT"/deploy/binary/systemd/openctem-signer.service \
		"$ROOT"/deploy/binary/systemd/openctem-migrate.service \
		"$ROOT"/deploy/binary/systemd/openctem.sysusers "$d/systemd/"
	install -m 0644 "$ROOT"/deploy/binary/env/server.env.example \
		"$ROOT"/deploy/binary/env/signer.env.example \
		"$ROOT"/deploy/binary/env/migrate.env.example "$d/env/"
	common_files "$d"
	pack "$WORK" "$name" "$name.tar.gz"
}

build_bootstrap_admin() {
	local name="bootstrap-admin-${VERSION}-${TARGET_OS}-${TARGET_ARCH}" bin=bootstrap-admin d
	[ "$TARGET_OS" = windows ] && bin=bootstrap-admin.exe
	d="$WORK/$name"
	mkdir -p "$d"
	gobuild "$d/$bin" ./cmd/bootstrap-admin
	cp "$ROOT/LICENSE" "$d/LICENSE"
	find "$d" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
	if [ "$TARGET_OS" = windows ]; then
		(cd "$d" && TZ=UTC zip -q -X -D "$OUT_DIR/$name.zip" LICENSE "$bin")
		echo "build-dist: $OUT_DIR/$name.zip"
	else
		pack "$WORK" "$name" "$name.tar.gz"
	fi
}

build_gateway() {
	[ "$TARGET_OS" = linux ] || die "gateway is built for linux only"
	local name="openctem-gateway-${VERSION}-linux-${TARGET_ARCH}" d df caddy l4 deps src
	d="$WORK/$name"
	df="$ROOT/api/deploy/gateway/Dockerfile"
	caddy="$(dockerfile_arg "$df" CADDY_VERSION)"
	l4="$(dockerfile_arg "$df" CADDY_L4_VERSION)"
	deps="$(dockerfile_arg "$df" CADDY_DEPS)"
	mkdir -p "$d/bin" "$d/systemd" "$d/env"
	# Same program and pins as the gateway image (api/deploy/gateway/Dockerfile).
	src="$(mktemp -d "$WORK/caddy.XXXX")"
	printf '%s\n' 'package main' 'import (' \
		'	caddycmd "github.com/caddyserver/caddy/v2/cmd"' \
		'	_ "github.com/caddyserver/caddy/v2/modules/standard"' \
		'	_ "github.com/mholt/caddy-l4"' ')' \
		'func main() { caddycmd.Main() }' >"$src/main.go"
	# shellcheck disable=SC2086 # CADDY_DEPS is a list of module@version
	(cd "$src" && go mod init openctem.local/gateway >/dev/null 2>&1 &&
		GOFLAGS=-mod=mod go get "github.com/caddyserver/caddy/v2@${caddy}" "github.com/mholt/caddy-l4@${l4}" $deps >/dev/null 2>&1 &&
		GOFLAGS=-mod=mod go mod tidy >/dev/null 2>&1 &&
		CGO_ENABLED=0 GOOS=linux GOARCH="$TARGET_ARCH" GOFLAGS=-mod=mod \
			go build -trimpath -ldflags="-s -w" -o "$d/bin/caddy" .)
	mkdir -p "$d/etc"
	(cd "$ROOT/api/deploy/gateway" && cp -R Caddyfile planes.caddy servers.common entrypoint.sh admin modes sensors "$d/etc/")
	chmod 0755 "$d/etc/entrypoint.sh"
	install -m 0644 "$ROOT/deploy/binary/systemd/openctem-gateway.service" "$ROOT/deploy/binary/systemd/openctem.sysusers" "$d/systemd/"
	install -m 0644 "$ROOT/deploy/binary/env/gateway.env.example" "$d/env/"
	common_files "$d"
	pack "$WORK" "$name" "$name.tar.gz"
}

# web and console: Next.js standalone output plus its static files, laid out
# as in the images (web/Dockerfile). The archive holds native modules (sharp)
# for the build machine's arch and glibc, so each arch is built on its own
# runner and the archive needs a glibc Linux.
web_prepare() {
	[ "$TARGET_OS" = linux ] || die "web/console are built for linux only"
	local want have
	want="$(tr -d 'v \n' <"$ROOT/web/.nvmrc")"
	have="$(node -p 'process.versions.node.split(".")[0]')"
	[ "$have" = "$want" ] || die "Node.js $have on PATH, web/.nvmrc wants $want"
	local host
	host="$(node -p 'process.arch' | sed 's/x64/amd64/')"
	[ "$host" = "$TARGET_ARCH" ] || die "web/console must be built on a $TARGET_ARCH machine (native modules), this one is $host"
	if [ ! -s "$ROOT/web/src/lib/api/generated/api.types.ts" ]; then
		make -s -C "$ROOT/api" contract >/dev/null
		(cd "$ROOT/web" && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run -s generate:api-types)
	fi
	(cd "$ROOT/web" && { [ -d node_modules ] || npm ci --no-audit --no-fund; })
}

web_env() {
	export NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 DOCKER_BUILD=true \
		NEXT_PUBLIC_APP_VERSION="$VERSION" NEXT_PUBLIC_APP_COMMIT="$COMMIT"
}

build_web() {
	web_prepare
	local name="openctem-web-${VERSION}-linux-${TARGET_ARCH}" d
	d="$WORK/$name"
	(web_env && cd "$ROOT/web" && npm run -s build)
	mkdir -p "$d/systemd" "$d/env"
	cp -R "$ROOT/web/.next/standalone" "$d/app"
	cp -R "$ROOT/web/.next/static" "$d/app/.next/static"
	cp -R "$ROOT/web/public" "$d/app/public"
	cp "$ROOT/web/server-with-ws.mjs" "$d/app/server-with-ws.mjs"
	mkdir -p "$d/app/.next/cache"
	install -m 0644 "$ROOT/deploy/binary/systemd/openctem-web.service" "$ROOT/deploy/binary/systemd/openctem.sysusers" "$d/systemd/"
	install -m 0644 "$ROOT/deploy/binary/env/web.env.example" "$d/env/"
	tr -d 'v \n' <"$ROOT/web/.nvmrc" >"$d/NODE_VERSION"
	common_files "$d"
	pack "$WORK" "$name" "$name.tar.gz"
}

build_console() {
	web_prepare
	local name="openctem-console-${VERSION}-linux-${TARGET_ARCH}" d
	d="$WORK/$name"
	(web_env && cd "$ROOT/web" && npm run -s build:console)
	mkdir -p "$d/systemd" "$d/env"
	cp -R "$ROOT/web/console/.next/standalone" "$d/app"
	cp -R "$ROOT/web/console/.next/static" "$d/app/console/.next/static"
	mkdir -p "$d/app/console/.next/cache"
	install -m 0644 "$ROOT/deploy/binary/systemd/openctem-console.service" "$ROOT/deploy/binary/systemd/openctem.sysusers" "$d/systemd/"
	install -m 0644 "$ROOT/deploy/binary/env/console.env.example" "$d/env/"
	tr -d 'v \n' <"$ROOT/web/.nvmrc" >"$d/NODE_VERSION"
	common_files "$d"
	pack "$WORK" "$name" "$name.tar.gz"
}

build_image_kit() {
	local name="openctem-image-kit-${VERSION}" d
	d="$WORK/$name"
	cp -R "$ROOT/deploy/airgap" "$d"
	# The kit's Dockerfiles default to this release.
	find "$d" -type f -exec sed -i "s/@VERSION@/${VERSION}/g" {} +
	cp "$ROOT/LICENSE" "$d/LICENSE"
	pack "$WORK" "$name" "$name.tar.gz"
}

[ $# -gt 0 ] || die "usage: build-dist.sh server|bootstrap-admin|gateway|web|console|image-kit ..."
for c in "$@"; do
	case "$c" in
	server) build_server ;;
	bootstrap-admin) build_bootstrap_admin ;;
	gateway) build_gateway ;;
	web) build_web ;;
	console) build_console ;;
	image-kit) build_image_kit ;;
	*) die "unknown component $c" ;;
	esac
done
