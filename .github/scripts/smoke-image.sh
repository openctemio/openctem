#!/usr/bin/env bash
# smoke-image.sh <component> <image-ref> <expected-arch: amd64|arm64>
#
# Runs on the NATIVE runner for <expected-arch>, before the image is pushed.
# Two independent proofs that the image is really built for that arch:
#   1. the image config says so, and
#   2. the main binary's ELF e_machine says so (catches the `ARG TARGETARCH=amd64`
#      default that shipped amd64 binaries inside "arm64" sensor images), and
#   3. the binary actually executes here (no QEMU on the runner).
# Files are read with `docker cp`, never a shell inside the image: images
# without a shell (admin-cli is distroless) are checked the same way.
set -euo pipefail
comp="$1" img="$2" want="$3"

got=$(docker image inspect --format '{{.Architecture}}' "$img")
[ "$got" = "$want" ] || { echo "smoke: $img config arch=$got, want $want" >&2; exit 1; }

case "$want" in amd64) elf=3e00 ;; arm64) elf=b700 ;; *) echo "unknown arch $want" >&2; exit 2 ;; esac
# img_file <path>: copies the file out of a stopped container into a temporary
# file and prints that file's name.
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
img_file() {
  local c rc=0 out
  out="$tmp/$(basename "$1")"
  c=$(docker create "$img")
  docker cp -L "$c:$1" - | tar -xOf - >"$out" || rc=$?
  docker rm "$c" >/dev/null
  [ "$rc" = 0 ] && echo "$out"
}
elf_of() { local f; f=$(img_file "$1") && od -An -t x1 -j 18 -N 2 "$f" | tr -d ' \n'; }

case "$comp" in
  openctem-api) bin=/app/server;            run=(/app/bootstrap-admin -h) ;;
  admin-cli)    bin=/usr/local/bin/bootstrap-admin; run=("$bin" -h) ;;
  migrations)   bin=/usr/local/bin/migrate; run=(migrate -version) ;;
  seed)         bin=""; run=(sh -c 'true') ;;
  openctem-web) bin=/usr/local/bin/node;    run=(node -e 'process.exit(0)') ;;
  openctem-console) bin=/usr/local/bin/node; run=(node -e "require('fs').accessSync('/app/console/server.js')") ;;
  openctem)     bin=/opt/openctem/api/server; run=(migrate -version) ;;
  openctem-gateway) bin=/usr/bin/caddy;   run=(caddy version) ;;
  *) echo "unknown component $comp" >&2; exit 2 ;;
esac

if [ -n "$bin" ]; then
  m=$(elf_of "$bin")
  [ "$m" = "$elf" ] || { echo "smoke: $img $bin ELF e_machine=$m, want $elf ($want)" >&2; exit 1; }
fi
set +e
docker run --rm --entrypoint "${run[0]}" "$img" "${run[@]:1}" >/tmp/smoke.out 2>&1; rc=$?
set -e
# -h / -version may exit 0 or 2; 126/127 or "exec format error" means it cannot run here.
if [ "$rc" -ge 126 ] || grep -qi 'exec format error' /tmp/smoke.out; then
  cat /tmp/smoke.out >&2; echo "smoke: $img cannot execute on $want (rc=$rc)" >&2; exit 1
fi
# The API serves its OpenAPI spec from the image (it is generated, not committed).
case "$comp" in
  openctem-api) spec=/app/api/openapi/swagger.yaml ;;
  openctem)     spec=/opt/openctem/api/api/openapi/swagger.yaml ;;
  *)            spec="" ;;
esac
if [ -n "$spec" ]; then
  { f=$(img_file "$spec") && test -s "$f" && grep -q '^paths:' "$f"; } \
    || { echo "smoke: $img has no OpenAPI spec at $spec" >&2; exit 1; }
fi
# The gateway image exists for the layer4 module (sensor ALPN routing).
if [ "$comp" = openctem-gateway ]; then
  docker run --rm --entrypoint caddy "$img" list-modules | grep -qx 'tls.handshake_match.alpn' \
    || { echo "smoke: $img lacks the layer4 ALPN matcher" >&2; exit 1; }
fi
echo "smoke: $comp $img arch=$got elf=${m:-n/a} exec-rc=$rc OK"
