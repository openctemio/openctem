#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# A release binary never carries the sign-in test seam: build-dist.sh refuses
# build tags in GOFLAGS, and check-no-test-seam.sh fails a binary built
# with the authtestseam tag.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

out="$(GOFLAGS=-tags=authtestseam OUT_DIR="$tmp/o" VERSION=v1.2.3 bash "$RELEASE_DIR/build-dist.sh" compose 2>&1)"; rc=$?
assert_eq "GOFLAGS with -tags is refused" 64 "$rc"
assert_contains "the refusal names GOFLAGS" "GOFLAGS must not set -tags" "$out"

mkdir "$tmp/m"
printf 'module seamprobe\n\ngo 1.21\n' >"$tmp/m/go.mod"
printf 'package main\n\nfunc main() {}\n' >"$tmp/m/main.go"
(cd "$tmp/m" && GOWORK=off go build -o "$tmp/plain" . && GOWORK=off go build -tags authtestseam -o "$tmp/tagged" . && GOWORK=off go build -tags foo,authtestseam -o "$tmp/tagged2" .)
bash "$RELEASE_DIR/check-no-test-seam.sh" "$tmp/plain" >/dev/null 2>&1; rc=$?
assert_eq "an untagged binary passes" 0 "$rc"
bash "$RELEASE_DIR/check-no-test-seam.sh" "$tmp/tagged" >/dev/null 2>&1; rc=$?
assert_eq "a binary built with authtestseam fails" 1 "$rc"
bash "$RELEASE_DIR/check-no-test-seam.sh" "$tmp/tagged2" >/dev/null 2>&1; rc=$?
assert_eq "authtestseam among other tags fails" 1 "$rc"

finish
