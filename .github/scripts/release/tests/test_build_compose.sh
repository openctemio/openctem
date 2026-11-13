#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The Compose bundle (build-dist.sh compose): the deploy files with the
# release's VERSION, tracked files only, no tests, install.sh executable.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"

ROOT="$(cd "$RELEASE_DIR/../../.." && pwd)"
out="$(mktemp -d)"
stray="$ROOT/server/deploy/.untracked-$$"
trap 'rm -f "$stray"; rm -rf "$out"' EXIT
# An untracked file (a stand-in for a local .env or key) must stay out.
printf 'SECRET=1\n' >"$stray"

VERSION=v1.2.3 OUT_DIR="$out" bash "$RELEASE_DIR/build-dist.sh" compose >/dev/null 2>&1
assert_eq "bundle built" "yes" "$([ -f "$out/openctem-compose-v1.2.3.tar.gz" ] && echo yes || echo no)"
list="$(tar -tzvf "$out/openctem-compose-v1.2.3.tar.gz" 2>/dev/null)"
assert_contains "install.sh is executable" "-rwxr-xr-x 0/0" "$(grep ' openctem-compose-v1.2.3/install.sh$' <<<"$list")"
assert_contains "the shared library is in" "openctem-compose-v1.2.3/lib/common.sh" "$list"
assert_contains "the compose file is in" "openctem-compose-v1.2.3/docker-compose.yml" "$list"
assert_not_contains "no shell tests" ".test.sh" "$list"
assert_not_contains "no Go tests" "_test.go" "$list"
assert_not_contains "no untracked file" ".untracked-" "$list"
assert_eq "VERSION is the release" "v1.2.3" "$(tar -xzOf "$out/openctem-compose-v1.2.3.tar.gz" openctem-compose-v1.2.3/VERSION)"

finish
