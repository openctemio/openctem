#!/usr/bin/env bash
# check-no-test-seam.sh <binary>...: fail when a Go binary was built with the
# authtestseam tag (the sign-in test suites' provider override). A release binary
# must never carry it. Reads the build info with `go version -m`.
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: check-no-test-seam.sh <binary>..." >&2; exit 64; }
rc=0
for f in "$@"; do
	[ -f "$f" ] || { echo "check-no-test-seam: $f is not a file" >&2; rc=1; continue; }
	info="$(go version -m "$f" 2>/dev/null)" || { echo "check-no-test-seam: cannot read build info of $f" >&2; rc=1; continue; }
	if grep -Eq '^[[:space:]]*build[[:space:]]+-tags=.*authtestseam' <<<"$info"; then
		echo "check-no-test-seam: $f was built with the authtestseam tag" >&2
		rc=1
	fi
done
exit "$rc"
