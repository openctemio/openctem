#!/usr/bin/env bash
# Tests for sanitize-notes.py: no stranger @mentions, no emails.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
san() { printf '%s' "$1" | python3 "$RELEASE_DIR/sanitize-notes.py"; }

# shellcheck disable=SC2016 # literal backticks throughout
{
assert_eq "package mention escaped" 'bump `@types/node` to 22' "$(san 'bump @types/node to 22')"
assert_eq "bare mention escaped" 'pin `@latest`' "$(san 'pin @latest')"
assert_eq "credit kept" '* fix x by @alice in #12' "$(san '* fix x by @alice in #12')"
assert_eq "list credit kept" '* @bob made their first contribution' "$(san '* @bob made their first contribution')"
assert_eq "code span untouched" 'run `npm i @scope/pkg@1`' "$(san 'run `npm i @scope/pkg@1`')"
assert_eq "bracketed email dropped" 'Jane Doe wrote it' "$(san 'Jane Doe <jane@example.com> wrote it')"
assert_eq "bare email dropped" 'mail  now' "$(san 'mail jane@example.com now')"
assert_eq "noreply email dropped" 'by .' "$(san 'by 1+bot@users.noreply.github.com.')"
assert_eq "module version is not an email" 'go get x@v1.2.3 y@1.2.3' "$(san 'go get x@v1.2.3 y@1.2.3')"
assert_eq "email inside code span kept" 'see `a@b.com`' "$(san 'see `a@b.com`')"
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf 'hi @someone\n' >"$tmp/n.md"
python3 "$RELEASE_DIR/sanitize-notes.py" "$tmp/n.md"
# shellcheck disable=SC2016
assert_eq "file rewritten in place" 'hi `@someone`' "$(cat "$tmp/n.md")"

finish
