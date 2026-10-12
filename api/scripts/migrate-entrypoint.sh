#!/bin/sh
# Entrypoint of the migrations image, also used by the all-in-one image:
# runs golang-migrate with the arguments it was given, unchanged.
#
# The migrations start from one baseline file (docs/rfcs/RFC-053-migration-baseline.md).
# A database older than the baseline is at a version that has no file any
# more, and golang-migrate refuses it with "no migration found for version N
# ... file does not exist" without changing anything. This wrapper adds what
# the operator has to do. It never changes migrate's exit code.
set -u

dir=/migrations
prev=""
for a in "$@"; do
  case "$a" in -path=* | --path=*) dir="${a#*=}" ;; esac
  case "$prev" in -path | --path) dir="$a" ;; esac
  prev="$a"
done

out="$(migrate "$@" 2>&1)"
rc=$?
[ -n "$out" ] && printf '%s\n' "$out"
[ "$rc" -eq 0 ] && exit 0

v="$(printf '%s\n' "$out" | sed -n 's/.*no migration found for version \([0-9][0-9]*\).*/\1/p' | head -n 1)"
base=""
for f in "$dir"/[0-9]*_baseline.up.sql; do
  [ -f "$f" ] && { f="${f##*/}"; base="${f%%_*}"; }
done
base_n="$(printf '%s' "$base" | sed 's/^0*//')"
if [ -n "$v" ] && [ -n "$base_n" ] && [ "$v" -lt "$base_n" ]; then
  cat >&2 <<EOF

This database is at migration $v, older than the migration baseline $base.
This release creates the schema from one baseline file and cannot upgrade a
database older than it; nothing was changed. To upgrade:
  1. back up the database;
  2. deploy the last release before the baseline (git tag pre-baseline-$base,
     which still ships every migration up to $base) and run its migrations;
  3. then deploy this release.
See api/docs/development/migrations.md, "Migration baseline".
EOF
fi
exit "$rc"
