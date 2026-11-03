#!/usr/bin/env bash
# Refuses AI attribution in text: "Generated with Claude Code", a Co-Authored-By
# trailer naming Claude or Anthropic, a Claude-Session trailer, or a
# claude.ai/code session link. This is the ONE place the pattern lives: the
# local commit-msg hook (.githooks/commit-msg) and the "No AI attribution" CI
# job (.github/workflows/attribution.yml) both run it, so the hook and the
# server-side gate cannot drift.
#
# Usage: check-attribution.sh <file>...
# Each file is read as data (grep never interprets it as a command). Exit 1
# and print the matching lines when any file matches; exit 0 otherwise.
set -u
pattern='(generated with \[?claude code|co-authored-by:.*(claude|anthropic)|claude-session:|claude\.ai/code/session)'
rc=0
for f in "$@"; do
  if grep -qiE -e "$pattern" -- "$f"; then
    echo "attribution: AI attribution lines are not allowed (found in $f):" >&2
    grep -niE -e "$pattern" -- "$f" >&2
    rc=1
  fi
done
exit "$rc"
