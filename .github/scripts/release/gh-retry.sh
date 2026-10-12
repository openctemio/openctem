#!/usr/bin/env bash
# gh-retry.sh <gh args...>
#
# Runs `gh <args>` and retries with exponential backoff (10s, 20s, 40s, 80s,
# 160s; about 5 minutes in all) when it fails. GitHub's API answers 5xx for
# minutes at a time during incidents, and a release step that gives up on the
# first 500 leaves a tag without its release, binaries or SBOMs. Every caller
# must be idempotent (create-or-update, upload --clobber).
set -uo pipefail
attempts="${GH_RETRY_ATTEMPTS:-6}"
delay="${GH_RETRY_DELAY:-10}"
for i in $(seq 1 "$attempts"); do
  rc=0
  gh "$@" || rc=$?
  if [ "$rc" -eq 0 ]; then
    exit 0
  fi
  if [ "$i" -eq "$attempts" ]; then
    echo "gh-retry: gh $1 $2 failed ${attempts} times (last exit ${rc})" >&2
    exit "$rc"
  fi
  echo "gh-retry: gh $1 $2 failed (exit ${rc}), attempt ${i}/${attempts}; retrying in ${delay}s" >&2
  sleep "$delay"
  delay=$((delay * 2))
done
