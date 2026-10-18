#!/usr/bin/env bash
# Fails when a commit added by a pull request (or merge-queue group) carries a
# denied email address as its author, its committer or in a Co-authored-by
# trailer. It exists so that an address that must not appear in this
# repository's history (for example a work address set by mistake in a local
# git config) is caught before the commit lands, instead of after.
#
# The deny list is newline- or comma-separated, case-insensitive fixed
# strings (usually a domain such as "@example.com") read from the
# COMMIT_EMAIL_DENYLIST environment variable, a repository secret so the list
# itself is never committed. Unset or empty (forks, Dependabot, before the
# secret exists): the check passes with a notice. Everything not denied passes:
# outside contributors are covered by the CLA check, not by this one.
#
# Output names only the commit and the field, never the address, so the log
# does not republish it. Never run this with `set -x`.
#
# Usage: bash .github/scripts/check-commit-emails.sh <base>..<head>
set -euo pipefail
set +x

range="${1:-}"
if [[ -z "$range" ]]; then
  echo "::notice::No commit range (not a pull request or merge group); the commit email check was skipped."
  exit 0
fi
if [[ -z "${COMMIT_EMAIL_DENYLIST:-}" ]]; then
  if [[ "${REQUIRE_DENYLIST:-}" == "true" ]]; then
    echo "::error::COMMIT_EMAIL_DENYLIST is not set on a repository that requires it. Add the secret (comma- or newline-separated addresses); until then this check cannot run and fails closed."
    exit 1
  fi
  echo "::notice::COMMIT_EMAIL_DENYLIST is not set; the commit email check was skipped."
  exit 0
fi

mapfile -t denied < <(printf '%s\n' "$COMMIT_EMAIL_DENYLIST" | tr ',' '\n' |
  sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]' | grep -v '^$' || true)
if [[ ${#denied[@]} -eq 0 ]]; then
  if [[ "${REQUIRE_DENYLIST:-}" == "true" ]]; then
    echo "::error::COMMIT_EMAIL_DENYLIST is empty on a repository that requires it; failing closed."
    exit 1
  fi
  echo "::notice::COMMIT_EMAIL_DENYLIST is empty; the commit email check was skipped."
  exit 0
fi

is_denied() {
  local email="${1,,}" d
  for d in "${denied[@]}"; do
    [[ "$email" == *"$d"* ]] && return 0
  done
  return 1
}

status=0
count=0
while read -r sha; do
  count=$((count + 1))
  fields=()
  is_denied "$(git log -1 --format=%ae "$sha")" && fields+=("author")
  is_denied "$(git log -1 --format=%ce "$sha")" && fields+=("committer")
  while IFS= read -r line; do
    if is_denied "$line"; then fields+=("Co-authored-by trailer"); break; fi
  done < <(git log -1 --format=%B "$sha" | grep -i '^co-authored-by:' || true)
  if [[ ${#fields[@]} -gt 0 ]]; then
    joined="$(printf '%s, ' "${fields[@]}")"
    echo "::error::Commit ${sha:0:12} uses a denied email address (${joined%, }). Fix your git user.email and rewrite the commit (git rebase <base> --exec 'git commit --amend --no-edit --reset-author') before pushing again; a trailer needs the commit message edited."
    status=1
  fi
done < <(git rev-list "$range")

if [[ $status -eq 0 ]]; then
  echo "Commit email check: ${count} commit(s) in ${range}, none denied."
fi
exit "$status"
