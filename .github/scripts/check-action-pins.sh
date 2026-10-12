#!/usr/bin/env bash
# Fails when a workflow uses an action by a mutable ref (tag or branch).
#
# Threat model: a tag like `@v4` or a branch like `@master` can be moved by
# whoever controls the action's repository (or steals its maintainer's token),
# and the new code then runs with this workflow's GITHUB_TOKEN and secrets. A
# full 40-character commit SHA cannot be moved. Every pin carries a
# `# vX.Y.Z` comment so Dependabot (github-actions ecosystem) can bump it.
# Local actions (`./...`) and `docker://` images are out of scope.
set -euo pipefail

dirs=()
for d in .github/workflows .github/actions; do
  [ -d "$d" ] && dirs+=("$d")
done
[ ${#dirs[@]} -eq 0 ] && exit 0

bad=$(grep -rnE '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*' "${dirs[@]}" \
  | grep -vE 'uses:[[:space:]]*["'\'']?\./' \
  | grep -vE 'uses:[[:space:]]*["'\'']?docker://' \
  | grep -vE 'uses:[[:space:]]*[^@[:space:]]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v?[0-9]' \
  || true)

if [ -n "$bad" ]; then
  echo "::error::Actions must be pinned to a full commit SHA with a '# vX.Y.Z' comment:"
  echo "$bad"
  exit 1
fi
echo "All actions are pinned to commit SHAs."
