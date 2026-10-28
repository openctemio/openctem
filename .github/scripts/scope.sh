#!/usr/bin/env bash
# scope.sh
#
# What KIND of change is this, for the workflow that calls it? changed.sh says
# which side (api, web) a change touches; this says which part of that side, so
# a workflow can skip work the change cannot affect. It only ever NARROWS:
# workflows run a job when changed.sh says the side changed AND this says the
# relevant part changed. When in doubt every output is true.
#
# Writes to $GITHUB_OUTPUT (and prints with the reason):
#   api_code=true|false  Go API code (api/, except documentation), or a shared
#                        build file (Makefile, go.work, go.work.sum, deploy/).
#   web_app=true|false   web application code: web/ except web/e2e/ and the
#                        translation catalogs, or a shared build file. Unit
#                        tests, config and lockfiles count as app code.
#   web_e2e=true|false   the end-to-end suite (web/e2e/: specs, fixtures,
#                        helpers, its config). Type-checked and linted by Web
#                        checks; run by Web E2E. Not shipped in any image.
#   web_i18n=true|false  a translation catalog
#                        (web/src/lib/i18n/dictionaries/<lang>/*.json).
#   i18n_files=<paths>   the changed catalogs, space separated, relative to web/
#                        (for `vitest related`); empty when none.
#   i18n_en=true|false   an English catalog: the e2e specs find elements by
#                        their English text, so Web E2E still runs for it.
#   ci_self=true|false   a CI file THIS workflow depends on: its own workflow
#                        file, or a file under .github/ that it reaches through
#                        references (scripts, composite actions, called
#                        workflows, data files such as quarantine.yml), followed
#                        transitively. The workflow then runs in full.
#   ci_other=true|false  another file under .github/ (informational).
#
# Examples (PR and merge queue alike):
#   only web/e2e/specs/x.spec.ts      web_app=false web_e2e=true: Web checks
#                                     (tsc + eslint cover e2e) and Web E2E run;
#                                     Web tests, the Next build, the all-in-one
#                                     image and CodeQL do not.
#   only a vi catalog                 web_i18n=true: Web checks + i18n tests.
#   only .github/workflows/web-ci.yml ci_self=true in Web CI only; API CI,
#                                     All-in-one CI and Web E2E skip (Workflow
#                                     Lint and the script self-tests still run).
#
# Range: the same as changed.sh. PR: origin/<base>...HEAD. Push: before..HEAD.
# Merge queue: merge_group.base_sha..head_sha. Anything else (schedule,
# dispatch, missing SHAs, unreadable commits) prints true for everything.
#
# Env: GITHUB_EVENT_NAME, GITHUB_BASE_REF, EVENT_BEFORE, MG_BASE, MG_HEAD,
#      WORKFLOW_FILE (default: the path in GITHUB_WORKFLOW_REF).
set -euo pipefail

out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/stdout}"; echo "$1=$2${3:+ ($3)}"; }
all() {
  local k
  for k in api_code web_app web_e2e web_i18n i18n_en ci_self ci_other; do out "$k" true "$1"; done
  out i18n_files ""
  exit 0
}

case "${GITHUB_EVENT_NAME:-}" in
  pull_request)
    git cat-file -e "origin/${GITHUB_BASE_REF:-}^{commit}" 2>/dev/null \
      || git fetch --no-tags --quiet origin "${GITHUB_BASE_REF:-}" 2>/dev/null || all "base not available"
    range="origin/${GITHUB_BASE_REF}...HEAD" ;;
  push)
    before="${EVENT_BEFORE:-}"
    if [[ -z "$before" || "$before" =~ ^0+$ ]] || ! git cat-file -e "${before}^{commit}" 2>/dev/null; then
      all "push without a usable 'before'"
    fi
    range="${before}..HEAD" ;;
  merge_group)
    base="${MG_BASE:-}" head="${MG_HEAD:-}"
    [[ -n "$base" && -n "$head" ]] || all "merge_group without base_sha/head_sha"
    git cat-file -e "${base}^{commit}" 2>/dev/null || git fetch --no-tags --quiet origin "$base" 2>/dev/null || true
    if ! git cat-file -e "${base}^{commit}" 2>/dev/null || ! git cat-file -e "${head}^{commit}" 2>/dev/null; then
      all "merge_group commits not available"
    fi
    range="${base}..${head}" ;;
  *) all "event ${GITHUB_EVENT_NAME:-unknown}" ;;
esac
changed="$(git diff --name-only "$range")" || all "cannot diff $range"

wf="${WORKFLOW_FILE:-}"
if [[ -z "$wf" && -n "${GITHUB_WORKFLOW_REF:-}" ]]; then
  wf="${GITHUB_WORKFLOW_REF#*/}"; wf="${wf#*/}"; wf="${wf%@*}"
fi

# closure: every file under .github/ the workflow file reaches. A file is
# reached when a reached file names it: its base name (a script, a data file),
# for a composite action its directory (.github/actions/<name>), for a called
# workflow its path (./.github/workflows/<file>). Over-matching only runs more.
closure=""
if [[ -n "$wf" && -f "$wf" ]]; then
  mapfile -t cand < <(git ls-files .github)
  reached=("$wf") closure="$wf"$'\n'
  grew=1
  while (( grew )); do
    grew=0
    for c in "${cand[@]}"; do
      grep -qxF "$c" <<<"$closure" && continue
      case "$c" in
        .github/actions/*/action.yml | .github/actions/*/action.yaml) needle="$(dirname "$c")"; needle="${needle#.github/}" ;;
        # Another workflow is reached only when called (uses: ./.github/workflows/x.yml),
        # not when a comment or a script mentions its name.
        .github/workflows/*) needle="./$c" ;;
        *) needle="$(basename "$c")" ;;
      esac
      if grep -qF -- "$needle" "${reached[@]}" 2>/dev/null; then
        reached+=("$c"); closure+="$c"$'\n'; grew=1
      fi
    done
  done
fi

is_docs() {
  case "$1" in
    api/docs/configuration/environment-variables.md) return 1 ;;
    *.md | api/docs/* | .claude/* | */.claude/*) return 0 ;;
  esac
  return 1
}

api_code="" web_app="" web_e2e="" web_i18n="" i18n_en="" ci_self="" ci_other="" i18n_files=""
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  is_docs "$f" && continue
  case "$f" in
    Makefile | go.work | go.work.sum | deploy/*) api_code=${api_code:-$f} web_app=${web_app:-$f} ;;
    api/*) api_code=${api_code:-$f} ;;
    web/e2e/*) web_e2e=${web_e2e:-$f} ;;
    web/src/lib/i18n/dictionaries/*/*.json)
      web_i18n=${web_i18n:-$f} i18n_files+="${i18n_files:+ }${f#web/}"
      case "$f" in web/src/lib/i18n/dictionaries/en/*) i18n_en=${i18n_en:-$f} ;; esac ;;
    web/*) web_app=${web_app:-$f} ;;
    .github/*)
      if [[ -z "$wf" || ! -f "$wf" ]]; then ci_self=${ci_self:-"$f (workflow file unknown)"}
      elif grep -qxF "$f" <<<"$closure"; then ci_self=${ci_self:-$f}
      else ci_other=${ci_other:-$f}; fi ;;
  esac
done <<<"$changed"

echo "scope of $range for ${wf:-an unknown workflow}:"
for k in api_code web_app web_e2e web_i18n i18n_en ci_self ci_other; do
  v="${!k}"
  if [[ -n "$v" ]]; then out "$k" true "$v"; else out "$k" false; fi
done
out i18n_files "$i18n_files"
