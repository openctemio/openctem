#!/usr/bin/env bash
# Prints `languages=<JSON array>` (also to $GITHUB_OUTPUT when set): the CodeQL
# languages this run analyses (.github/workflows/codeql.yml, header).
#
#   pull_request, push to develop   the side that changed: API=true -> go,
#                                   WEB=true -> javascript-typescript
#   schedule, push to any other     both (main moves only on releases; the
#   branch                          daily schedule refreshes develop's baseline)
#
# Env: EVENT (github.event_name), REF (github.ref), API, WEB (true|false, from
# changed.sh and scope.sh). Unknown values count as "changed": the script only
# ever adds languages.
set -euo pipefail
api=${API:-true} web=${WEB:-true}
case "${EVENT:-}" in
  pull_request) ;;
  push) [ "${REF:-}" = refs/heads/develop ] || { api=true web=true; } ;;
  *) api=true web=true ;;
esac
[ "$api" = false ] || [ "$api" = true ] || api=true
[ "$web" = false ] || [ "$web" = true ] || web=true
langs=()
[ "$api" = true ] && langs+=('"go"')
[ "$web" = true ] && langs+=('"javascript-typescript"')
languages="[$(IFS=,; echo "${langs[*]}")]"
echo "languages=$languages"
[ -z "${GITHUB_OUTPUT:-}" ] || echo "languages=$languages" >>"$GITHUB_OUTPUT"
