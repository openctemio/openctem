#!/usr/bin/env bash
# Fails when the platform (api/ or web/) depends on a sensor implementation
# instead of on contracts (api/docs/rfcs/RFC-094-platform-contracts-only.md).
#
# The platform may depend on ctis (schemas, importers and the contract
# packages, including ctis/transfer), the versioned sensor protocol and
# signed manifests. It must never require, import or vendor the sensor SDK
# (github.com/openctemio/sdk-go) or a sensor (github.com/openctemio/sensor,
# or any other sensor product repository): every sensor, ours or a
# customer's, is treated the same, so none may be compiled in.
#
# Checked:
#   - api/go.mod and api/go.sum: no require, replace or checksum line for a
#     forbidden module (go.sum lists every module in the graph, so an
#     indirect requirement is caught too);
#   - api Go files: no import of a forbidden module path;
#   - web/package.json and web/package-lock.json: no dependency on a
#     forbidden package;
#   - web sources: no import of a forbidden package.
#
# Usage: check-platform-deps.sh [repo-root]   (default: the repository root)
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$root"

# Module paths a platform build must never reach. A prefix match: it also
# covers nested modules such as sdk-go/pkg/<x>.
go_forbidden='github\.com/openctemio/(sdk-go|sensor|connector-[a-z0-9-]+)([/" ]|$)'
# npm package names a platform build must never reach.
npm_forbidden='"@openctemio/(sdk|sdk-go|sensor)[a-z0-9-]*"'

fail=0
report() {
  echo "::error::$1"
  fail=1
}

for f in api/go.mod api/go.sum; do
  [[ -f "$f" ]] || continue
  while IFS= read -r hit; do
    report "$f:${hit%%:*}: the platform must not depend on a sensor module (${hit#*:})"
  done < <(grep -nE "$go_forbidden" "$f" || true)
done

if [[ -d api ]]; then
  # Import lines: a quoted path at the start of an import spec, alone or in a
  # block. Comments and strings elsewhere do not count.
  while IFS= read -r hit; do
    report "$hit: the platform must not import a sensor module"
  done < <(grep -rnE --include='*.go' "^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.]+[[:space:]]+)?\"$go_forbidden" api || true)
fi

for f in web/package.json web/package-lock.json; do
  [[ -f "$f" ]] || continue
  while IFS= read -r hit; do
    report "$f:${hit%%:*}: the web must not depend on a sensor package"
  done < <(grep -nE "$npm_forbidden" "$f" || true)
done

if [[ -d web/src ]]; then
  while IFS= read -r hit; do
    report "$hit: the web must not import a sensor package"
  done < <(grep -rnE --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' \
    "from[[:space:]]+['\"]@openctemio/(sdk|sdk-go|sensor)" web/src || true)
fi

if [[ "$fail" -ne 0 ]]; then
  echo "The platform depends on contracts only: ctis, the sensor protocol and signed manifests."
  echo "Move the shared code into ctis (see RFC-094) instead of importing a sensor or the SDK."
  exit 1
fi
echo "OK: api and web depend on no sensor module or SDK."
