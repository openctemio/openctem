#!/usr/bin/env bash
# Cheap check (no Docker, no image build) that scripts/generate-in-docker.sh
# names paths that exist in the tree. The script runs only on a source checkout,
# so no CI job executes it: after the backend directory rename (api/ -> server/)
# its OPENAPI_SPEC stayed on the old layout and every console image build from a
# checkout failed. This test reads the script and requires:
#   - every checkout file it reads (server/..., web/...) is tracked;
#   - every generated output sits in a tracked directory;
#   - every /src/<path> it hands to a container (the checkout mount) is one of
#     those paths or a directory that exists;
#   - the make target it runs exists in server/Makefile.
# Usage: check-generate-in-docker-paths.sh [repo-root]
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$root"
script=scripts/generate-in-docker.sh
[[ -f "$script" ]] || { echo "::error::$script is missing"; exit 1; }
fail=0
bad() { echo "::error::$script: $1"; fail=1; }
tracked() { [[ -n "$(git ls-files -- "$1" | head -n 1)" ]]; }

# Outputs: the array entries between "outputs=(" and ")".
mapfile -t outputs < <(awk '/^outputs=\(/{f=1;next} f&&/^\)/{f=0} f{print $1}' "$script")
[[ ${#outputs[@]} -gt 0 ]] || bad "no outputs=( ... ) list found"
for o in "${outputs[@]}"; do
  d="$(dirname "$o")"
  tracked "$d/" || bad "output $o: directory $d has no tracked file (wrong layout?)"
done

# Inputs read from the checkout: ROOT-relative literals and /src/ paths.
mapfile -t reads < <(grep -oP '"\$ROOT/[A-Za-z0-9_./-]+"|(?<![A-Za-z0-9_./-])/src/[A-Za-z0-9_./-]+' "$script" | sed -E 's#^"\$ROOT/##; s#"$##; s#^/src/##' | sort -u)
for p in "${reads[@]}"; do
  p="${p%/}"
  in_outputs=0
  for o in "${outputs[@]}"; do [[ "$p" == "$o" ]] && in_outputs=1; done
  if [[ $in_outputs -eq 1 ]]; then continue; fi
  tracked "$p" || tracked "$p/" || bad "reads $p, which is not tracked in the tree"
done

# Paths in the container shell blocks that start with server/ or web/.
mapfile -t inner < <(grep -oE '(^|[[:space:]])(server|web)/[A-Za-z0-9_./-]+' "$script" | tr -d ' \t' | sort -u)
for p in "${inner[@]}"; do
  in_outputs=0
  for o in "${outputs[@]}"; do [[ "$p" == "$o" ]] && in_outputs=1; done
  [[ $in_outputs -eq 1 ]] && continue
  tracked "$p" || tracked "${p%/}/" || bad "names $p, which is not tracked in the tree"
done

# The make target.
if grep -q 'make -C server contract' "$script"; then
  grep -qE '^contract:' server/Makefile || bad "make -C server contract: no such target in server/Makefile"
fi

# Tools: the Go half runs `make -C server contract` in the golang alpine image
# with only the apk packages the script installs. A recipe reachable from the
# contract target (swagger, swagger-install, contract) that calls a tool the
# image lacks fails there (perl did, after the rename). BusyBox has sh, sed,
# grep, awk and mv; anything else must be in the apk list.
apk_list="$(sed -n 's/^[[:space:]]*apk add --no-cache \(.*\) >\/dev\/null$/\1/p' "$script" | head -n 1)"
recipes="$(awk '/^[A-Za-z0-9_-]+:/ { t=$1; sub(/:.*/, "", t); on = (t=="swagger" || t=="swagger-install" || t=="contract") } on && /^\t/ && !/^\t@?#/ { print }' server/Makefile)"
for tool in perl python python3 bash jq gawk curl; do
  if grep -qE "(^|[^A-Za-z0-9_./-])$tool([^A-Za-z0-9_-]|\$)" <<<"$recipes" && ! grep -qwF "$tool" <<<"$apk_list"; then
    bad "server/Makefile (swagger/contract recipes) calls $tool, which the golang alpine image does not have: avoid it, or add it to the apk add line"
  fi
done

[[ $fail -eq 0 ]] || exit 1
echo "OK: every path scripts/generate-in-docker.sh reads exists in the tree."
