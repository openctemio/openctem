#!/usr/bin/env bash
# Fails when a tracked file names a customer or carries the live LAN address.
#
# 1. Customer identifiers: newline-separated, case-insensitive fixed strings
#    read from the CUSTOMER_DENYLIST environment variable (a repository
#    secret, so the list itself is never committed). Unset or empty (forks,
#    Dependabot, before the secret exists): this part passes with a notice.
# 2. The live LAN (192.168.8.0/24) anywhere, test files included: a plain pattern.
#
# Fail closed: when REQUIRE_DENYLIST=true (set by CI on the main repository,
# where the secret is available) a missing or empty CUSTOMER_DENYLIST fails
# the check instead of skipping it. Forks and Dependabot runs cannot read
# secrets and leave it unset, so they skip with a notice.
#
# Output names only file:line, never the matched text, and withholds a path
# that itself contains a denied string. Never run this with `set -x`: the
# patterns would be traced into the log.
#
# Run from the repository root: bash .github/scripts/check-customer-identifiers.sh
set -euo pipefail
set +x

status=0

# --- 2. live LAN address --------------------------------------
lan_re='192\.168\.8\.[0-9]{1,3}'
lan_hits="$(git grep -I -n -E "$lan_re" -- . \
  ':(exclude).github/scripts/check-customer-identifiers*' |
  awk -F: '{print $1 ":" $2}' || true)"
if [[ -n "$lan_hits" ]]; then
  echo "::error::The live LAN address range appears in a tracked file. Use an RFC 5737 address (192.0.2.x, 198.51.100.x, 203.0.113.x) or a generic private one:"
  printf "%s\n" "$lan_hits" | sed "s/^/  /"
  status=1
fi

# --- 1. customer identifiers -------------------------------------------------
if [[ -z "${CUSTOMER_DENYLIST:-}" ]]; then
  if [[ "${REQUIRE_DENYLIST:-}" == "true" ]]; then
    echo "::error::CUSTOMER_DENYLIST is not set on a repository that requires it. Add the CUSTOMER_DENYLIST secret (newline-separated names); until then this check cannot run and fails closed."
    exit 1
  fi
  echo "::notice::CUSTOMER_DENYLIST is not set; the customer-identifier check was skipped."
  exit "$status"
fi

patterns="$(mktemp)"
trap 'shred -u "$patterns" 2>/dev/null || : > "$patterns"' EXIT
chmod 600 "$patterns"
# Drop CRs and blank lines: an empty pattern would match every line.
printf '%s\n' "$CUSTOMER_DENYLIST" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' |
  grep -v '^$' > "$patterns" || true
if [[ ! -s "$patterns" ]]; then
  if [[ "${REQUIRE_DENYLIST:-}" == "true" ]]; then
    echo "::error::CUSTOMER_DENYLIST holds no patterns on a repository that requires it; failing closed."
    exit 1
  fi
  echo "::notice::CUSTOMER_DENYLIST holds no patterns; the customer-identifier check was skipped."
  exit "$status"
fi

denied_path() { printf '%s\n' "$1" | grep -q -F -i -f "$patterns"; }

found=0
# Paths first: a file named after a customer is a leak even when empty.
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  found=$((found + 1))
  [[ "$found" -eq 1 ]] && echo "::error::Customer identifiers found (patterns are in the CUSTOMER_DENYLIST secret):"
  echo "  (a tracked path name; withheld)"
done < <(git -c core.quotepath=off ls-files | grep -F -i -f "$patterns" || true)

while IFS= read -r hit; do
  [[ -z "$hit" ]] && continue
  path="${hit%:*}" line="${hit##*:}"
  found=$((found + 1))
  [[ "$found" -eq 1 ]] && echo "::error::Customer identifiers found (patterns are in the CUSTOMER_DENYLIST secret):"
  if denied_path "$path"; then echo "  (path withheld):$line"; else echo "  $path:$line"; fi
done < <(git -c core.quotepath=off grep -I -n -F -i -f "$patterns" -- . | awk -F: '{print $1 ":" $2}' || true)

if [[ "$found" -gt 0 ]]; then
  echo "Replace them with documentation names (example.com/.net/.org) and addresses (RFC 5737, RFC 3849)."
  status=1
fi
exit "$status"
