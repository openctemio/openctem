#!/usr/bin/env bash
# Refreshes pkg/emaildomain/disposable.txt from the public-domain (CC0)
# disposable-email-domains blocklist. Review the diff before committing.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${here}/pkg/emaildomain/disposable.txt"
url="https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
curl -sSfL --proto '=https' -o "${tmp}" "${url}"

# Keep only plain lower-case domain names, one per line.
if grep -qv '^[a-z0-9.-]*$' "${tmp}"; then
  echo "unexpected characters in the downloaded list; refusing" >&2
  exit 1
fi
lines="$(wc -l < "${tmp}")"
if [ "${lines}" -lt 1000 ]; then
  echo "downloaded list has only ${lines} lines; refusing" >&2
  exit 1
fi
LC_ALL=C sort -u "${tmp}" > "${out}"
echo "wrote ${out} ($(wc -l < "${out}") domains)"
