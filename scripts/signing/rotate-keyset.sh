#!/usr/bin/env bash
# The yearly task: re-sign the content catalog key set with the catalog root
# key (new version, new 365 day validity). Run it on the machine that holds
# the root key, with the key directory made by init-keys.sh.
#
#   scripts/signing/rotate-keyset.sh [key-directory]   default ./openctem-signing-keys
#
# The online public key is read from online.pub. To add a second online key
# (rotation overlap) or drop one, list the keys: ONLINE_PUBS=<hex>,<hex> ...
#
# Prints only public material. The old key set stays in keyset.dsse.json.prev.
set -euo pipefail
umask 077
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"
ensure_tool

dir="${1:-./openctem-signing-keys}"
for f in catalog-root.key keyset.dsse.json; do
  [ -f "$dir/$f" ] || { echo "rotate-keyset: $dir/$f is missing (is the root key mounted?)" >&2; exit 1; }
done
pubs="${ONLINE_PUBS:-}"
if [ -z "$pubs" ]; then
  [ -f "$dir/online.pub" ] || { echo "rotate-keyset: $dir/online.pub is missing; set ONLINE_PUBS" >&2; exit 1; }
  pubs="$(tr -d ' \n' < "$dir/online.pub")"
fi

# The key set payload is base64 in the DSSE envelope; read its version.
old="$(tr -d '\n' < "$dir/keyset.dsse.json" | sed -n 's/.*"payload":"\([^"]*\)".*/\1/p' | base64 -d | sed -n 's/.*"version":\([0-9][0-9]*\).*/\1/p')"
case "$old" in ''|*[!0-9]*) echo "rotate-keyset: cannot read the current key set version" >&2; exit 1 ;; esac
new=$((old + 1))

tmp="$dir/keyset.dsse.json.new"
if [ -e "$tmp" ]; then echo "rotate-keyset: $tmp exists; remove it first" >&2; exit 1; fi
content_bundle keyset -root "$dir/catalog-root.key" -online "$pubs" -version "$new" \
  -days "$CATALOG_KEYSET_DAYS" -out "$tmp"
cp "$dir/keyset.dsse.json" "$dir/keyset.dsse.json.prev"
mv "$tmp" "$dir/keyset.dsse.json"
chmod 644 "$dir/keyset.dsse.json"

cat <<OUT
Key set re-signed: version $old -> $new, valid $CATALOG_KEYSET_DAYS days.
Online public key(s): $pubs

Commit and publish the new key set (public):
  $dir/keyset.dsse.json
Next reminder: in about 11 months.
OUT
