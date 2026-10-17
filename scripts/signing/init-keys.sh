#!/usr/bin/env bash
# Creates the OpenCTEM signing keys. Run it ONCE, by the owner, on the
# owner's own machine (not in CI, not on a shared host).
#
#   scripts/signing/init-keys.sh [key-directory]      default ./openctem-signing-keys
#
# It creates, in the directory (mode 0700):
#   catalog-root.key   the content catalog ROOT key (0600). Keep it OFFLINE.
#   online.key         the RELEASE FEED online key (0600): signs only the
#                      release feed. Its copy lives in a GitHub secret.
#   online.pub         its public key (hex), public.
#   catalog-online.key the CATALOG online key (0600): signs only the content
#                      catalog documents, never the release feed. Its copy
#                      lives in a second GitHub secret (own environment).
#   catalog-online.pub its public key (hex), public.
#   keyset.dsse.json   the catalog key set (lists catalog-online.pub only),
#                      signed by the root, valid 365 days.
#
# It prints ONLY public material (key ids, public key, file paths, commands).
# It refuses to overwrite existing keys. See api/docs/architecture/signing-keys.md.
set -euo pipefail
umask 077
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"
ensure_tool

dir="${1:-./openctem-signing-keys}"
for f in catalog-root.key online.key online.pub catalog-online.key catalog-online.pub keyset.dsse.json; do
  if [ -e "$dir/$f" ]; then
    echo "init-keys: $dir/$f already exists; refusing to overwrite existing keys." >&2
    echo "Use scripts/signing/rotate-keyset.sh for the yearly re-sign." >&2
    exit 1
  fi
done
mkdir -p "$dir"
chmod 700 "$dir"

root_out="$(content_bundle keygen -out "$dir/catalog-root.key")"
online_out="$(content_bundle keygen -out "$dir/online.key")"
catalog_out="$(content_bundle keygen -out "$dir/catalog-online.key")"
root_id="$(printf '%s\n' "$root_out" | sed -n 's/^key id: *//p')"
online_id="$(printf '%s\n' "$online_out" | sed -n 's/^key id: *//p')"
online_pub="$(printf '%s\n' "$online_out" | sed -n 's/^public key: *//p')"
catalog_id="$(printf '%s\n' "$catalog_out" | sed -n 's/^key id: *//p')"
catalog_pub="$(printf '%s\n' "$catalog_out" | sed -n 's/^public key: *//p')"
if [ -z "$root_id" ] || [ -z "$online_pub" ] || [ -z "$catalog_pub" ]; then
  echo "init-keys: the key tool printed no key id or public key" >&2
  exit 1
fi
printf '%s\n' "$online_pub" > "$dir/online.pub"
chmod 644 "$dir/online.pub"
printf '%s\n' "$catalog_pub" > "$dir/catalog-online.pub"
chmod 644 "$dir/catalog-online.pub"

# The catalog key set lists the catalog online key only: the release feed key
# is a different key and is never listed.
content_bundle keyset -root "$dir/catalog-root.key" -online "$catalog_pub" -version 1 \
  -days "$CATALOG_KEYSET_DAYS" -out "$dir/keyset.dsse.json"
chmod 644 "$dir/keyset.dsse.json"

cat <<OUT

Keys created in $dir (private keys: mode 0600, never printed).

Public material
  catalog root key id : $root_id
  release feed key id : $online_id
  release feed public : $online_pub
  catalog online id   : $catalog_id
  catalog online pub  : $catalog_pub

1. Pin them in the code (one reviewed pull request):
     api/pkg/releasefeed/ PinnedKeys   add  "$online_pub"   (release feed key)
     api/pkg/contentpkg/  PinnedRoots  add  "$root_id"
   and commit the signed catalog key set (public):
     $dir/keyset.dsse.json

2. Store each online key as its own secret in its own restricted GitHub
   environment (read from the file, not echoed). The two keys never share a
   secret or an environment: a key that signs information must not ship code.
     gh secret set RELEASE_FEED_SIGNING_KEY --env release-feed --repo openctemio/openctem < "$dir/online.key"
     gh secret set CONTENT_CATALOG_SIGNING_KEY --env content-catalog --repo openctemio/openctem < "$dir/catalog-online.key"
   Restrict the content-catalog environment to main and v* tags, like release-feed.

3. Store the ROOT key offline: move $dir/catalog-root.key to an encrypted
   USB stick or a password manager's secure attachment, keep a second copy in
   another place, then delete it from this machine. You need it once a year
   (scripts/signing/rotate-keyset.sh) and to rotate or revoke the online key.
   Keep catalog-online.pub next to it. The online key files may also be
   deleted from this machine once the secrets are set, but keep one encrypted
   backup of each.

The key set expires in $CATALOG_KEYSET_DAYS days: put a yearly reminder in your calendar.
OUT
