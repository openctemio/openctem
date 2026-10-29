#!/usr/bin/env bash
# ci-images-keys.sh <requested images, space-separated>
#
# Prints the content keys of the requested CI images as one JSON object
# ({"api":"<key>",...}). `allinone` implies api, web and console: it is
# assembled FROM those three. Used by build-images.yml (plan) and
# resolve-images.yml, so both agree on what a request means.
set -euo pipefail
want=" ${1:?requested images} "
case "$want" in *" allinone "*) want="$want api web console " ;; esac
keys='{}'
for i in api admin-cli web console allinone; do
  case "$want" in *" $i "*) ;; *) continue ;; esac
  k="$(bash "$(dirname "$0")/image-key.sh" "$i")"
  keys="$(jq -c --arg i "$i" --arg k "$k" '. + {($i): $k}' <<<"$keys")"
done
printf '%s\n' "$keys"
