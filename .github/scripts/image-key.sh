#!/usr/bin/env bash
# image-key.sh <image> [<git-rev>]
#
# Prints the content key of a CI image: the first 40 hex characters of a sha256
# over everything the image is built from. Two commits with the same key build
# the same image, so build-images.yml builds each key once and every workflow
# of the run (and of later runs) reuses it.
#
# The inputs of an image are the git tree hashes of the directories its
# Dockerfile copies (a tree hash changes when any file below it changes, and
# does not change with a commit), the Dockerfile's own path, the target and the
# build arguments. CI images take no commit-specific build argument (no
# version, commit or time), which is what makes a content key possible; the
# release build passes them and so never reuses a CI image as-is
# (api/docs/development/ci-cd.md, "Build images once").
#
#   api        the API (target production): tree api
#   web        the web app: tree web, plus tree api and the generate-contract
#              action, because the web compiles against contract files
#              generated from the Go source
#   console    the platform console (web Dockerfile, target console): as web
#   allinone   deploy/allinone + the gateway, and the keys of api, web, console
#
# Every key also covers the blobs of .github/workflows/build-images.yml and of
# this script: a change to how images are built or keyed gives every image a new
# key, so an image made by an older workflow is never reused (no manual bump).
set -euo pipefail
image="${1:?usage: image-key.sh <image> [<git-rev>]}"
rev="${2:-HEAD}"

tree() { git rev-parse --verify --quiet "${rev}:$1" || { echo "image-key: $1 does not exist at $rev" >&2; exit 2; }; }
h() { sha256sum | cut -c1-40; }

case "$image" in
  api)       parts=("api:$(tree api)" "file:api/Dockerfile" "target:production" "args:") ;;
  web | console)
    target=""; [ "$image" = console ] && target=console
    parts=("web:$(tree web)" "api:$(tree api)" "contract:$(tree .github/actions/generate-contract)"
           "file:web/Dockerfile" "target:$target" "args:") ;;
  allinone)
    parts=("allinone:$(tree deploy/allinone)" "gateway:$(tree api/deploy/gateway)"
           "api:$("$0" api "$rev")" "web:$("$0" web "$rev")" "console:$("$0" console "$rev")"
           "file:deploy/allinone/Dockerfile" "args:") ;;
  *) echo "image-key: unknown image '$image'" >&2; exit 2 ;;
esac
{ echo "workflow:$(tree .github/workflows/build-images.yml)"; echo "keyscript:$(tree .github/scripts/image-key.sh)"; echo "image:$image"; printf '%s\n' "${parts[@]}"; } | h
