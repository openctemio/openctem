#!/bin/sh
# stable-swagger-names.sh <swagger.yaml>: swag names definitions after the Go
# package path. The published names keep the module's pre-rename spelling
# (openctem/api), so the backend directory rename to server/ changed no schema
# name of the contract. Used by `make swagger` and server/Dockerfile (one step,
# so the two cannot drift).
#
# POSIX sh and a redirect plus mv instead of `sed -i` or perl: it runs unchanged
# in the golang alpine image (BusyBox, no perl), on GNU and on BSD.
set -eu
f="${1:?usage: stable-swagger-names.sh <swagger.yaml>}"
sed 's/github_com_openctemio_openctem_server_/github_com_openctemio_openctem_api_/g' "$f" >"$f.tmp"
mv "$f.tmp" "$f"
