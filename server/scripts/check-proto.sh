#!/usr/bin/env bash
# Sensor protocol v3 gates (docs/rfcs/RFC-059-sensor-transport-v3.md):
#   1. buf lint (STANDARD rules) on api/proto;
#   2. buf breaking against the base branch (FILE rules), when the base has
#      the module; a breaking change needs a new package (openctem.sensor.v4);
#   3. the committed Go code (api/pkg/sensorproto/v3) is what buf generate
#      writes from the committed .proto.
#
# Tools are pinned: buf from its release (checksum verified), the Go plugins
# with go install at fixed versions.
#
# Usage (from api/): scripts/check-proto.sh [base-ref]   (default origin/develop)
#                    scripts/check-proto.sh --generate   (regenerate only)
set -euo pipefail

BUF_VERSION=1.73.0
BUF_SHA256=8f2986298ad08f0cc1bf999b9797b7c383adf32d7edf0f73d6f1e1a701baeac1
PROTOC_GEN_GO_VERSION=v1.36.12
PROTOC_GEN_CONNECT_GO_VERSION=v1.21.0

cd "$(dirname "$0")/.."
api_dir="$(pwd)"
tools="${PROTO_TOOLS_DIR:-$api_dir/.proto-tools}"
mkdir -p "$tools"
export PATH="$tools:$PATH"

if ! "$tools/buf" --version 2>/dev/null | grep -qx "$BUF_VERSION"; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
      curl -fsSL -o "$tools/buf.tmp" "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-x86_64"
      echo "${BUF_SHA256}  $tools/buf.tmp" | sha256sum -c - >/dev/null
      chmod +x "$tools/buf.tmp"
      mv "$tools/buf.tmp" "$tools/buf"
      ;;
    *)
      GOBIN="$tools" GOWORK=off go install "github.com/bufbuild/buf/cmd/buf@v${BUF_VERSION}"
      ;;
  esac
fi
GOBIN="$tools" GOWORK=off go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
GOBIN="$tools" GOWORK=off go install "connectrpc.com/connect/cmd/protoc-gen-connect-go@${PROTOC_GEN_CONNECT_GO_VERSION}"

if [ "${1:-}" = "--generate" ]; then
  (cd proto && buf generate)
  echo "generated api/pkg/sensorproto/v3"
  exit 0
fi

base="${1:-origin/develop}"

echo "== buf lint"
(cd proto && buf lint)

echo "== buf breaking against $base"
if git cat-file -e "$base:api/proto/buf.yaml" 2>/dev/null; then
  root="$(git rev-parse --show-toplevel)"
  (cd proto && buf breaking --against "$root/.git#ref=$base,subdir=api/proto")
else
  echo "base has no api/proto module yet; nothing to compare"
fi

echo "== generated code is current"
out="$(mktemp -d)"
trap 'find "$out" -delete' EXIT
sed "s#out: \.\.#out: $out#" proto/buf.gen.yaml > "$out/buf.gen.yaml"
(cd proto && buf generate --template "$out/buf.gen.yaml")
if ! diff -r "$out/pkg/sensorproto/v3" pkg/sensorproto/v3; then
  echo "::error::api/pkg/sensorproto/v3 is stale: run make proto and commit the result"
  exit 1
fi
echo "proto checks passed"
