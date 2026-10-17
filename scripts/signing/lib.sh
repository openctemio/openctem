# Shared by init-keys.sh and rotate-keyset.sh (sourced, not run).
# Prints only public material. Private keys are written by the Go tool to
# files with mode 0600 and are never read into a shell variable or printed.

repo_root() { (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); }

# ensure_tool: call once at the top level (not in a subshell). CONTENT_BUNDLE_BIN
# names a prebuilt binary; otherwise it is built once from api/ into a
# temporary directory that is removed on exit.
ensure_tool() {
  if [ -z "${CONTENT_BUNDLE_BIN:-}" ]; then
    tool_tmp="$(mktemp -d)"
    trap 'find "$tool_tmp" -type f -delete; rmdir "$tool_tmp" 2>/dev/null || true' EXIT
    (cd "$(repo_root)/api" && GOWORK=off go build -o "$tool_tmp/content-bundle" ./cmd/content-bundle) >&2
    CONTENT_BUNDLE_BIN="$tool_tmp/content-bundle"
  fi
}

content_bundle() { "$CONTENT_BUNDLE_BIN" "$@"; }

CATALOG_KEYSET_DAYS=365
