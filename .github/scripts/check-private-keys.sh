#!/usr/bin/env bash
# Fails when a file a change adds or modifies holds private key material.
#   check-private-keys.sh <base> <head>   files changed between two revisions (CI)
#   check-private-keys.sh --staged        files staged for commit (pre-commit hook)
# Flagged: a PEM/OpenSSH private key block (header followed by a key body line, so
# a placeholder or a test string that merely names the header passes), key and
# keystore files (.key .p12 .pfx .jks .keystore, id_rsa-style names), and anything
# under data/ (runtime state: the sensor CA key lived there once).
# Allowed: throwaway keys under a testdata/ directory.
# Prints only path and reason, never content.
set -euo pipefail

if [[ "${1:-}" == "--staged" ]]; then
  mode=staged
  mapfile -d '' files < <(git diff --cached --name-only -z --diff-filter=ACMR)
  show() { git show ":$1"; }
elif [[ $# -eq 2 && -n "$1" && -n "$2" && ! "$1" =~ ^0+$ ]]; then
  mode=range; head_rev="$2"
  mapfile -d '' files < <(git diff --name-only -z --diff-filter=ACMR "$1" "$2")
  show() { git show "${head_rev}:$1"; }
else
  echo "check-private-keys: no revision range (push to a new branch or schedule), skipped"
  exit 0
fi

pem='-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=:, ._-]{16,}'
bad=0
flag() { echo "private-key guard: $1: $2" >&2; bad=1; }

for f in "${files[@]}"; do
  [[ -z "$f" ]] && continue
  case "/$f" in */testdata/*) continue ;; esac
  base="${f##*/}"
  lower="${base,,}"
  case "$lower" in
    *.key|*.p12|*.pfx|*.jks|*.keystore|id_rsa|id_dsa|id_ecdsa|id_ed25519)
      flag "$f" "key or keystore file"; continue ;;
  esac
  case "$f" in data/*) flag "$f" "files under data/ are runtime state, never committed"; continue ;; esac
  if show "$f" 2>/dev/null | grep -Pzq -- "$pem"; then
    flag "$f" "contains a private key block"
  fi
done

if [[ "$bad" -ne 0 ]]; then
  {
    echo "A private key must never be committed. Remove it, rotate the key if it was ever real,"
    echo "and load it from a file path, secret store or volume at run time."
    echo "Throwaway test keys belong under a testdata/ directory."
  } >&2
  exit 1
fi
echo "private-key guard: ok ($mode, ${#files[@]} file(s))"
