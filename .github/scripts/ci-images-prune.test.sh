#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'find "$tmp" -delete' EXIT
cat > "$tmp/v.json" <<J
[{"id":1,"name":"sha256:old","created_at":"2026-09-01T00:00:00Z"},
 {"id":2,"name":"sha256:keep","created_at":"2026-09-01T00:00:00Z"},
 {"id":3,"name":"sha256:new","created_at":"2026-10-20T00:00:00Z"},
 {"id":4,"name":"sha256:edge","created_at":"2026-10-12T00:00:00Z"}]
J
printf 'sha256:keep\n' > "$tmp/p.txt"
now="$(date -u -d 2026-10-26T00:00:00Z +%s)"
got="$(bash "$here/ci-images-prune.sh" select "$tmp/v.json" "$tmp/p.txt" 14 "$now" | tr '\n' ' ')"
[ "$got" = "1 " ] || { echo "FAIL: deleted '$got', want '1 '"; exit 1; }
: > "$tmp/none.txt"
got="$(bash "$here/ci-images-prune.sh" select "$tmp/v.json" "$tmp/none.txt" 14 "$now" | tr '\n' ' ')"
[ "$got" = "1 2 " ] || { echo "FAIL: deleted '$got', want '1 2 '"; exit 1; }
echo "ci-images-prune: ok"
