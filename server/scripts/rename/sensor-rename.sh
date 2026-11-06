#!/usr/bin/env bash
# =============================================================================
# sensor-rename.sh — the mechanical half of the agent → sensor rename
# (RFC-023 §9.5). Re-runnable: on a tree that is already renamed it is a no-op,
# so a branch opened before the rename catches up by rebasing and running it.
#
# What it does, in order:
#   1. type-aware rename of every Go identifier, package, import path and
#      comment (scripts/rename/sensorrename — see its package doc for why this
#      is a go/types pass rather than one `gopls rename` per object);
#   2. git mv of every .go file and config directory with "agent" in its path;
#   3. the text/template field references that reach the renamed
#      SensorTemplateData.Sensor field ({{.Agent.X}} → {{.Sensor.X}});
#   4. goimports on every changed file, then build + vet as a gate.
#
# What it does NOT do: string literals, struct tags, SQL, migrations, routes,
# permission ids, audit ids. Those are contracts; they move in reviewed,
# hand-written commits (see RFC-023 §9.5).
#
# Usage:  scripts/rename/sensor-rename.sh            (from the api repo root)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export GOWORK=off

echo "sensor-rename: renaming identifiers, comments, packages and files…"
go run ./scripts/rename/sensorrename -dir "$ROOT"

echo "sensor-rename: rewriting text/template field references…"
for f in configs/sensor-templates/*.tmpl internal/app/sensor/config_template.go; do
  [ -f "$f" ] || continue
  # Only inside template actions; the rendered text (agent_id:, AGENT_ID, the
  # ./agent binary) describes the released sensor binary and stays as is.
  perl -0pi -e '1 while s/(\{\{[^}]*?)\.Agent\b/$1.Sensor/g' "$f"
done

# git mv leaves the emptied source directories behind on disk.
find internal pkg cmd tests configs -type d -empty -delete 2>/dev/null || true

echo "sensor-rename: goimports…"
changed=$(git diff --name-only --diff-filter=AMR -- '*.go'; git ls-files --others --exclude-standard -- '*.go')
if [ -n "$changed" ]; then
  # shellcheck disable=SC2086
  if command -v goimports >/dev/null; then goimports -w $changed; else go run golang.org/x/tools/cmd/goimports -w $changed; fi
fi

echo "sensor-rename: build + vet gate…"
go build ./...
go vet ./...
echo "sensor-rename: done."
