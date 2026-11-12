#!/usr/bin/env bash
# Self-test of check-backend-dir-name.sh: a clean tree passes, and each way of
# naming the old backend directory or module path fails it.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
check="$here/check-backend-dir-name.sh"
work="$(mktemp -d)"
trap 'find "$work" -delete 2>/dev/null || true' EXIT

tree() { # <file> <content>: a new repository holding one tracked file
  local d; d="$(mktemp -d -p "$work")"   # called in a subshell: no counter survives
  git init -q "$d"; mkdir -p "$d/$(dirname "$1")"
  printf '%s\n' "$2" >"$d/$1"
  git -C "$d" add -A
  echo "$d"
}
expect() { # <want> <name> <file> <content>
  local want="$1" name="$2" d got
  d="$(tree "$3" "$4")"
  if bash "$check" "$d" >/dev/null 2>&1; then got=pass; else got=fail; fi
  [[ "$got" == "$want" ]] || { echo "FAIL: $name: want $want, got $got"; exit 1; }
  echo "ok: $name"
}

expect pass "new directory and module"        Makefile 'cd server && go build ./...  # github.com/openctemio/openctem/server/pkg/x'
expect pass "URL path /api/v1"                x.md   'curl https://h/api/v1/assets and /api/v2/sensor/x'
expect pass "web source folder"               x.md   'see web/src/lib/api/client.ts and src/app/api/health'
expect pass "image name"                      x.yml  'image: ghcr.io/openctemio/openctem-api:v1'
expect pass "runtime path inside the image"   x.sh   'cd /opt/openctem/api && ./server'
expect pass "service name and log value"      x.yml  'service=api  compose: api'
expect pass "CHANGELOG history"               CHANGELOG.md 'moved api/internal and github.com/openctemio/openctem/api'
expect pass "marked deliberate reference"     x.sh   'git archive v0.19.0 api/migrations # rename-guard: allow'
expect fail "module path"                     x.go   'import "github.com/openctemio/openctem/api/pkg/x"'
expect fail "module path in a Dockerfile"     Dockerfile 'RUN go build -ldflags "-X github.com/openctemio/openctem/api/pkg/version.Version=1"'
expect fail "repository path in a workflow"   x.yml  'paths: ["api/internal/**"]'
expect fail "repository path in prose"        x.md   'edit api/docs/rfcs/README.md'
expect fail "glob"                            x.yml  "- 'api/**'"
expect fail "relative path"                   x.sh   'cp ../api/Makefile .'
expect fail "variable-rooted path"            x.sh   'cat "$ROOT/api/go.mod"'
expect fail "make -C"                         x.sh   'make -C api migration-new'
expect fail "cd"                              x.sh   'cd api && go test ./...'
expect fail "working-directory"               x.yml  '      working-directory: api'
expect fail "examples directory"              x.md   'see api/examples/custombuild'
expect fail "build context in a flow mapping" x.yml  '  - { name: migrations, legacy: x, context: api, file: server/Dockerfile }'
expect pass "legacy image name in a mapping"  x.yml  '  - { name: openctem-api, legacy: api, context: server, file: server/Dockerfile }'
expect fail "TREE_PATHS"                      x.yml  '          TREE_PATHS: web api Makefile go.work'
expect fail "Trivy scan-ref"                  x.yml  "          scan-ref: 'api'"
expect fail "docker build context"            x.yml  '        run: docker build -t x --target production api'
expect fail "shell default"                   x.sh   'dir="${MIGRATIONS_DIR:-api/migrations}"'
expect pass "TREE_PATHS with the new name"    x.yml  '          TREE_PATHS: web server Makefile go.work'
expect fail "anchored grep"                   x.sh   "grep '^api/.*\\.go\$'"
expect fail "Python pathlib root"             x.py   'CHANGELOG = ROOT / "api" / "CHANGELOG.md"'
expect fail "os.path.join"                    x.py   'd = os.path.join(repo, "api", "changelog.d")'
expect pass "a Go comment listing names"      x.go   '//		"api",           // key prefix'
expect fail "workflow expression root"        x.yml  '          X: ${{ github.workspace }}/api/configs/x.tmpl'
expect fail "bake context"                    x.hcl  '  context    = "api"'
expect fail "merged migration is not scanned, a doc is" x.md 'see api/docs/x.md'
expect pass "merged migration keeps its text" server/migrations/000001_x.up.sql '-- see api/internal/x.go'
expect fail "find argument"                   x.sh   "x=\"\$(find api -name '*.go' -print -quit)\""
expect fail "a tracked file under api/"       api/x.txt 'hello'

expect fail "checkout mounted in a container (/src/api)" x.sh   'OPENAPI_SPEC=/src/api/api/openapi/swagger.yaml bash gen.sh'
expect fail "checkout mounted at /workspace"  x.sh   'cat /workspace/api/go.mod'
expect pass "runtime spec path inside an image" x.sh 'COPY --from=api /app/api/openapi/swagger.yaml /opt/openctem/api/api/openapi/swagger.yaml'
expect pass "new mount path"                  x.sh   'OPENAPI_SPEC=/src/server/api/openapi/swagger.yaml bash gen.sh'
echo "all check-backend-dir-name tests passed"
