#!/usr/bin/env bash
# Runs routes through the MVP v2 layout matrix (spec e2e/specs/75e-layout-matrix,
# or console/e2e/specs/layout-matrix with CONSOLE=1) against the e2e stack of
# this directory (compose.yml). Used by .github/workflows/layout-matrix.yml, one
# call per shard; also runs locally.
#
#   layout-matrix.sh <out-dir> <route>...
#
# Before it: the API image is present ($API_IMAGE), make-env.sh wrote .env (or
# the variables are exported), `npm ci` ran in web/, Chromium is installed and
# the app is built (`npx next build`, or `npm run build:console` for CONSOLE=1).
#
# Steps
#   1. stack: Postgres, Redis, migrations and the API (compose.yml, plus
#      console.compose.yml for the console listener with CONSOLE=1), seeded by
#      seed.sh and, for the tenant app, seed-matrix.sh. With CONSOLE=1 a
#      platform administrator is made by bootstrap-admin; its one-time password
#      is masked in GitHub Actions and never printed.
#   2. web: `next start` on 127.0.0.1 behind a small proxy that gives every
#      request its own client address (X-Forwarded-For, one random address of
#      198.18.0.0/15, RFC 2544), so the API's per-address sign-in limits do not
#      refuse one state after another; only this scratch web trusts the header
#      (TRUST_PROXY_HEADERS=true). The console runs `next start console`.
#   3. the spec, LAYOUT_MATRIX=v2 (or $LAYOUT_MATRIX), LAYOUT_WIDTHS when set.
#   4. one JSON per route in <out-dir>: {route, totals, variants}, only the
#      detector kinds with findings; screenshots and w<width>.json per route in
#      <out-dir>/<route-slug>/.
#   5. the web stops; the stack is removed unless KEEP=1.
#
# Env: CONSOLE (0|1), LAYOUT_MATRIX (v2), LAYOUT_WIDTHS (e.g. 390,1440),
#      WORKERS (4), STACK_DIR (scratch for logs and the seed output, mode 700),
#      E2E_ADMIN_PORT (8081) and E2E_CONSOLE_PORT (3001) with CONSOLE=1.
set -euo pipefail

OUT="${1:?usage: layout-matrix.sh <out-dir> <route>...}"; shift
[ $# -ge 1 ] || { echo "usage: layout-matrix.sh <out-dir> <route>..." >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"
web="$(cd "$here/../.." && pwd)"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
STACK_DIR="${STACK_DIR:-$(mktemp -d)}"
mkdir -p "$STACK_DIR"; chmod 700 "$STACK_DIR"
CONSOLE="${CONSOLE:-0}"

# shellcheck source=/dev/null
if [ -f "$here/.env" ]; then set -a; . "$here/.env"; set +a; fi
: "${E2E_DATABASE_URL:?run make-env.sh first}" "${API_IMAGE:?set API_IMAGE}"
API_PORT="${E2E_API_PORT:-8080}" WEB_PORT="${E2E_WEB_PORT:-3000}"
export E2E_ADMIN_PORT="${E2E_ADMIN_PORT:-8081}" E2E_CONSOLE_PORT="${E2E_CONSOLE_PORT:-3001}"
CONSOLE_URL="http://localhost:$E2E_CONSOLE_PORT"
mask() { if [ -n "${GITHUB_ENV:-}" ]; then echo "::add-mask::$1"; fi; }
# seed.sh prints KEY=value lines with unquoted spaces: export them line by line.
load_seed() { while IFS= read -r l; do if [ -n "$l" ]; then export "${l?}"; fi; done <"$STACK_DIR/seed.out"; }

dcf=(-f "$here/compose.yml")
if [ "$CONSOLE" = 1 ]; then dcf+=(-f "$here/console.compose.yml"); fi
dc() { docker compose "${dcf[@]}" "$@"; }

if [ "$CONSOLE" = 1 ]; then
  [ -f "$web/console/.next/BUILD_ID" ] || { echo "build the console first: npm run build:console" >&2; exit 1; }
else
  [ -f "$web/.next/BUILD_ID" ] || { echo "build the web first: npx next build" >&2; exit 1; }
fi

# 1. The stack.
echo "layout-matrix: stack"
dc up -d --wait --wait-timeout 240 api >"$STACK_DIR/compose.log" 2>&1 || { tail -20 "$STACK_DIR/compose.log" >&2; exit 1; }
( umask 077; API="http://127.0.0.1:$API_PORT" bash "$here/seed.sh" >"$STACK_DIR/seed.out" 2>"$STACK_DIR/seed.log" ) \
  || { tail -15 "$STACK_DIR/seed.log" >&2; exit 1; }
# Mask every credential the seed printed (keys ending in _PASSWORD or _TOKEN).
while IFS= read -r l; do case "${l%%=*}" in *_PASSWORD|*_TOKEN) mask "${l#*=}" ;; esac; done <"$STACK_DIR/seed.out"
if [ "$CONSOLE" = 1 ]; then
  setup="$(docker run --rm --network "${COMPOSE_NETWORK:-octe2e-ci_default}" -e DATABASE_URL="$E2E_DATABASE_URL" \
    --entrypoint /app/bootstrap-admin "$API_IMAGE" -print-secrets -no-backup \
    -email=console-matrix@openctem-test.local 2>&1)" || { echo "bootstrap-admin failed" >&2; exit 1; }
  # The one-time password is the second field of its line in the output.
  pw="$(awk '$1 == "Password:" { print $2; exit }' <<<"$setup")"; unset setup
  [ -n "$pw" ] || { echo "bootstrap-admin printed no temporary password" >&2; exit 1; }
  mask "$pw"
  export CONSOLE_E2E_BASE_URL="$CONSOLE_URL" CONSOLE_E2E_EMAIL=console-matrix@openctem-test.local \
    CONSOLE_E2E_PASSWORD="$pw" CONSOLE_E2E_ELEVATE=1
  unset pw
  rm -rf "$web/.console-e2e-auth"
else
  ( load_seed; bash "$here/seed-matrix.sh" ) 2>"$STACK_DIR/seed-matrix.log" \
    || { tail -15 "$STACK_DIR/seed-matrix.log" >&2; exit 1; }
fi

# 2. The web.
cd "$web"
if [ "$CONSOLE" = 1 ]; then
  port="$E2E_CONSOLE_PORT"
  ADMIN_API_URL="http://127.0.0.1:$E2E_ADMIN_PORT" BACKEND_API_URL="http://127.0.0.1:$API_PORT" SECURE_COOKIES=false \
    NODE_ENV=production nohup node node_modules/next/dist/bin/next start console --hostname 127.0.0.1 --port "$port" \
    >"$STACK_DIR/web.log" 2>&1 </dev/null &
  pids=("$!")
else
  inner="$((WEB_PORT + 5))"
  TRUST_PROXY_HEADERS=true BACKEND_API_URL="http://127.0.0.1:$API_PORT" SECURE_COOKIES=false NODE_ENV=production \
    nohup node node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port "$inner" \
    >"$STACK_DIR/web.log" 2>&1 </dev/null &
  pids=("$!")
  nohup node - "$WEB_PORT" "$inner" >"$STACK_DIR/proxy.log" 2>&1 <<'JS' &
const http = require('http'), [listen, inner] = process.argv.slice(2).map(Number)
const addr = () => { const n = Math.floor(Math.random() * 131070) + 1; return `198.${18 + (n >> 16)}.${(n >> 8) & 255}.${n & 255}` }
http.createServer((req, res) => {
  const headers = { ...req.headers }
  delete headers['x-real-ip']; delete headers.forwarded
  headers['x-forwarded-for'] = addr()
  const up = http.request({ host: '127.0.0.1', port: inner, method: req.method, path: req.url, headers }, (r) => {
    res.writeHead(r.statusCode, r.headers); r.pipe(res)
  })
  up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end() })
  req.pipe(up)
}).listen(listen, '127.0.0.1')
JS
  pids+=("$!"); port="$WEB_PORT"
fi
cleanup() {
  kill "${pids[@]}" 2>/dev/null || true
  rm -rf "$web/.console-e2e-auth"
  if [ "${KEEP:-0}" != 1 ]; then dc down -v >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
ready=0
for _ in $(seq 90); do
  if curl -fsS --max-time 10 "http://127.0.0.1:$port/login" 2>/dev/null | grep -q '</html>'; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || { echo "the web did not start" >&2; tail -20 "$STACK_DIR/web.log" >&2; exit 1; }

# 3. The matrix.
routes="$(IFS=,; echo "$*")"
if [ "$CONSOLE" = 1 ]; then
  spec=(-c playwright.console.config.ts console/e2e/specs/layout-matrix.spec.ts)
else
  load_seed
  spec=(e2e/specs/75e-layout-matrix.spec.ts)
fi
echo "layout-matrix: $routes"
CI=true E2E_BASE_URL="http://localhost:$WEB_PORT" E2E_API_BASE_URL="http://localhost:$API_PORT" \
  LAYOUT_MATRIX="${LAYOUT_MATRIX:-v2}" LAYOUT_ROUTES="$routes" LAYOUT_SWEEP_OUT="$OUT" \
  npx playwright test "${spec[@]}" --workers="${WORKERS:-4}" --retries=0 --reporter=line \
  >"$OUT/run.log" 2>&1 || true
tail -3 "$OUT/run.log"

# 4. One JSON per route: { route, totals, variants: { "<tag>": { "<kind>": [lines] } } }.
node - "$OUT" "$@" <<'JS'
const fs = require('fs'), path = require('path')
const [out, ...routes] = process.argv.slice(2)
const slug = (r) => r.replace(/\W+/g, '-').replace(/^-|-$/g, '') || 'home'
for (const r of routes) {
  const dir = path.join(out, slug(r))
  if (!fs.existsSync(dir)) { console.log(`${r}: no output`); continue }
  const merged = {}, totals = {}
  for (const f of fs.readdirSync(dir).filter((f) => /^w\d+\.json$/.test(f))) {
    for (const [tag, found] of Object.entries(JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')))) {
      if (typeof found === 'string') { merged[tag] = found; continue }
      const hit = Object.fromEntries(Object.entries(found).filter(([, v]) => v.length))
      for (const [k, v] of Object.entries(hit)) totals[k] = (totals[k] ?? 0) + v.length
      merged[tag] = hit
    }
  }
  fs.writeFileSync(path.join(out, `${slug(r)}.json`), JSON.stringify({ route: r, totals, variants: merged }, null, 1))
  console.log(`${r}: ${JSON.stringify(totals)}`)
}
JS
