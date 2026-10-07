#!/usr/bin/env node
// ensure-generated.mjs — runs before dev, build, type-check, lint and test.
//
// The contract files the web console compiles against are generated, not
// committed (so pull requests cannot conflict on them):
//
//   src/lib/api/generated/api.types.ts      from api/api/openapi/swagger.yaml
//   src/config/api-route-permissions.json   from the API route table
//
// Both come from the Go source, so they need Go: `make generate` at the
// repository root writes them (or `make generate-docker`, which needs only
// Docker). This script does not run Go. It refreshes the TypeScript types when
// the spec is newer than them (that step needs only Node), and otherwise fails
// early with the fix instead of letting tsc or next report hundreds of missing
// imports.
//
// Inside an image build only the web directory is present: the files must have
// been generated before `docker build` (CI does that), and are then used as is.
import { spawnSync } from 'node:child_process'
import { existsSync, statSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const spec = process.env.OPENAPI_SPEC || resolve(web, '../api/api/openapi/swagger.yaml')
const types = resolve(web, 'src/lib/api/generated/api.types.ts')
const permissions = resolve(web, 'src/config/api-route-permissions.json')

const mtime = (p) => (existsSync(p) ? statSync(p).mtimeMs : 0)

if (existsSync(spec) && mtime(spec) > mtime(types)) {
  const r = spawnSync('bash', [resolve(web, 'scripts/generate-api-types.sh')], {
    stdio: 'inherit',
    env: { ...process.env, OPENAPI_SPEC: spec },
  })
  if (r.status !== 0) process.exit(r.status ?? 1)
}

const missing = [types, permissions].filter((p) => !existsSync(p))
if (missing.length > 0) {
  console.error(
    [
      'Generated contract files are missing:',
      ...missing.map((p) => '  ' + p.slice(web.length + 1)),
      '',
      'They are generated from the Go API, not committed. From the repository root:',
      '  make generate          (needs Go and Node)',
      '  make generate-docker   (needs only Docker)',
      'and again after pulling or changing a handler, a route or its gate.',
    ].join('\n')
  )
  process.exit(1)
}
