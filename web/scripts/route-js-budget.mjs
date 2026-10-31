#!/usr/bin/env node
// route-js-budget.mjs - first-load JavaScript per page route of a production
// build, gzipped, checked against scripts/route-js-budget.json.
//
// First-load JS of a route = the root main files (framework runtime) plus the
// client chunks of the page and of every layout above it, as listed in the
// route's page_client-reference-manifest.js. Chunks loaded later (next/dynamic,
// import(), the active locale's message catalog) are not counted: keeping heavy
// code in those is the point.
//
// Usage (from web/, after `next build`):
//   node scripts/route-js-budget.mjs                  table + budget check
//   node scripts/route-js-budget.mjs --json out.json  also write the numbers
//   node scripts/route-js-budget.mjs --top 30         list the 30 largest routes
// Options: --next-dir <dir> (default .next), --budget <file>.
// Exit 1 when a route or the median is over budget, 2 on a missing build.
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { gzipSync } from 'node:zlib'
import vm from 'node:vm'

const APP = '[project]/src/app'

function manifestFiles(dir, out = []) {
  if (!existsSync(dir)) return out
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) manifestFiles(path, out)
    else if (name === 'page_client-reference-manifest.js') out.push(path)
  }
  return out
}

/** Gzipped first-load JS per page route of the build in `nextDir`. */
export function measureRoutes(nextDir) {
  const buildManifest = JSON.parse(readFileSync(join(nextDir, 'build-manifest.json'), 'utf8'))
  const norm = (f) => f.replace(/^\/_next\//, '')
  const rootMain = (buildManifest.rootMainFiles ?? []).map(norm)
  const sizes = new Map()
  const gz = (file) => {
    if (!sizes.has(file)) {
      const path = join(nextDir, file)
      sizes.set(file, existsSync(path) ? gzipSync(readFileSync(path), { level: 9 }).length : 0)
    }
    return sizes.get(file)
  }

  const routes = []
  for (const file of manifestFiles(join(nextDir, 'server', 'app'))) {
    // The manifest is a script that assigns globalThis.__RSC_MANIFEST.
    const sandbox = {}
    sandbox.globalThis = sandbox
    vm.runInNewContext(readFileSync(file, 'utf8'), sandbox)
    for (const [routeId, manifest] of Object.entries(sandbox.__RSC_MANIFEST ?? {})) {
      if (!routeId.endsWith('/page')) continue
      const parts = routeId.slice(0, -'/page'.length).split('/').filter(Boolean)
      // The page and every layout above it.
      const owners = new Set([`${APP}/${[...parts, 'page'].join('/')}`, `${APP}/layout`])
      for (let i = 1; i <= parts.length; i++) {
        owners.add(`${APP}/${parts.slice(0, i).join('/')}/layout`)
      }
      const files = new Set(rootMain)
      for (const [owner, chunks] of Object.entries(manifest.entryJSFiles ?? {})) {
        // The console app builds from console/src/app.
        const key = owner.replace(/^\[project\]\/(console\/)?src\/app/, APP)
        if (owners.has(key)) for (const c of chunks) files.add(norm(c))
      }
      const js = [...files].filter((f) => f.endsWith('.js'))
      routes.push({
        route: '/' + parts.filter((p) => !/^\(.*\)$/.test(p)).join('/'),
        kb: Math.round(js.reduce((n, f) => n + gz(f), 0) / 1024),
      })
    }
  }
  routes.sort((a, b) => b.kb - a.kb || a.route.localeCompare(b.route))
  const sorted = routes.map((r) => r.kb).sort((a, b) => a - b)
  return {
    routes,
    median: sorted.length ? sorted[Math.floor(sorted.length / 2)] : 0,
    framework: Math.round(rootMain.reduce((n, f) => n + gz(f), 0) / 1024),
  }
}

/** Budget violations as human-readable lines (empty when within budget). */
export function checkBudget({ routes, median }, budget) {
  const limit = (route) => budget.routes?.[route] ?? budget.defaultKb ?? Infinity
  const problems = routes
    .filter((r) => r.kb > limit(r.route))
    .map((r) => `over budget: ${r.route} ${r.kb} KB > ${limit(r.route)} KB`)
  if (budget.medianKb != null && median > budget.medianKb) {
    problems.push(`median over budget: ${median} KB > ${budget.medianKb} KB`)
  }
  return problems
}

function main(argv) {
  const here = dirname(fileURLToPath(import.meta.url))
  const opt = (name, def) => {
    const i = argv.indexOf(name)
    return i >= 0 ? argv[i + 1] : def
  }
  const nextDir = resolve(opt('--next-dir', '.next'))
  const budgetFile = resolve(opt('--budget', join(here, 'route-js-budget.json')))
  const jsonOut = opt('--json', '')
  const top = Number(opt('--top', '15'))
  if (!existsSync(join(nextDir, 'build-manifest.json'))) {
    console.error(`route-js-budget: ${nextDir} has no build-manifest.json; run next build first`)
    return 2
  }
  const result = measureRoutes(nextDir)
  if (!result.routes.length) {
    console.error(`route-js-budget: no page manifests under ${nextDir}/server/app`)
    return 2
  }
  console.log(
    `routes: ${result.routes.length}, median first-load JS ${result.median} KB gzip, ` +
      `framework ${result.framework} KB`
  )
  for (const r of result.routes.slice(0, top)) {
    console.log(`  ${String(r.kb).padStart(6)} KB  ${r.route}`)
  }
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(result, null, 2) + '\n')
  const budget = JSON.parse(readFileSync(budgetFile, 'utf8'))
  const problems = checkBudget(result, budget)
  if (problems.length) {
    for (const p of problems) console.error(p)
    console.error(
      'Load heavy code where it is used (next/dynamic, import()), or raise the number in ' +
        'scripts/route-js-budget.json and say why in the pull request.'
    )
    return 1
  }
  console.log(
    `within budget: every route <= ${budget.defaultKb} KB, median <= ${budget.medianKb} KB`
  )
  return 0
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)))
}
