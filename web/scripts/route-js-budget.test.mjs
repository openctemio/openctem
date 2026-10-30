// Tests for scripts/route-js-budget.mjs on a minimal fake build output.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { afterAll, describe, expect, it } from 'vitest'
import { checkBudget, measureRoutes } from './route-js-budget.mjs'

const dir = mkdtempSync(join(tmpdir(), 'route-js-budget-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

const gz = {}
const chunk = (name, n) => {
  const body = randomBytes(n).toString('hex')
  writeFileSync(join(dir, 'static', 'chunks', name), body)
  gz[name] = gzipSync(body, { level: 9 }).length
}

mkdirSync(join(dir, 'static', 'chunks'), { recursive: true })
chunk('main.js', 10 * 1024)
chunk('layout.js', 20 * 1024)
chunk('page-a.js', 50 * 1024)
chunk('lazy.js', 400 * 1024)
writeFileSync(
  join(dir, 'build-manifest.json'),
  JSON.stringify({ rootMainFiles: ['static/chunks/main.js'] })
)
const pageDir = join(dir, 'server', 'app', '(dashboard)', 'a')
mkdirSync(pageDir, { recursive: true })
const manifest = {
  entryJSFiles: {
    '[project]/src/app/layout': ['static/chunks/layout.js'],
    '[project]/src/app/(dashboard)/a/page': ['static/chunks/page-a.js'],
    // Another route's page: not part of /a.
    '[project]/src/app/(dashboard)/b/page': ['static/chunks/lazy.js'],
  },
}
writeFileSync(
  join(pageDir, 'page_client-reference-manifest.js'),
  `globalThis.__RSC_MANIFEST = globalThis.__RSC_MANIFEST || {};\n` +
    `globalThis.__RSC_MANIFEST["/(dashboard)/a/page"] = ${JSON.stringify(manifest)};\n`
)

describe('measureRoutes', () => {
  it('sums the root main files, the layouts above the page and the page, gzipped', () => {
    const { routes, median, framework } = measureRoutes(dir)
    expect(routes).toHaveLength(1)
    expect(routes[0].route).toBe('/a')
    const expected = (gz['main.js'] + gz['layout.js'] + gz['page-a.js']) / 1024
    expect(routes[0].kb).toBe(Math.round(expected))
    // The other route's chunk is not counted.
    expect(routes[0].kb).toBeLessThan(gz['lazy.js'] / 1024)
    expect(median).toBe(routes[0].kb)
    expect(framework).toBeLessThan(routes[0].kb)
  })
})

describe('checkBudget', () => {
  const result = {
    median: 300,
    routes: [
      { route: '/scans', kb: 600 },
      { route: '/a', kb: 300 },
    ],
  }
  it('passes within the default, a per-route limit and the median', () => {
    expect(
      checkBudget(result, { defaultKb: 500, medianKb: 300, routes: { '/scans': 650 } })
    ).toEqual([])
  })
  it('reports a route over the default and a median over budget', () => {
    expect(checkBudget(result, { defaultKb: 500, medianKb: 250 })).toEqual([
      'over budget: /scans 600 KB > 500 KB',
      'median over budget: 300 KB > 250 KB',
    ])
  })
})
