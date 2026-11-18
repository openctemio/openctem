import fs from 'fs'
import path from 'path'
import type { Page, Request } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import budget from '../request-budget.json'

/**
 * Request budget (research/81): what a hard load of every dashboard page asks
 * the API for.
 *
 *   1. Every page sends at most its budget of API requests (request-budget.json;
 *      defaultMax when a page is not listed), and never the same request twice.
 *   2. The session (profile, organizations, badge counts, organization policy)
 *      comes from ONE /me/bootstrap: the endpoints it replaces are never asked.
 *   3. The findings page loads one stats response, and switching the state tab
 *      sends no stats request.
 *
 * Pages are found from the app tree, so a new page is covered the day it
 * lands: every static route under (dashboard), and every page with an id in
 * its path ([id], [cve]), which request-budget.json must list under
 * dynamicRoutes with the list that gives a sample id (research/335: the
 * finding page sent about twenty requests and no gate counted them).
 */

const APP_DIR = path.resolve(__dirname, '../../src/app/(dashboard)')
// The account area (/account/*) lives in its own route group with its own shell.
const ACCOUNT_DIR = path.resolve(__dirname, '../../src/app/(account)')
const QUIET_MS = 1200
const CAP_MS = 20_000

function dashboardRoutes(dir = APP_DIR, prefix = '', dynamic = false): string[] {
  const out: string[] = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) {
      if (entry.name === 'page.tsx' && dynamic === prefix.includes('[')) out.push(prefix || '/')
      continue
    }
    if (entry.name === '__tests__') continue
    if (entry.name.startsWith('[') && !dynamic) continue
    // Route groups, e.g. (discovery), are not part of the URL.
    const segment = entry.name.startsWith('(') ? '' : `/${entry.name}`
    out.push(...dashboardRoutes(path.join(dir, entry.name), prefix + segment, dynamic))
  }
  return out.sort()
}

/** A call of the app to its API (same-origin /api/v1, through the web proxy). */
function isApi(req: Request): boolean {
  const type = req.resourceType()
  return (type === 'fetch' || type === 'xhr') && new URL(req.url()).pathname.startsWith('/api/v1/')
}

/** Loads `route` and returns the API requests (method + path?query) until quiet. */
async function apiRequestsOfLoad(page: Page, route: string): Promise<string[]> {
  const seen: string[] = []
  let pending = 0
  let last = Date.now()
  const onRequest = (req: Request) => {
    if (!isApi(req)) return
    const url = new URL(req.url())
    seen.push(`${req.method()} ${url.pathname}${url.search}`)
    pending++
    last = Date.now()
  }
  const onDone = (req: Request) => {
    if (!isApi(req)) return
    pending = Math.max(0, pending - 1)
    last = Date.now()
  }
  page.on('request', onRequest)
  page.on('requestfinished', onDone)
  page.on('requestfailed', onDone)
  try {
    await page.goto(route, { waitUntil: 'load' })
    // The app's requests start after hydration, which can be after `load`:
    // count quiet time from here, not from before the navigation.
    last = Math.max(last, Date.now())
    const capAt = Date.now() + CAP_MS
    while (Date.now() < capAt && (pending > 0 || Date.now() - last < QUIET_MS)) {
      await page.waitForTimeout(100)
    }
  } finally {
    page.off('request', onRequest)
    page.off('requestfinished', onDone)
    page.off('requestfailed', onDone)
  }
  return seen
}

/** A page of the account area (/account/*), which has its own shell and session. */
function isAccountRoute(route: string): boolean {
  return route === '/account' || route.startsWith('/account/')
}

/** Adds the budget, duplicate and session-read problems of one load. */
function checkLoad(route: string, max: number, requests: string[], problems: string[]): void {
  if (requests.length > max) {
    problems.push(
      `${route}: ${requests.length} API requests (budget ${max})\n    ${requests.join('\n    ')}`
    )
  }
  const counts = new Map<string, number>()
  for (const r of requests) counts.set(r, (counts.get(r) ?? 0) + 1)
  for (const [r, n] of counts) if (n > 1) problems.push(`${route}: ${r} sent ${n} times`)

  const bootstraps = requests.filter((r) => r.startsWith('GET /api/v1/me/bootstrap')).length
  if (isAccountRoute(route)) {
    // The account area runs on the account session, outside any organization:
    // it never reads the organization bootstrap, and the account's own reads
    // (/users/me, /users/me/tenants, ownership invitations) are asked directly.
    if (bootstraps !== 0) problems.push(`${route}: /me/bootstrap sent ${bootstraps} times (want 0)`)
    return
  }
  if (bootstraps !== 1) problems.push(`${route}: /me/bootstrap sent ${bootstraps} times (want 1)`)
  const pageUses = (budget.pageUsesSessionEndpoint as Record<string, string[]>)[route] ?? []
  for (const r of requests) {
    const target = r.replace(/^GET /, '')
    if (budget.sessionOnlyFromBootstrap.includes(target) && !pageUses.includes(target)) {
      problems.push(`${route}: ${target} is carried by /me/bootstrap and must not be asked`)
    }
  }
}

/**
 * A page with an id is loaded for one sample item: the first item `sample`
 * (an API list) returns, or the first link to such a page on the list page
 * `from`. `max` is its budget.
 */
type DynamicBudget = { sample?: string; field?: string; from?: string; max: number }
const dynamicBudgets =
  (budget as { dynamicRoutes?: Record<string, DynamicBudget> }).dynamicRoutes ?? {}

/** The page of a dynamic route for one sample item, or null when there is none. */
async function sampleRoute(page: Page, route: string, b: DynamicBudget): Promise<string | null> {
  if (b.sample) {
    const res = await page.request.get(b.sample)
    if (!res.ok()) return null
    const body = (await res.json()) as
      { data?: Record<string, unknown>[] } | Record<string, unknown>[]
    const first = (Array.isArray(body) ? body : (body.data ?? []))[0]
    const value = first?.[b.field ?? 'id']
    if (typeof value !== 'string' || !value) return null
    return route.replace(/\[[^\]]+\]/, encodeURIComponent(value))
  }
  if (!b.from) return null
  await apiRequestsOfLoad(page, b.from)
  const pattern = new RegExp('^' + route.replace(/\[[^\]]+\]/g, '[^/?#]+') + '$')
  const hrefs = await page
    .locator('main a[href]')
    .evaluateAll((as) => as.map((a) => new URL((a as HTMLAnchorElement).href).pathname))
  return hrefs.find((h) => pattern.test(h)) ?? null
}

const routeBudgets = budget.routes as Record<string, number>

// The pages are checked in PARTS tests of every PARTS-th page each, so the
// suite's sharding spreads them over the CI shards instead of one test taking
// minutes on one shard while the others idle.
const PARTS = 4

for (let part = 0; part < PARTS; part++) {
  test(
    `every dashboard page stays within its request budget (part ${part + 1}/${PARTS})`,
    { tag: ['@budget'] },
    async ({ page }) => {
      test.setTimeout(8 * 60_000)
      const all = [...dashboardRoutes(), ...dashboardRoutes(ACCOUNT_DIR)].sort()
      expect(all.length).toBeGreaterThan(50)
      // Budget entries must name real pages, so a removed page does not keep a
      // stale allowance.
      for (const listed of Object.keys(routeBudgets)) expect(all, listed).toContain(listed)
      // E2E_BUDGET_ROUTES="/,/findings" checks only those pages (a local run
      // while changing one page); CI leaves it unset and checks every page.
      const only = (process.env.E2E_BUDGET_ROUTES ?? '').split(',').filter(Boolean)
      const selected = only.length ? all.filter((r) => only.includes(r)) : all
      expect(selected.length).toBeGreaterThan(0)
      const routes = selected.filter((_, i) => i % PARTS === part)
      test.skip(routes.length === 0, 'no page of the selection falls in this part')

      // A person's first visit to / stores their copy of the Overview template
      // (one write, once); the budget is for every load after that.
      await apiRequestsOfLoad(page, '/')

      const problems: string[] = []
      for (const route of routes) {
        const requests = await apiRequestsOfLoad(page, route)
        checkLoad(route, routeBudgets[route] ?? budget.defaultMax, requests, problems)
      }
      expect(problems, problems.join('\n')).toEqual([])
    }
  )
}

test(
  'every page with an id in its path stays within its request budget',
  { tag: ['@budget'] },
  async ({ page }) => {
    test.setTimeout(8 * 60_000)
    const all = dashboardRoutes(APP_DIR, '', true)
    expect(all.length).toBeGreaterThan(5)
    // Every such page has an entry, and every entry names a real page.
    expect(Object.keys(dynamicBudgets).sort()).toEqual(all)
    const only = (process.env.E2E_BUDGET_ROUTES ?? '').split(',').filter(Boolean)
    const selected = only.length ? all.filter((r) => only.includes(r)) : all
    test.skip(selected.length === 0, 'no page with an id in the selection')

    await apiRequestsOfLoad(page, '/')
    const problems: string[] = []
    let measured = 0
    for (const route of selected) {
      const url = await sampleRoute(page, route, dynamicBudgets[route])
      // The seed has nothing of this kind: nothing to load.
      if (!url) continue
      measured++
      const requests = await apiRequestsOfLoad(page, url)
      if (process.env.E2E_BUDGET_REPORT) console.log(`budget ${route} ${requests.length}`)
      checkLoad(route, dynamicBudgets[route].max, requests, problems)
    }
    expect(measured, 'the seed gives a sample for at least the finding page').toBeGreaterThan(0)
    expect(problems, problems.join('\n')).toEqual([])
  }
)

test(
  'findings: one stats and one quick-views response, and a view switch sends no stats',
  { tag: ['@budget'] },
  async ({ page }) => {
    const requests = await apiRequestsOfLoad(page, '/findings')
    const stats = requests.filter((r) => r.includes('/api/v1/findings/stats'))
    expect(stats, requests.join('\n')).toHaveLength(1)
    const quickViews = requests.filter((r) => r.includes('/api/v1/findings/quick-views'))
    expect(quickViews, requests.join('\n')).toHaveLength(1)
    // The source catalog loads when the Source filter opens, not with the page.
    expect(requests.filter((r) => r.includes('/api/v1/finding-sources'))).toHaveLength(0)

    const afterSwitch: string[] = []
    const listen = (req: Request) => {
      if (req.url().includes('/api/v1/findings/stats')) afterSwitch.push(req.url())
    }
    page.on('request', listen)
    await page.getByRole('link', { name: /^Closed/ }).click()
    await expect(page).toHaveURL(/state=closed/)
    await page.waitForTimeout(QUIET_MS)
    page.off('request', listen)
    expect(afterSwitch).toEqual([])
  }
)

test(
  'findings, an empty practice: one more stats response for its first run, none on a view switch',
  { tag: ['@budget'] },
  async ({ page }) => {
    // The seed has no runtime findings: the empty list asks once for the
    // practice's total in every state (its first run or "No findings match").
    const requests = await apiRequestsOfLoad(page, '/findings?practice=runtime')
    const stats = requests.filter((r) => r.includes('/api/v1/findings/stats'))
    expect(stats, requests.join('\n')).toHaveLength(2)
    expect(
      stats.filter((r) => r.includes('practice=runtime')),
      requests.join('\n')
    ).toHaveLength(1)
    expect(requests.filter((r) => r.includes('/api/v1/findings/quick-views'))).toHaveLength(1)

    const afterSwitch: string[] = []
    const listen = (req: Request) => {
      if (req.url().includes('/api/v1/findings/stats')) afterSwitch.push(req.url())
    }
    page.on('request', listen)
    await page.getByRole('link', { name: /^Closed/ }).click()
    await expect(page).toHaveURL(/state=closed/)
    await page.waitForTimeout(QUIET_MS)
    page.off('request', listen)
    expect(afterSwitch).toEqual([])
  }
)

test(
  'settings general: the dashboard data section reads its state only when it comes into view',
  { tag: ['@budget'] },
  async ({ page }) => {
    // The section is below the fold: the load stays within the default budget
    // without its read, and scrolling to it (or a link to it) loads it.
    await page.setViewportSize({ width: 1280, height: 720 })
    const dashboardData = (r: string) => r.startsWith('GET /api/v1/dashboard-data')
    const load = await apiRequestsOfLoad(page, '/settings/general')
    expect(load.length, load.join('\n')).toBeLessThanOrEqual(budget.defaultMax)
    expect(load.filter(dashboardData), load.join('\n')).toEqual([])

    const read = page.waitForRequest(
      (req) => isApi(req) && req.url().includes('/api/v1/dashboard-data')
    )
    await page.getByRole('heading', { name: 'Dashboard data' }).scrollIntoViewIfNeeded()
    await read
    // Let that read finish (the API answers the path with a redirect) before the next load.
    await page.waitForTimeout(QUIET_MS)

    // The old tab link lands on the section with its state loaded.
    const deep = await apiRequestsOfLoad(page, '/settings/general?tab=dashboard-data')
    // One read of the section's state (the path the page asks for, not the redirect it follows).
    expect(
      deep.filter((r) => r === 'GET /api/v1/dashboard-data/'),
      deep.join('\n')
    ).toHaveLength(1)
    await expect(page.getByRole('button', { name: 'Rebuild dashboard data' })).toBeVisible()
  }
)

test('findings: Refresh sends each request once', { tag: ['@budget'] }, async ({ page }) => {
  await apiRequestsOfLoad(page, '/findings')
  const seen: string[] = []
  const listen = (req: Request) => {
    if (isApi(req) && req.method() === 'GET')
      seen.push(new URL(req.url()).pathname + new URL(req.url()).search)
  }
  page.on('request', listen)
  await page.getByRole('button', { name: 'Refresh' }).click()
  await page.waitForTimeout(QUIET_MS)
  page.off('request', listen)
  const counts = new Map<string, number>()
  for (const r of seen) counts.set(r, (counts.get(r) ?? 0) + 1)
  expect([...counts].filter(([, n]) => n > 1)).toEqual([])
})
