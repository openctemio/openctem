import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * The CTEM Scoping and Discovery loop as a tenant owner lives it: scope a
 * domain, put names under it in inventory, check what a scan would touch,
 * and protect a host with an exclusion. research/272 lists the invariants:
 *
 *   1. A domain entry authorizes host names only: a URL on another host
 *      whose query ends in the scoped name is treated like that other host.
 *   2. An asset found twice is one asset: case and the DNS root dot do not
 *      make a second one.
 *   3. An exclusion that can never match is refused instead of shown as
 *      protecting its target.
 *   4. An excluded host is never in what a scan would touch.
 *
 * Each run uses its own names under example.com, so it needs only an owner.
 */

type ApiResult = { status: number; body: string }

async function api(page: Page, method: string, path: string, data?: unknown): Promise<ApiResult> {
  return page.evaluate(
    async ({ method, path, data }) => {
      const r = await fetch(path, {
        method,
        headers: data === undefined ? {} : { 'Content-Type': 'application/json' },
        body: data === undefined ? undefined : JSON.stringify(data),
      })
      return { status: r.status, body: await r.text() }
    },
    { method, path, data }
  )
}

async function apiOk<T>(page: Page, method: string, path: string, data?: unknown): Promise<T> {
  const res = await api(page, method, path, data)
  expect(res.status, `${method} ${path}: ${res.status} ${res.body}`).toBeLessThan(300)
  return (res.body ? JSON.parse(res.body) : {}) as T
}

type PreviewTarget = { target: string; in_scope: number; refused_code?: string }

async function inScope(page: Page, targets: string[]): Promise<Record<string, PreviewTarget>> {
  const out = await apiOk<{ targets: PreviewTarget[] }>(
    page,
    'POST',
    '/api/v1/scans/quick/preview',
    {
      targets,
      scanner_name: 'nuclei',
    }
  )
  return Object.fromEntries(out.targets.map((t) => [t.target, t]))
}

test('scope a domain, inventory names under it, see what a scan would touch', async ({ page }) => {
  test.setTimeout(120_000)
  const stamp = Date.now().toString(36)
  const root = `ctem-${stamp}.example.com`
  const app = `app.${root}`
  const admin = `admin.${root}`

  await page.goto('/assets')
  await apiOk(page, 'POST', '/api/v1/scope/targets', {
    target_type: 'domain',
    pattern: `*.${root}`,
    description: 'e2e CTEM scope to inventory',
  })

  // 2. One asset per name, whatever its spelling.
  const created = await apiOk<{ id: string }>(page, 'POST', '/api/v1/assets', {
    name: app,
    type: 'domain',
    criticality: 'medium',
  })
  const again = await api(page, 'POST', '/api/v1/assets', {
    name: `${app.toUpperCase()}.`,
    type: 'domain',
    criticality: 'medium',
  })
  expect(
    again.status,
    `second spelling created another asset: ${again.body}`
  ).toBeGreaterThanOrEqual(400)
  const listed = await apiOk<{ data?: { name: string }[]; total?: number }>(
    page,
    'GET',
    `/api/v1/assets?search=${encodeURIComponent(root)}&per_page=50`
  )
  expect((listed.data ?? []).filter((a) => a.name === app)).toHaveLength(1)

  await page.goto(`/assets/${created.id}`)
  await expect(page.getByText(app).first()).toBeVisible({ timeout: 30_000 })

  // 1. A URL on another host with the scoped name in its query is the
  // other host, not a scoped name.
  const bypass = `http://other-${stamp}.test/?q=.${root}`
  const other = `other-${stamp}.test`
  const before = await inScope(page, [app, bypass, other])
  expect(
    before[app]?.refused_code ?? '',
    `scoped name refused: ${JSON.stringify(before[app])}`
  ).toBe('')
  expect(before[app]?.in_scope).toBeGreaterThanOrEqual(1)
  expect(before[bypass]?.in_scope, 'the scoped name in a query authorized another host').toBe(
    before[other]?.in_scope
  )

  // 3. An exclusion that can never match is refused.
  for (const bad of [
    { exclusion_type: 'ip_range', pattern: '10.0.0.9-10.0.0.1' },
    { exclusion_type: 'cidr', pattern: '10.0.0.0/33' },
    { exclusion_type: 'domain', pattern: `https://${admin}` },
  ]) {
    const res = await api(page, 'POST', '/api/v1/scope/exclusions', { ...bad, reason: 'e2e' })
    expect(
      res.status,
      `${bad.exclusion_type} ${bad.pattern} accepted: ${res.body}`
    ).toBeGreaterThanOrEqual(400)
    expect(res.status).toBeLessThan(500)
  }

  // 4. An excluded host is never in what a scan would touch.
  await apiOk(page, 'POST', '/api/v1/scope/exclusions', {
    exclusion_type: 'domain',
    pattern: admin,
    reason: 'e2e fragile host',
  })
  const after = await inScope(page, [admin, app])
  expect(
    after[admin]?.in_scope ?? 0,
    `excluded host would be scanned: ${JSON.stringify(after[admin])}`
  ).toBe(0)
  expect(after[app]?.in_scope).toBeGreaterThanOrEqual(1)
})

test('the uncovered assets list opens with its gaps, never an error', async ({ page }) => {
  await page.goto('/assets?coverage=uncovered&program_assets=exclude')
  await expect(page.getByRole('main')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByRole('alert').filter({ hasText: /error|failed/i })).toHaveCount(0)
})
