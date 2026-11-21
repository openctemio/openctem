import type { Request } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { layoutDefects, seriousAxe } from '../helpers/layout'

/**
 * CI/CD setup tabs: Connections (status line, one line per configuration,
 * folded organization rules), Gate and Pull request feedback, each its own
 * tab; Connect a CI provider is the one main action, in the page header; old
 * `?tab=setup[&section=]` links land on the new tab and the address is
 * rewritten; break-glass lives on Runs. No sideways scroll at 1440 px or
 * 390 px; no serious axe violation; one read per resource, within budget.
 *
 * The seeded owner has CI write, so the header action and the refused jobs
 * read are made. No CI data is needed.
 */

/** Reads per tab: /me/bootstrap plus the tab's own resources. */
const TABS: { tab: string; name: string; budget: number }[] = [
  // bootstrap, CI settings, trust configurations, refused tokens
  { tab: 'connections', name: 'Connections', budget: 4 },
  // bootstrap, gate policies, repository names (one batch, only when a repository policy exists)
  { tab: 'gate', name: 'Gate', budget: 3 },
  // bootstrap, code-host apps
  { tab: 'feedback', name: 'Pull request feedback', budget: 2 },
]

function isApi(req: Request): boolean {
  const type = req.resourceType()
  return (type === 'fetch' || type === 'xhr') && new URL(req.url()).pathname.startsWith('/api/v1/')
}

test.describe('CI/CD settings', { tag: ['@sensors'] }, () => {
  for (const width of [1440, 390]) {
    for (const { tab, name, budget } of TABS) {
      test(`${tab}: its own tab at ${width}px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 })
        const seen: string[] = []
        page.on('request', (r) => {
          // The shell's own out-of-date-data read is not the page's (request-budget.json).
          if (isApi(r) && new URL(r.url()).pathname !== '/api/v1/threat-intel/freshness') {
            const u = new URL(r.url())
            seen.push(`${r.method()} ${u.pathname}${u.search}`)
          }
        })
        await page.goto(`/ci-cd?tab=${tab}`)
        const main = page.locator('main#content')
        await expect(main.getByRole('tab', { name, selected: true })).toBeVisible({
          timeout: 30_000,
        })
        await page.waitForLoadState('networkidle')
        // One main action, in the header; the tabs add no second one.
        await expect(main.getByRole('button', { name: 'Connect a CI provider' })).toHaveCount(1)
        await expect(main.getByRole('button', { name: /add trust/i })).toHaveCount(0)
        if (tab === 'connections')
          await expect(main.getByRole('button', { name: /organization rules/i })).toBeVisible()

        expect(await layoutDefects(page)).toEqual([])
        expect(await seriousAxe(page)).toEqual([])
        expect(seen.length, seen.join('\n')).toBeLessThanOrEqual(budget)
        expect(new Set(seen).size, seen.join('\n')).toBe(seen.length)
      })
    }
  }

  test('an old Settings link opens Connections and rewrites the address', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/ci-cd?tab=setup')
    await expect(page.getByRole('tab', { name: 'Connections', selected: true })).toBeVisible({
      timeout: 30_000,
    })
    await expect(page).toHaveURL(/[?&]tab=connections(&|$)/)
  })

  test('an old break-glass link lands on Runs with break-glass in view', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/ci-cd?tab=setup&section=break-glass')
    const heading = page.getByRole('heading', { level: 2, name: 'Break-glass' })
    await expect(heading).toBeInViewport({ timeout: 30_000 })
    await expect(page).toHaveURL(/view=runs/)
  })
})
