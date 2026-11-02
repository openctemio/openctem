import type { Request } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { layoutDefects, seriousAxe } from '../helpers/layout'

/**
 * CI/CD Settings (/ci-cd?tab=setup): every section on one page, in setup
 * order, with no section picker; a link that names a section scrolls to it;
 * Connect a pipeline sits in the page header; no sideways scroll at 1440 px
 * or 390 px; no serious axe violation; one read per resource.
 *
 * The seeded owner has CI write, so the header action and the refused
 * pipelines block are shown. No CI data is needed.
 */

const SECTIONS = ['Trusted pipelines', 'Gate policy', 'Pull request feedback', 'Break-glass']
/** /me/bootstrap plus the settings, trust, refusals, gate policies, code-host apps and overrides. */
const BUDGET = 7

function isApi(req: Request): boolean {
  const type = req.resourceType()
  return (type === 'fetch' || type === 'xhr') && new URL(req.url()).pathname.startsWith('/api/v1/')
}

test.describe('CI/CD settings', { tag: ['@sensors'] }, () => {
  for (const width of [1440, 390]) {
    test(`settings: one page of sections at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      const seen: string[] = []
      page.on('request', (r) => {
        if (isApi(r)) {
          const u = new URL(r.url())
          seen.push(`${r.method()} ${u.pathname}${u.search}`)
        }
      })
      await page.goto('/ci-cd?tab=setup')
      const main = page.locator('main#content')
      await expect(main.getByRole('heading', { level: 2, name: 'Break-glass' })).toBeVisible({
        timeout: 30_000,
      })
      await page.waitForLoadState('networkidle')
      expect(await main.getByRole('heading', { level: 2 }).allTextContents()).toEqual(SECTIONS)
      await expect(main.getByRole('button', { name: /^Section:/ })).toHaveCount(0)
      await expect(main.getByRole('button', { name: 'Connect a pipeline' }).first()).toBeVisible()

      expect(await layoutDefects(page)).toEqual([])
      expect(await seriousAxe(page)).toEqual([])
      expect(seen.length, seen.join('\n')).toBeLessThanOrEqual(BUDGET)
      expect(new Set(seen).size, seen.join('\n')).toBe(seen.length)
    })
  }

  test('settings: a link to a section scrolls it into view', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/ci-cd?tab=setup&section=break-glass')
    const heading = page.getByRole('heading', { level: 2, name: 'Break-glass' })
    await expect(heading).toBeInViewport({ timeout: 30_000 })
  })
})
