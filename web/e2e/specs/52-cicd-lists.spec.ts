import type { Request } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { layoutDefects, seriousAxe } from '../helpers/layout'

/**
 * CI/CD lists: Pipelines (/ci-cd) and Runs (/ci-cd?view=runs) at 1440 px and
 * 390 px. No sideways scroll (the runs list is the shared table, so a phone
 * gets cards, not a clipped table), no serious axe violation, and each tab
 * loads within its request budget with no request sent twice:
 *   Pipelines: /me/bootstrap, the pipeline page, the refused pipelines
 *     (the notice above the list, CI writers only);
 *   Runs: /me/bootstrap and the run page.
 * The seed has no CI data: the empty states are what is measured.
 */

const PAGES: Array<{ path: string; budget: number }> = [
  { path: '/ci-cd', budget: 3 },
  { path: '/ci-cd?view=runs', budget: 2 },
]

function isApi(req: Request): boolean {
  const type = req.resourceType()
  return (type === 'fetch' || type === 'xhr') && new URL(req.url()).pathname.startsWith('/api/v1/')
}

test.describe('CI/CD lists', { tag: ['@sensors'] }, () => {
  for (const width of [1440, 390]) {
    for (const { path, budget } of PAGES) {
      test(`${path} at ${width}px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 })
        const seen: string[] = []
        page.on('request', (r) => {
          if (isApi(r)) {
            const u = new URL(r.url())
            seen.push(`${r.method()} ${u.pathname}${u.search}`)
          }
        })
        await page.goto(path)
        await expect(
          page.locator('main#content').getByRole('heading', { level: 1, name: 'CI/CD integration' })
        ).toBeVisible({ timeout: 30_000 })
        await page.waitForLoadState('networkidle')
        expect(await layoutDefects(page)).toEqual([])
        expect(await seriousAxe(page)).toEqual([])
        expect(seen.length, seen.join('\n')).toBeLessThanOrEqual(budget)
        expect(new Set(seen).size, seen.join('\n')).toBe(seen.length)
      })
    }
  }
})
