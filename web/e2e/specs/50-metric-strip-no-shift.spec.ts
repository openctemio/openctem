import { test, expect } from '../fixtures/authenticated-page'
import { layoutShift, trackLayoutShift } from '../helpers/layout-shift'

/**
 * A metric strip keeps its height while its numbers load: the value skeleton
 * sits in a box of the value's line height and a tile with a detail line
 * holds that line. Measured before: the strip on /attack-surface grew from 68
 * to 92px when the numbers arrived and pushed the sections below it (layout
 * shift 0.11 at 1440px). The page's answers are held back the way a slow
 * network does.
 */
const DATA = /\/api\/v1\/(?!me\/bootstrap)/

test.describe('Metric strip layout stability', { tag: ['@attack-surface', '@phone'] }, () => {
  for (const viewport of [
    { width: 1440, height: 900 },
    { width: 390, height: 844 },
  ]) {
    test(`/attack-surface does not move while its numbers load at ${viewport.width}px`, async ({
      page,
    }) => {
      await page.setViewportSize(viewport)
      await page.goto('/attack-surface')
      await expect(page.locator('[data-slot="metric-strip"]')).toBeVisible({ timeout: 30_000 })

      await page.route(DATA, async (route) => {
        await new Promise((r) => setTimeout(r, 600))
        await route.continue()
      })
      await trackLayoutShift(page)
      await page.reload()
      await page.waitForTimeout(4000)
      const shift = await layoutShift(page)
      expect(shift.score, `moved: ${shift.nodes.join(', ')}`).toBeLessThan(0.05)
    })
  }
})
