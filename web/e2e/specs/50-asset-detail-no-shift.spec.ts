import { test, expect } from '../fixtures/authenticated-page'
import { layoutShift, trackLayoutShift } from '../helpers/layout-shift'

/**
 * The asset page shows its panels together once they answered, so a panel
 * that loads a moment after the asset (or hides because it has nothing to
 * show) does not push what is already on screen. Measured before: a layout
 * shift of 0.08 to 0.46 at 390px, the attribute sources, freshness and
 * coverage sections growing one after another below the properties.
 *
 * The page's answers are held back here, the way a slow network does.
 */
const DATA = /\/api\/v1\/(?!me\/bootstrap)/

test.describe('Asset page layout stability', { tag: ['@assets', '@phone'] }, () => {
  for (const viewport of [
    { width: 390, height: 844 },
    { width: 1440, height: 900 },
  ]) {
    test(`no layout shift while the panels load at ${viewport.width}px`, async ({ page }) => {
      const res = page.waitForResponse((r) => /\/api\/v1\/assets\?/.test(r.url()) && r.ok(), {
        timeout: 60_000,
      })
      await page.goto('/assets')
      const body = (await (await res).json()) as { data?: Array<{ id: string; type?: string }> }
      const id = body.data?.find((a) => a.type !== 'repository')?.id
      test.skip(!id, 'Needs an asset')

      await page.setViewportSize(viewport)
      await page.route(DATA, async (route) => {
        await new Promise((r) => setTimeout(r, 600))
        await route.continue()
      })
      await trackLayoutShift(page)
      await page.goto(`/assets/${id}`)
      await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({
        timeout: 30_000,
      })
      await expect(page.getByTestId('asset-detail-panels-skeleton')).toHaveCount(0)
      // Let any late panel land.
      await page.waitForTimeout(1500)
      const shift = await layoutShift(page)
      expect(shift.score, `moved: ${shift.nodes.join(', ')}`).toBeLessThan(0.05)
    })
  }
})
