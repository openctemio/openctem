import { test, expect } from '../fixtures/authenticated-page'
import { layoutShift, trackLayoutShift } from '../helpers/layout-shift'

/**
 * The finding page shows once its bands and side panels have answered, so
 * nothing pushes the content down after it painted. Measured before the fix:
 * a layout shift of 0.29 on a phone, the verification and retest panels
 * arriving under the header and moving the body by about 760px.
 *
 * The side panels' answers are held back here, the way a slow network does,
 * so the test does not depend on the CI runner being fast.
 */
const LATE = /\/api\/v1\/findings\/[^/]+\/(verification|retest-check|retests|approvals)(\?|$)/

test.describe('Finding page layout stability', { tag: ['@findings', '@phone'] }, () => {
  for (const viewport of [
    { width: 390, height: 844 },
    { width: 1440, height: 900 },
  ]) {
    test(`no layout shift while the panels load at ${viewport.width}px`, async ({ page }) => {
      const res = page.waitForResponse((r) => /\/api\/v1\/findings\?/.test(r.url()) && r.ok(), {
        timeout: 60_000,
      })
      await page.goto('/findings')
      const body = (await (await res).json()) as { data?: Array<{ id: string }> }
      const id = body.data?.[0]?.id
      test.skip(!id, 'Needs a finding')

      await page.setViewportSize(viewport)
      await page.route(LATE, async (route) => {
        await new Promise((r) => setTimeout(r, 700))
        await route.continue()
      })
      await trackLayoutShift(page)
      await page.goto(`/findings/${id}`)
      await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({
        timeout: 30_000,
      })
      await expect(page.getByTestId('finding-detail-skeleton')).toHaveCount(0)
      // Let any late panel land.
      await page.waitForTimeout(1500)
      const shift = await layoutShift(page)
      expect(shift.score, `moved: ${shift.nodes.join(', ')}`).toBeLessThan(0.05)
    })
  }
})
