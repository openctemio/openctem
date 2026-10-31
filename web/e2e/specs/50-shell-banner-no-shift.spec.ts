import { test, expect } from '../fixtures/authenticated-page'
import { layoutShift, trackLayoutShift } from '../helpers/layout-shift'

/**
 * Within a session a page renders before the session bootstrap answers, and
 * the platform notice it carries used to appear a moment later above the page
 * and push it all down (a layout shift of 0.12 to 0.16 on every page on a
 * phone). The banner slot now holds the space the banners took on the last
 * page. The notice is added to the bootstrap answer here, and the answer is
 * held back the way a slow network does.
 */
const NOTICE = {
  id: '00000000-0000-4000-8000-0000000000e2',
  message: 'Planned maintenance window for this test.',
  severity: 'maintenance',
}

test.describe('Shell banners', { tag: ['@shell', '@phone'] }, () => {
  test('a platform notice does not push the page down on reload', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.route(/\/api\/v1\/me\/bootstrap(\?|$)/, async (route) => {
      const res = await route.fetch()
      const body = (await res.json()) as Record<string, unknown>
      await new Promise((r) => setTimeout(r, 700))
      await route.fulfill({ response: res, json: { ...body, announcements: [NOTICE] } })
    })
    // First page of the session: the banner shows and its height is noted.
    await page.goto('/findings')
    await expect(page.getByText(NOTICE.message)).toBeVisible({ timeout: 30_000 })

    await trackLayoutShift(page)
    await page.reload()
    await expect(page.getByText(NOTICE.message)).toBeVisible({ timeout: 30_000 })
    await page.waitForTimeout(1000)
    const shift = await layoutShift(page)
    expect(shift.score, `moved: ${shift.nodes.join(', ')}`).toBeLessThan(0.05)
  })
})
