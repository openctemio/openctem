import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { touchTargetHeight } from '../helpers/touch'

/**
 * Dashboard header on a phone (390px). Before content there are two rows:
 *   1. the dashboard's name with the switcher chevron right after it, and at
 *      the end of the same row an icon-only Refresh and an icon-only More
 *      menu, each with a 44px touch target;
 *   2. one muted meta line (scope, updated, next) that never wraps.
 * Customize and the refresh schedule live in More. A screenshot of the header
 * in light and dark is attached for review. From 640px Customize is a toolbar
 * button; the schedule stays in More at every width.
 */

/** 44px touch target, with room for sub-pixel layout rounding. */
const TOUCH = 43.5

for (const scheme of ['light', 'dark'] as const) {
  test(
    `dashboard header at 390px in ${scheme}`,
    { tag: ['@dashboard'] },
    async ({ page }, testInfo) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.emulateMedia({ colorScheme: scheme })
      await page.goto('/')
      const toolbar = page.getByTestId('dashboard-toolbar')
      await expect(page.getByTestId('dashboard-meta')).toBeVisible({ timeout: 45_000 })

      // The More trigger is a placeholder until the menu's code has loaded;
      // measure the real one, not a node about to be replaced.
      await expect(toolbar.locator('[data-action-menu-pending]')).toHaveCount(0)
      const switcher = page.getByRole('button', { name: /Switch dashboard/ })
      const refresh = toolbar.getByRole('button', { name: 'Refresh now' })
      const more = toolbar.getByRole('button', { name: 'More dashboard actions' })
      const title = page.getByRole('heading', { level: 1 })
      const boxes = await Promise.all([title, switcher, refresh, more].map((l) => l.boundingBox()))
      expect(boxes.every(Boolean), 'title, switcher, refresh and more render').toBe(true)
      const [h, s, r, m] = boxes as NonNullable<(typeof boxes)[number]>[]

      // One row, in this order: name, chevron, then Refresh and More at the end.
      const mid = (b: { y: number; height: number }) => b.y + b.height / 2
      expect(Math.abs(mid(s) - mid(h))).toBeLessThan(4)
      for (const b of [r, m]) expect(Math.abs(mid(b) - mid(s))).toBeLessThan(4)
      expect(h.x).toBeLessThan(s.x)
      expect(s.x).toBeLessThan(r.x)
      expect(r.x).toBeLessThan(m.x)
      for (const l of [switcher, refresh, more])
        expect(await touchTargetHeight(l), 'touch target').toBeGreaterThanOrEqual(TOUCH)
      // Customize and the schedule are not in the row on a phone.
      await expect(toolbar.getByRole('button', { name: 'Customize' })).toBeHidden()
      await expect(page.getByRole('combobox', { name: 'Refresh schedule' })).toHaveCount(0)

      // The meta line is one line.
      const meta = await page.getByTestId('dashboard-meta').boundingBox()
      expect(meta && meta.height, 'meta line wraps').toBeLessThan(24)

      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth
      )
      expect(overflow, 'horizontal page scroll on a phone').toBeLessThanOrEqual(0)

      await testInfo.attach(`dashboard-header-390-${scheme}.png`, {
        body: await page.screenshot({ clip: { x: 0, y: 0, width: 390, height: 360 } }),
        contentType: 'image/png',
      })

      // More carries Customize (on an editable dashboard) and the schedule.
      await more.click()
      // Customize and a submenu: the menu is a bottom sheet on a phone.
      const menu = page.locator('[data-slot="action-sheet"]')
      await expect(menu).toBeVisible()
      // The sheet slides in: measure once it has settled.
      await menu.evaluate((el) =>
        Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished))
      )
      await testInfo.attach(`dashboard-header-390-${scheme}-menu.png`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })
      const items = menu.locator('[data-slot="action-sheet-row"]')
      for (const item of await items.all()) {
        const b = await item.boundingBox()
        if (b) expect(b.height).toBeGreaterThanOrEqual(TOUCH)
      }
    }
  )
}

/**
 * Force the figures' state on the landing dashboard: the home request carries
 * the first snapshot and a building dashboard polls its own data route.
 */
async function forceFiguresState(page: Page, state: 'building' | 'stale') {
  const patch = (d: Record<string, unknown>) =>
    state === 'building'
      ? { ...d, facts_built_at: null }
      : { ...d, stale: true, last_refresh_error: 'refresh timed out' }
  await page.route('**/api/v1/me/dashboards/home**', async (route) => {
    const res = await route.fetch()
    const body = await res.json()
    if (body.data) body.data = patch(body.data)
    await route.fulfill({ response: res, json: body })
  })
  await page.route(/\/api\/v1\/(me|organization)\/dashboards\/[^/]+\/data/, async (route) => {
    const res = await route.fetch()
    await route.fulfill({ response: res, json: patch(await res.json()) })
  })
}

for (const state of ['current', 'building', 'stale'] as const) {
  test(
    `dashboard header at 1440px is one toolbar row (${state} figures)`,
    { tag: ['@dashboard'] },
    async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 900 })
      if (state !== 'current') await forceFiguresState(page, state)
      await page.goto('/')
      const toolbar = page.getByTestId('dashboard-toolbar')
      await expect(page.getByTestId('dashboard-meta')).toBeVisible({ timeout: 45_000 })
      await expect(toolbar.locator('[data-action-menu-pending]')).toHaveCount(0)
      const notice = page.getByTestId('dashboard-data-notice')
      if (state === 'current') await expect(notice).toHaveCount(0)
      else await expect(notice).toBeVisible()

      const controls = toolbar.locator('button:visible, [role="combobox"]:visible')
      const boxes = await Promise.all((await controls.all()).map((c) => c.boundingBox()))
      expect(boxes.length).toBeGreaterThanOrEqual(3)
      expect(boxes.every(Boolean), 'every toolbar control is laid out').toBe(true)
      const centres = (boxes as NonNullable<(typeof boxes)[number]>[]).map(
        (b) => b.y + b.height / 2
      )
      // Same row: every control's vertical centre on one line.
      for (const y of centres) expect(Math.abs(y - centres[0])).toBeLessThan(2)
      // The row stays beside the name: a notice never pushes the controls down.
      const title = await page.getByRole('heading', { level: 1 }).boundingBox()
      expect(title).not.toBeNull()
      expect(centres[0]).toBeLessThan(title!.y + title!.height)
      // The notice is under the header, not inside it.
      if (state !== 'current') {
        const header = await page.locator('[data-slot="page-header"]').boundingBox()
        const n = await notice.boundingBox()
        expect(n!.y).toBeGreaterThanOrEqual(header!.y + header!.height)
      }
      // The switcher is on the title line; the schedule is not a toolbar control.
      await expect(page.locator('[data-slot="page-header-title-line"]')).toContainText(
        (await page.getByRole('heading', { level: 1 }).textContent()) ?? ''
      )
      await expect(
        page
          .locator('[data-slot="page-header-title-action"]')
          .getByRole('button', { name: /Switch dashboard/ })
      ).toBeVisible()
      await expect(page.getByRole('combobox', { name: 'Refresh schedule' })).toHaveCount(0)
    }
  )
}
