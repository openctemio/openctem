import { test, expect } from '../fixtures/authenticated-page'

/**
 * Dashboard header on a phone (390px). Before content there are two rows:
 *   1. the dashboard switcher filling the width, an icon-only Refresh and an
 *      icon-only More menu, all on one line and at least 44px tall;
 *   2. one muted meta line (scope · updated · next) that never wraps.
 * Customize and the refresh schedule live in More. A screenshot of the header
 * in light and dark is attached for review. From 640px the same controls sit
 * in one toolbar row with their labels.
 */

/** 44px touch target, with room for sub-pixel layout rounding. */
const TOUCH = 43.5

for (const scheme of ['light', 'dark'] as const) {
  test(`dashboard header at 390px in ${scheme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/')
    const toolbar = page.getByTestId('dashboard-toolbar')
    await expect(page.getByTestId('dashboard-meta')).toBeVisible({ timeout: 45_000 })

    const switcher = toolbar.getByRole('button', { name: /Switch dashboard/ })
    const refresh = toolbar.getByRole('button', { name: 'Refresh now' })
    const more = toolbar.getByRole('button', { name: 'More dashboard actions' })
    const boxes = await Promise.all([switcher, refresh, more].map((l) => l.boundingBox()))
    expect(boxes.every(Boolean), 'switcher, refresh and more render').toBe(true)
    const [s, r, m] = boxes as NonNullable<(typeof boxes)[number]>[]

    // One row, in this order, touch-sized, switcher taking the free width.
    for (const b of [r, m]) expect(Math.abs(b.y - s.y)).toBeLessThan(2)
    expect(s.x).toBeLessThan(r.x)
    expect(r.x).toBeLessThan(m.x)
    for (const b of [s, r, m]) expect(b.height).toBeGreaterThanOrEqual(TOUCH)
    expect(s.width).toBeGreaterThan(390 / 2)
    // Customize and the schedule are not in the row on a phone.
    await expect(toolbar.getByRole('button', { name: 'Customize' })).toBeHidden()
    await expect(toolbar.getByRole('combobox', { name: 'Refresh schedule' })).toBeHidden()

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
    const menu = page.getByRole('menu')
    await expect(menu).toBeVisible()
    // The menu opens with a short zoom: measure once it has settled.
    await menu.evaluate((el) =>
      Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished))
    )
    await testInfo.attach(`dashboard-header-390-${scheme}-menu.png`, {
      body: await page.screenshot(),
      contentType: 'image/png',
    })
    const items = menu.getByRole('menuitem')
    for (const item of await items.all()) {
      const b = await item.boundingBox()
      if (b) expect(b.height).toBeGreaterThanOrEqual(TOUCH)
    }
  })
}

test('dashboard header at 1440px is one toolbar row', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')
  const toolbar = page.getByTestId('dashboard-toolbar')
  await expect(page.getByTestId('dashboard-meta')).toBeVisible({ timeout: 45_000 })
  const controls = toolbar.locator('button:visible, [role="combobox"]:visible')
  // Same row: every control's vertical centre on one line.
  const centres = await Promise.all(
    (await controls.all()).map(async (c) => {
      const b = await c.boundingBox()
      return b ? b.y + b.height / 2 : -1
    })
  )
  expect(centres.length).toBeGreaterThanOrEqual(3)
  for (const y of centres) expect(Math.abs(y - centres[0])).toBeLessThan(2)
  await expect(toolbar.getByRole('button', { name: 'Refresh now' })).toContainText('Refresh now')
})
