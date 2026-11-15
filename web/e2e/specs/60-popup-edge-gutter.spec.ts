import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Popups keep the page gutter (owner report 2026-11-15, /findings at 390 px):
 * the page-header More menu opened flush against the left screen edge while
 * the toolbar More menu kept its 16 px. Radix let a right-aligned menu whose
 * trigger sits at the left of the wrapped header row slide to x = 0. Every kit
 * floating surface now has a 16 px collision padding.
 *
 * At 375 and 390 px, each More menu on /findings opens at least 16 px from
 * both screen edges.
 */

const GUTTER = 16

async function edges(page: Page, trigger: Locator) {
  await trigger.click()
  const menu = page.getByRole('menu')
  await expect(menu).toBeVisible()
  // Measure once the position has settled.
  let last = ''
  await expect
    .poll(async () => {
      const now = await menu.evaluate((el) => {
        const b = el.getBoundingClientRect()
        return `${Math.round(b.left)},${Math.round(b.right)}`
      })
      const same = now === last
      last = now
      return same
    })
    .toBe(true)
  const [left, right] = last.split(',').map(Number)
  await page.keyboard.press('Escape')
  await expect(menu).toBeHidden()
  return { left, right, width: page.viewportSize()!.width }
}

for (const width of [375, 390] as const) {
  test(
    `More menus on /findings keep the page gutter at ${width}px`,
    { tag: ['@findings', '@shell', '@phone'] },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 844 })
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.goto('/findings')

      const header = page.locator('[data-slot="page-header"]')
      const headerMore = header.getByRole('button', { name: 'More actions' })
      await expect(headerMore).toBeVisible({ timeout: 45_000 })
      const h = await edges(page, headerMore)
      test.info().annotations.push({ type: 'header More', description: JSON.stringify(h) })
      expect(h.left, 'header More: left gutter').toBeGreaterThanOrEqual(GUTTER)
      expect(h.right, 'header More: right gutter').toBeLessThanOrEqual(h.width - GUTTER)

      const toolbarMore = page
        .getByTestId('findings-toolbar-primary')
        .getByRole('button', { name: 'More actions' })
      await expect(toolbarMore).toBeVisible()
      const l = await edges(page, toolbarMore)
      test.info().annotations.push({ type: 'toolbar More', description: JSON.stringify(l) })
      expect(l.left, 'toolbar More: left gutter').toBeGreaterThanOrEqual(GUTTER)
      expect(l.right, 'toolbar More: right gutter').toBeLessThanOrEqual(l.width - GUTTER)
    }
  )
}
