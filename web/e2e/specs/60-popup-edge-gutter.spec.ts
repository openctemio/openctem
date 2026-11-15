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
 * both screen edges. At 375, 390, 768 and 1440 px (smart anchoring): the
 * header More menu and the Group select list stay inside the gutter, the
 * select list opens below or above its trigger and never over it, and an open
 * popup never makes the page scroll sideways.
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

async function settledRect(popup: Locator) {
  let last = ''
  await expect
    .poll(async () => {
      const now = await popup.evaluate((el) => {
        const b = el.getBoundingClientRect()
        return [b.left, b.right, b.top, b.bottom].map(Math.round).join(',')
      })
      const same = now === last
      last = now
      return same
    })
    .toBe(true)
  const [left, right, top, bottom] = last.split(',').map(Number)
  return { left, right, top, bottom }
}

async function noSidewaysScroll(page: Page) {
  return page.evaluate(
    () => document.documentElement.scrollWidth <= document.documentElement.clientWidth
  )
}

for (const width of [375, 390, 768, 1440] as const) {
  test(
    `Popups on /findings are placed by their trigger at ${width}px`,
    { tag: ['@findings', '@shell', ...(width < 768 ? ['@phone'] : [])] },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 844 })
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.goto('/findings')

      const headerMore = page
        .locator('[data-slot="page-header"]')
        .getByRole('button', { name: 'More actions' })
      await expect(headerMore).toBeVisible({ timeout: 45_000 })
      await headerMore.click()
      const menu = page.getByRole('menu')
      await expect(menu).toBeVisible()
      const m = await settledRect(menu)
      test.info().annotations.push({ type: 'header More', description: JSON.stringify(m) })
      expect(m.left, 'header More: left gutter').toBeGreaterThanOrEqual(GUTTER)
      expect(m.right, 'header More: right gutter').toBeLessThanOrEqual(width - GUTTER)
      expect(await noSidewaysScroll(page), 'no sideways page scroll with a menu open').toBe(true)
      await page.keyboard.press('Escape')
      await expect(menu).toBeHidden()

      const group = page.getByRole('combobox', { name: 'Group findings' })
      await expect(group).toBeVisible()
      const t = await settledRect(group)
      await group.click()
      const list = page.getByRole('listbox')
      await expect(list).toBeVisible()
      const l = await settledRect(list)
      test.info().annotations.push({
        type: 'Group select',
        description: JSON.stringify({ trigger: t, list: l }),
      })
      expect(l.left, 'select list: left gutter').toBeGreaterThanOrEqual(GUTTER)
      expect(l.right, 'select list: right gutter').toBeLessThanOrEqual(width - GUTTER)
      expect(
        l.top >= t.bottom || l.bottom <= t.top,
        'select list opens below or above its trigger, never over it'
      ).toBe(true)
      expect(
        l.right - l.left,
        'select list at least as wide as its trigger'
      ).toBeGreaterThanOrEqual(t.right - t.left - 1)
      expect(await noSidewaysScroll(page), 'no sideways page scroll with a list open').toBe(true)
      await page.keyboard.press('Escape')
      await expect(list).toBeHidden()
    }
  )
}
