import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { layoutIssues } from '../design/layout-checks'

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
 *
 * Below 768 px the header More is an action sheet: titled with the page, a
 * close button, rows of 48 (at least 44), no heading over a single item, no
 * icons, inside the viewport; the close button, Escape and a tap on the scrim
 * close it and the focus returns to the trigger. From 768 px up it is the
 * anchored menu.
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
    `The toolbar More menu on /findings keeps the page gutter at ${width}px`,
    { tag: ['@findings', '@shell', '@phone'] },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 844 })
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.goto('/findings')

      // The header More is an action sheet on a phone (tested below).
      await expect(
        page.locator('[data-slot="page-header"]').getByRole('button', { name: 'More actions' })
      ).toBeVisible({ timeout: 45_000 })

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
      if (width >= 768) {
        await headerMore.click()
        const menu = page.getByRole('menu')
        await expect(menu).toBeVisible()
        const m = await settledRect(menu)
        test.info().annotations.push({ type: 'header More', description: JSON.stringify(m) })
        expect(m.left, 'header More: left gutter').toBeGreaterThanOrEqual(GUTTER)
        expect(m.right, 'header More: right gutter').toBeLessThanOrEqual(width - GUTTER)
        expect(await noSidewaysScroll(page), 'no sideways page scroll with a menu open').toBe(true)
        const issues = await page.evaluate(layoutIssues)
        expect(issues.filter((i) => i.kind === 'popup' || i.kind === 'target')).toEqual([])
        await page.keyboard.press('Escape')
        await expect(menu).toBeHidden()
      }

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

for (const width of [375, 390] as const) {
  test(
    `The findings header More is an action sheet at ${width}px`,
    { tag: ['@findings', '@shell', '@phone'] },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 844 })
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.goto('/findings')
      const headerMore = page
        .locator('[data-slot="page-header"]')
        .getByRole('button', { name: 'More actions' })
      await expect(headerMore).toBeVisible({ timeout: 45_000 })
      await expect(headerMore).toHaveAttribute('aria-haspopup', 'dialog')

      const sheet = page.getByRole('dialog', { name: 'Findings' })
      const open = async () => {
        await headerMore.click()
        await expect(sheet).toBeVisible()
        await settledRect(sheet)
      }

      await open()
      expect(await page.getByRole('menu').count(), 'no anchored menu on a phone').toBe(0)
      const rows = sheet.locator('[data-slot="action-sheet-row"]')
      await expect(rows.first()).toBeVisible()
      const heights = await rows.evaluateAll((els) =>
        els.map((e) => Math.round(e.getBoundingClientRect().height))
      )
      test.info().annotations.push({ type: 'sheet rows', description: JSON.stringify(heights) })
      for (const h of heights) expect(h, 'sheet row height').toBeGreaterThanOrEqual(48)
      expect(await sheet.locator('[data-slot="action-sheet-row"] svg').count(), 'no icons').toBe(0)
      await expect(sheet.getByText('Create', { exact: true })).toHaveCount(0)
      const s = await settledRect(sheet)
      expect(s.left).toBeGreaterThanOrEqual(0)
      expect(s.right).toBeLessThanOrEqual(width)
      expect(s.bottom).toBeLessThanOrEqual(844)
      expect(await noSidewaysScroll(page)).toBe(true)
      const issues = await page.evaluate(layoutIssues)
      expect(issues.filter((i) => i.kind === 'popup' || i.kind === 'target')).toEqual([])

      // Close button, then Escape, then a tap on the scrim.
      await sheet.getByRole('button', { name: 'Close' }).click()
      await expect(sheet).toBeHidden()
      await expect(headerMore).toBeFocused()
      await open()
      await page.keyboard.press('Escape')
      await expect(sheet).toBeHidden()
      await open()
      await page.mouse.click(width / 2, 20)
      await expect(sheet).toBeHidden()

      // A row acts: Approvals navigates.
      await open()
      await sheet.getByRole('link', { name: 'Approvals' }).click()
      await expect(page).toHaveURL(/\/findings\/approvals/)
    }
  )
}
