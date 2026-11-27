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
 * Below 768 px an action menu chooses by fit (owner, 2026-11-15): the header
 * More (two items) is a small anchored menu under its trigger, rows of at
 * least 44, 16 px from both edges, in English and Vietnamese. When the same
 * menu has no room beside its trigger (a short screen) it is the bottom
 * sheet: titled with the page, a close button, rows of 48, no icons, at least
 * 16 px under its last row, its bottom on the visible screen; the close
 * button, Escape and a tap on the scrim close it and the focus returns to the
 * trigger. From 768 px up it is the anchored menu.
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

const HEADER_MORE = {
  en: { more: 'More actions', title: 'Findings', approvals: 'Approvals', close: 'Close' },
  vi: { more: 'Thao tác khác', title: 'Phát hiện', approvals: 'Phê duyệt', close: 'Đóng' },
} as const

for (const locale of ['en', 'vi'] as const) {
  for (const width of [375, 390] as const) {
    test(
      `The findings header More is a small menu under its trigger at ${width}px (${locale})`,
      { tag: ['@findings', '@shell', '@phone'] },
      async ({ page, baseURL }) => {
        const l = HEADER_MORE[locale]
        await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
        await page.setViewportSize({ width, height: 844 })
        await page.emulateMedia({ reducedMotion: 'reduce' })
        await page.goto('/findings')
        const headerMore = page
          .locator('[data-slot="page-header"]')
          .getByRole('button', { name: l.more })
        await expect(headerMore).toBeVisible({ timeout: 45_000 })
        await expect(headerMore).toHaveAttribute('aria-haspopup', 'menu')
        const t = await settledRect(headerMore)

        await headerMore.click()
        const menu = page.getByRole('menu')
        await expect(menu).toBeVisible()
        const m = await settledRect(menu)
        const heights = await menu
          .getByRole('menuitem')
          .evaluateAll((els) => els.map((e) => Math.round(e.getBoundingClientRect().height)))
        test.info().annotations.push({
          type: 'phone header More',
          description: JSON.stringify({ trigger: t, menu: m, rows: heights }),
        })
        expect(await page.getByRole('dialog').count(), 'no sheet for a short menu').toBe(0)
        expect(m.left, 'left gutter').toBeGreaterThanOrEqual(GUTTER)
        expect(m.right, 'right gutter').toBeLessThanOrEqual(width - GUTTER)
        expect(m.top, 'opens under its trigger').toBeGreaterThanOrEqual(t.bottom)
        expect(m.top - t.bottom, 'next to its trigger').toBeLessThanOrEqual(8)
        expect(heights.length).toBeGreaterThan(0)
        for (const h of heights) expect(h, 'menu row height').toBeGreaterThanOrEqual(44)
        expect(await noSidewaysScroll(page)).toBe(true)
        const issues = await page.evaluate(layoutIssues)
        expect(issues.filter((i) => i.kind === 'popup' || i.kind === 'target')).toEqual([])

        await page.keyboard.press('Escape')
        await expect(menu).toBeHidden()
        await expect(headerMore).toBeFocused()

        // A row acts: Approvals navigates.
        await headerMore.click()
        await menu.getByRole('menuitem', { name: l.approvals }).click()
        await expect(page).toHaveURL(/\/findings\/approvals/)
      }
    )
  }
}

// A short screen leaves the same menu no room beside its trigger: the sheet.
for (const locale of ['en', 'vi'] as const) {
  for (const width of [375, 390] as const) {
    test(
      `An action menu without room beside its trigger is a bottom sheet at ${width}px (${locale})`,
      { tag: ['@findings', '@shell', '@phone'] },
      async ({ page, baseURL }) => {
        const l = HEADER_MORE[locale]
        await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
        await page.setViewportSize({ width, height: 844 })
        await page.emulateMedia({ reducedMotion: 'reduce' })
        await page.goto('/findings')
        const headerMore = page
          .locator('[data-slot="page-header"]')
          .getByRole('button', { name: l.more })
        await expect(headerMore).toBeVisible({ timeout: 45_000 })
        // Shrink the screen so the two-row menu (98 px) has no room below the
        // trigger (90 px left after the gutter) nor above it, while the sheet
        // still fits without scrolling.
        const t = await settledRect(headerMore)
        expect(t.top - 4 - GUTTER, 'precondition: no room above').toBeLessThan(98)
        const height = t.bottom + 4 + GUTTER + 90
        await page.setViewportSize({ width, height })

        const sheet = page.getByRole('dialog', { name: l.title })
        const open = async () => {
          await headerMore.click()
          await expect(sheet).toBeVisible()
          await settledRect(sheet)
        }

        await open()
        expect(await page.getByRole('menu').count(), 'no anchored menu without room').toBe(0)
        const rows = sheet.locator('[data-slot="action-sheet-row"]')
        await expect(rows.first()).toBeVisible()
        const heights = await rows.evaluateAll((els) =>
          els.map((e) => Math.round(e.getBoundingClientRect().height))
        )
        for (const h of heights) expect(h, 'sheet row height').toBeGreaterThanOrEqual(44)
        expect(await sheet.locator('[data-slot="action-sheet-row"] svg').count(), 'no icons').toBe(
          0
        )
        const s = await settledRect(sheet)
        const geo = await sheet.evaluate((el) => {
          const vv = window.visualViewport!
          const rows = el.querySelectorAll('[data-slot="action-sheet-row"]')
          const last = rows[rows.length - 1].getBoundingClientRect()
          return {
            padBottom: parseFloat(getComputedStyle(el).paddingBottom),
            gapUnderLastRow: Math.round(el.getBoundingClientRect().bottom - last.bottom),
            visibleBottom: Math.round(vv.offsetTop + vv.height),
          }
        })
        test.info().annotations.push({
          type: 'sheet',
          description: JSON.stringify({ height, sheet: s, rows: heights, ...geo }),
        })
        expect(geo.padBottom, 'bottom padding').toBeGreaterThanOrEqual(16)
        expect(geo.gapUnderLastRow, 'room under the last row').toBeGreaterThanOrEqual(16)
        expect(s.bottom, 'on the visible screen').toBeLessThanOrEqual(geo.visibleBottom)
        expect(s.left).toBeGreaterThanOrEqual(0)
        expect(s.right).toBeLessThanOrEqual(width)
        expect(await noSidewaysScroll(page)).toBe(true)

        // Close button, then Escape, then a tap on the scrim.
        await sheet.getByRole('button', { name: l.close }).click()
        await expect(sheet).toBeHidden()
        await expect(headerMore).toBeFocused()
        await open()
        await page.keyboard.press('Escape')
        await expect(sheet).toBeHidden()
        await open()
        await page.mouse.click(width / 2, 2)
        await expect(sheet).toBeHidden()
      }
    )
  }
}

/**
 * Owner report (desktop): the status menu of the finding drawer ("New",
 * items "Confirmed" and "False positive") opened as a 256 px panel hanging to
 * the left of its trigger, out over the dimmed page. A menu is as wide as its
 * content (at least 160 px with icons) and lines up with its trigger's start
 * edge unless that would cross the room it has; inside a drawer that room is
 * the drawer.
 */
async function newFindingId(page: Page): Promise<string | null> {
  return page.evaluate(async () => {
    const res = await fetch('/api/v1/findings?per_page=50')
    const body = (await res.json().catch(() => null)) as {
      data?: Array<{ id: string; status: string }>
    } | null
    return body?.data?.find((f) => f.status === 'new')?.id ?? null
  })
}

for (const width of [1440, 390] as const) {
  test(
    `The finding drawer's status menu opens under its trigger, inside the drawer, at ${width}px`,
    { tag: ['@findings', ...(width < 768 ? ['@phone'] : [])] },
    async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 900 })
      await page.goto('/findings')
      await page.waitForLoadState('networkidle')
      const id = await newFindingId(page)
      test.skip(!id, 'No finding in "New": seed findings to enable this test')

      await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
      await page.emulateMedia({ reducedMotion: 'reduce' })
      // The page reads the hash once, on load: leave first so this is a load.
      await page.goto('about:blank')
      await page.goto(`/findings#finding=${id}`)
      const drawer = page.getByRole('dialog')
      await expect(drawer).toBeVisible({ timeout: 45_000 })
      const status = drawer.getByRole('button', { name: /^New$/ }).first()
      await expect(status).toBeVisible()
      const d = await settledRect(drawer)
      const t = await settledRect(status)

      await status.click()
      const menu = page.getByRole('menu')
      await expect(menu.getByRole('menuitem').first()).toBeVisible()
      const m = await settledRect(menu)
      // Widest row: its children (icon, text) plus the row and panel padding.
      const content = await menu.evaluate((el) => {
        let widest = 0
        for (const row of el.querySelectorAll('[role="menuitem"]')) {
          const cs = getComputedStyle(row)
          let w = parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight)
          const kids = [...row.children]
          for (const c of kids) w += c.getBoundingClientRect().width
          w += parseFloat(cs.columnGap || '0') * Math.max(0, kids.length - 1)
          widest = Math.max(widest, w)
        }
        const ps = getComputedStyle(el)
        return Math.ceil(
          widest +
            parseFloat(ps.paddingLeft) +
            parseFloat(ps.paddingRight) +
            parseFloat(ps.borderLeftWidth) +
            parseFloat(ps.borderRightWidth)
        )
      })
      test.info().annotations.push({
        type: 'drawer status menu',
        description: JSON.stringify({ drawer: d, trigger: t, menu: m, content }),
      })
      expect(Math.abs(m.left - t.left), "menu's left edge on the trigger's").toBeLessThanOrEqual(1)
      expect(m.top, 'under its trigger').toBeGreaterThanOrEqual(t.bottom)
      expect(m.left, 'inside the drawer (left)').toBeGreaterThanOrEqual(d.left)
      expect(m.right, 'inside the drawer (right)').toBeLessThanOrEqual(d.right)
      expect(m.right - m.left, 'as wide as its content').toBeLessThanOrEqual(
        Math.max(160, t.right - t.left, content) + 1
      )
      expect(await noSidewaysScroll(page)).toBe(true)
      const issues = await page.evaluate(layoutIssues)
      expect(issues.filter((i) => i.kind === 'popup')).toEqual([])
      await page.keyboard.press('Escape')
      await expect(menu).toBeHidden()
      await expect(drawer).toBeVisible()
    }
  )
}
