import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { layoutIssues } from '../design/layout-checks'
import { openFindingsPhoneSelect } from '../helpers/table'

/**
 * Row menus and the bulk bar's More use the shared action menu, which picks
 * its presentation by fit on a phone.
 *
 * - A finding's row menu (seven items or more) is a bottom sheet below 768 px:
 *   titled with the finding, rows of at least 44, at least 16 px under its
 *   last row, its bottom on the visible screen; Escape closes it and gives
 *   the focus back. From 768 px up it is a menu inside the 16 px gutter.
 * - The bulk bar's More (one item) is a small menu at every width, above its
 *   button (never covering it), inside the gutter, rows of at least 44 on a
 *   phone.
 *
 * At 375, 390, 768 and 1440 px, in English and Vietnamese.
 */

const GUTTER = 16
const WIDTHS = [375, 390, 768, 1440] as const
const L = {
  en: { more: 'More actions', remediation: 'Remediation task', rowActions: /^Actions for / },
  vi: { more: 'Thao tác khác', remediation: 'Tác vụ khắc phục', rowActions: /^Thao tác cho / },
} as const

async function settledRect(el: Locator) {
  let last = ''
  await expect
    .poll(async () => {
      const now = await el.evaluate((e) => {
        const b = e.getBoundingClientRect()
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

async function openFindings(page: Page, width: number, locale: 'en' | 'vi', baseURL?: string) {
  await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
  await page.setViewportSize({ width, height: 844 })
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('/findings')
  const trigger = page.getByRole('button', { name: L[locale].rowActions }).first()
  await expect(trigger).toBeVisible({ timeout: 45_000 })
  return trigger
}

for (const locale of ['en', 'vi'] as const) {
  for (const width of WIDTHS) {
    const phone = width < 768
    test(
      `A finding's row menu is ${phone ? 'a bottom sheet' : 'a menu'} at ${width}px (${locale})`,
      { tag: ['@findings', ...(phone ? ['@phone'] : [])] },
      async ({ page, baseURL }) => {
        const trigger = await openFindings(page, width, locale, baseURL)
        const name = (await trigger.getAttribute('aria-label'))!
        await trigger.click()

        if (phone) {
          const sheet = page.locator('[data-slot="action-sheet"]')
          await expect(sheet).toBeVisible()
          const s = await settledRect(sheet)
          const title = (await sheet.locator('[data-slot="drawer-title"]').innerText()).trim()
          expect(name.endsWith(title), 'titled with the finding').toBe(true)
          const rows = sheet.locator('[data-slot="action-sheet-row"]')
          const heights = await rows.evaluateAll((els) =>
            els.map((e) => Math.round(e.getBoundingClientRect().height))
          )
          const geo = await sheet.evaluate((el) => {
            const body = el.querySelector('[data-slot="action-sheet-body"]')!
            const vv = window.visualViewport!
            return {
              padBottom: parseFloat(getComputedStyle(el).paddingBottom),
              underBody: Math.round(
                el.getBoundingClientRect().bottom - body.getBoundingClientRect().bottom
              ),
              visibleBottom: Math.round(vv.offsetTop + vv.height),
            }
          })
          test.info().annotations.push({
            type: 'row sheet',
            description: JSON.stringify({ sheet: s, rows: heights, ...geo }),
          })
          expect(heights.length, 'a long menu').toBeGreaterThanOrEqual(7)
          for (const h of heights) expect(h, 'sheet row height').toBeGreaterThanOrEqual(44)
          expect(await sheet.locator('[data-slot="action-sheet-row"] svg').count()).toBe(0)
          expect(geo.padBottom).toBeGreaterThanOrEqual(16)
          expect(geo.underBody, 'room under the last row').toBeGreaterThanOrEqual(16)
          expect(s.bottom, 'on the visible screen').toBeLessThanOrEqual(geo.visibleBottom)
          expect(await page.getByRole('menu').count()).toBe(0)
          await page.keyboard.press('Escape')
          await expect(sheet).toBeHidden()
        } else {
          const menu = page.getByRole('menu')
          await expect(menu).toBeVisible()
          const m = await settledRect(menu)
          test.info().annotations.push({ type: 'row menu', description: JSON.stringify(m) })
          expect(m.left).toBeGreaterThanOrEqual(GUTTER)
          expect(m.right).toBeLessThanOrEqual(width - GUTTER)
          expect(await page.locator('[data-slot="action-sheet"]').count()).toBe(0)
          const issues = await page.evaluate(layoutIssues)
          expect(issues.filter((i) => i.kind === 'popup' || i.kind === 'target')).toEqual([])
          await page.keyboard.press('Escape')
          await expect(menu).toBeHidden()
        }
        await expect(trigger).toBeFocused()
      }
    )

    test(
      `The bulk bar's More is a small menu above its button at ${width}px (${locale})`,
      { tag: ['@findings', ...(phone ? ['@phone'] : [])] },
      async ({ page, baseURL }) => {
        await openFindings(page, width, locale, baseURL)
        if (phone) {
          // Select mode from the list's More (title row), then the first card.
          await openFindingsPhoneSelect(page)
          await page.getByTestId('finding-phone-card').first().getByRole('checkbox').check()
        } else {
          await page.getByRole('row').nth(1).getByRole('checkbox').check()
        }
        const bar = page.locator('[data-slot="bulk-action-bar"]')
        await expect(bar).toBeVisible()
        const b = await settledRect(bar)
        const more = bar.getByRole('button', { name: L[locale].more })
        const t = await settledRect(more)
        await more.click()
        const menu = page.getByRole('menu')
        await expect(menu).toBeVisible()
        const m = await settledRect(menu)
        const heights = await menu
          .getByRole('menuitem')
          .evaluateAll((els) => els.map((e) => Math.round(e.getBoundingClientRect().height)))
        test.info().annotations.push({
          type: 'bulk More',
          description: JSON.stringify({ bar: b, trigger: t, menu: m, rows: heights }),
        })
        expect(await page.locator('[data-slot="action-sheet"]').count()).toBe(0)
        expect(m.bottom, 'above its button, never covering it').toBeLessThanOrEqual(t.top)
        expect(m.left).toBeGreaterThanOrEqual(GUTTER)
        expect(m.right).toBeLessThanOrEqual(width - GUTTER)
        if (phone) for (const h of heights) expect(h, 'row height').toBeGreaterThanOrEqual(44)
        await expect(menu.getByRole('menuitem', { name: L[locale].remediation })).toBeVisible()
        await page.keyboard.press('Escape')
        await expect(menu).toBeHidden()
        // The bar's Escape is for the menu first: the selection stays.
        await expect(bar).toBeVisible()
      }
    )
  }
}
