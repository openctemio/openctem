import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * A picker never opens the on-screen keyboard by itself on a touch screen
 * (owner report 2026-11-15, /findings at 390 px: Add filter focused its search
 * field on open, the keyboard covered half the screen and the field scrolled
 * out of view).
 *
 * At 375 and 390 px with touch (en and vi): Add filter opens as a bottom
 * sheet whose search field is pinned at its top and on screen, the focus is
 * on the option list (not the field) and the rows are at least 44 px. Then
 * the user taps the field and the keyboard opens: emulated as the visible
 * viewport shrinking to 420 px (iOS Safari keeps the layout viewport, so
 * `innerHeight` does not change), once in place and once panned down by
 * 120 px. The sheet follows the visible part: the field and at least 3 rows
 * stay inside it. At 1440 px with a mouse the field has focus on open, as
 * before.
 */

const LABEL = {
  en: { add: 'Add filter', search: 'Search fields…' },
  vi: { add: 'Thêm bộ lọc', search: 'Tìm trường…' },
} as const

const KEYBOARD_UP_HEIGHT = 420

async function openAddFilter(page: Page, locale: 'en' | 'vi', baseURL: string) {
  await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL }])
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('/findings')
  const l = LABEL[locale]
  const trigger = page.getByRole('button', { name: l.add, exact: true }).first()
  await expect(trigger).toBeVisible({ timeout: 45_000 })
  await trigger.click()
  const sheet = page.getByRole('dialog', { name: l.add })
  await expect(sheet.getByRole('option').first()).toBeVisible({ timeout: 20_000 })
  // Measure once the open animation has finished.
  await expect
    .poll(() =>
      sheet.evaluate(
        (el) => el.getAnimations({ subtree: true }).filter((a) => a.playState === 'running').length
      )
    )
    .toBe(0)
  return { sheet, field: sheet.getByPlaceholder(l.search) }
}

/** Emulates the keyboard: the visible viewport shrinks (and may pan); the layout viewport stays. */
async function keyboardUp(page: Page, height: number, offsetTop: number) {
  await page.evaluate(
    ({ height, offsetTop }) => {
      const vv = window.visualViewport!
      Object.defineProperty(vv, 'height', { configurable: true, get: () => height })
      Object.defineProperty(vv, 'offsetTop', { configurable: true, get: () => offsetTop })
      vv.dispatchEvent(new Event('resize'))
      vv.dispatchEvent(new Event('scroll'))
    },
    { height, offsetTop }
  )
}

/** Field and option rows, measured against the visible band [top, bottom]. */
async function visibleRows(page: Page, top: number, bottom: number) {
  return page.evaluate(
    ({ top, bottom }) => {
      const sheet = document.querySelector<HTMLElement>('[data-slot="responsive-popover-sheet"]')!
      const field = sheet.querySelector<HTMLElement>('[data-slot="command-input"]')!
      const f = field.getBoundingClientRect()
      const fieldBottom = f.bottom
      const rows = Array.from(sheet.querySelectorAll<HTMLElement>('[data-slot="command-item"]'))
        .map((el) => el.getBoundingClientRect())
        .filter(
          (r) => r.height > 0 && r.top >= fieldBottom - 1 && r.top >= top && r.bottom <= bottom + 1
        )
      const s = sheet.getBoundingClientRect()
      return {
        fieldTop: Math.round(f.top),
        fieldBottom: Math.round(f.bottom),
        rows: rows.length,
        sheetTop: Math.round(s.top),
        sheetBottom: Math.round(s.bottom),
      }
    },
    { top, bottom }
  )
}

test.describe('touch', () => {
  test.use({ hasTouch: true, isMobile: true })

  for (const locale of ['en', 'vi'] as const) {
    for (const width of [375, 390] as const) {
      // A phone has no Add filter (its one filter entry is the Filters button
      // joined to the search field): these cases move to the next picker that
      // opens as a sheet on a phone (the assignee picker).
      test.fixme(
        `Add filter opens without the keyboard and follows it once tapped at ${width}px (${locale})`,
        { tag: ['@findings', '@phone'] },
        async ({ page, baseURL }) => {
          await page.setViewportSize({ width, height: 844 })
          const touch = await page.evaluate(
            () => window.matchMedia('(pointer: coarse) and (hover: none)').matches
          )
          expect(touch, 'touch emulation').toBe(true)

          const { sheet, field } = await openAddFilter(page, locale, baseURL!)

          // No keyboard on open: the option list has focus, not the field.
          await expect
            .poll(() => page.evaluate(() => document.activeElement?.getAttribute('role')))
            .toBe('listbox')
          await expect(field).not.toBeFocused()

          // The field is pinned at the top of the sheet, right under its
          // title, and on screen.
          const top = await page.evaluate(() => {
            const sheet = document.querySelector('[data-slot="responsive-popover-sheet"]')!
            const header = sheet
              .querySelector('[data-slot="sheet-header"]')!
              .getBoundingClientRect()
            const f = sheet.querySelector('[data-slot="command-input"]')!.getBoundingClientRect()
            const s = sheet.getBoundingClientRect()
            return {
              sheetTop: Math.round(s.top),
              headerBottom: Math.round(header.bottom),
              fieldTop: Math.round(f.top),
              fieldBottom: Math.round(f.bottom),
              viewport: window.innerHeight,
            }
          })
          test.info().annotations.push({ type: 'opened', description: JSON.stringify(top) })
          expect(top.fieldTop, 'field on screen').toBeGreaterThanOrEqual(0)
          expect(top.fieldBottom, 'field on screen').toBeLessThanOrEqual(top.viewport)
          expect(
            top.fieldTop - top.headerBottom,
            'field right under the title'
          ).toBeLessThanOrEqual(16)

          // Rows sized for a finger.
          const heights = await sheet
            .locator('[data-slot="command-item"]')
            .evaluateAll((els) => els.map((el) => el.getBoundingClientRect().height))
          expect(heights.length).toBeGreaterThan(3)
          for (const h of heights) expect(Math.round(h)).toBeGreaterThanOrEqual(44)

          // The user taps the field; the keyboard opens.
          await field.tap()
          await expect(field).toBeFocused()
          for (const offsetTop of [0, 120]) {
            await keyboardUp(page, KEYBOARD_UP_HEIGHT, offsetTop)
            const band = { top: offsetTop, bottom: offsetTop + KEYBOARD_UP_HEIGHT }
            // The sheet sits on the keyboard at once (no easing behind it).
            await expect
              .poll(async () => (await visibleRows(page, band.top, band.bottom)).sheetBottom)
              .toBe(band.bottom)
            const m = await visibleRows(page, band.top, band.bottom)
            test.info().annotations.push({
              type: `keyboard up, offset ${offsetTop}`,
              description: JSON.stringify(m),
            })
            expect(m.fieldTop, 'field below the top of the visible part').toBeGreaterThanOrEqual(
              band.top
            )
            expect(m.fieldBottom, 'field above the keyboard').toBeLessThanOrEqual(band.bottom)
            expect(m.rows, 'rows visible above the keyboard').toBeGreaterThanOrEqual(3)
          }
        }
      )
    }
  }
})

for (const locale of ['en', 'vi'] as const) {
  test(
    `Add filter focuses its search field on open with a mouse at 1440px (${locale})`,
    { tag: ['@findings'] },
    async ({ page, baseURL }) => {
      await page.setViewportSize({ width: 1440, height: 900 })
      const { field } = await openAddFilter(page, locale, baseURL!)
      await expect(field).toBeFocused()
    }
  )
}
