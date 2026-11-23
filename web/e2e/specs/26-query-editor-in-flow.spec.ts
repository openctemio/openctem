import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The expanded query editor grows in place, in the page's flow: the field
 * keeps its left edge and width, the list below moves down by exactly the
 * editor's growth (nothing overlays it), the toolbar's other controls keep
 * their places, and folding brings the list back to the same position. On
 * findings, at 1440, 1024 and 390 (touch), in English and Vietnamese. Needs
 * no particular data.
 */

// What follows the toolbar in the page (the chips row or the list: table or
// phone cards): the first visible next sibling of the toolbar (with its chips
// row) or of one of its ancestors.
async function listBox(page: Page) {
  const b = await page.evaluate(() => {
    const search = document.querySelector('[data-slot="list-search"]')
    let el: Element | null =
      search?.closest('[data-slot="list-toolbar-region"]') ??
      search?.closest('[data-slot="list-toolbar"]') ??
      null
    while (el) {
      for (let n = el.nextElementSibling; n; n = n.nextElementSibling) {
        const r = n.getBoundingClientRect()
        if (r.height > 0 && getComputedStyle(n).display !== 'none')
          return { x: r.x, y: r.y, width: r.width, height: r.height }
      }
      el = el.parentElement
    }
    return null
  })
  expect(b).not.toBeNull()
  return b!
}

async function box(l: Locator) {
  const b = await l.boundingBox()
  expect(b).not.toBeNull()
  return b!
}

async function settled(page: Page) {
  // The height animates for 200 ms.
  await page.waitForTimeout(400)
}

for (const [width, height, touch] of [
  [1440, 900, false],
  [1024, 768, false],
  [390, 844, true],
] as const) {
  test.describe(`Expanded query editor in the flow (${width})`, { tag: ['@findings'] }, () => {
    test.use({ viewport: { width, height }, isMobile: touch, hasTouch: touch })
    for (const locale of ['en', 'vi'] as const) {
      test(`grows in place and pushes the list down, ${width} ${locale}`, async ({
        page,
        baseURL,
      }) => {
        await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
        await page.goto('/findings')
        // The Query segment (from 768) or the phone's toggle.
        await page
          .locator(
            '[data-slot="list-search-mode-query"]:visible, button[data-slot="list-search-mode"]:visible'
          )
          .click()
        const field = page.locator('[data-slot="list-search-query"] [role="combobox"]')
        await expect(field).toBeEnabled({ timeout: 20_000 })
        await page.waitForLoadState('networkidle')
        await field.blur()
        const before = await box(field)
        const listBefore = await listBox(page)
        const mode = page.locator('[data-slot="list-search-mode"]:visible')
        const modeBefore = await box(mode)

        const controls = page.locator('[data-slot="query-field-controls"]')
        if (touch) {
          await controls
            .getByRole('button', { name: /more query options|thêm tùy chọn truy vấn/i })
            .tap()
          await page.getByRole('menuitem', { name: /expand the editor|mở rộng trình soạn/i }).tap()
        } else {
          await controls
            .getByRole('button', { name: /expand the editor|mở rộng trình soạn/i })
            .click()
        }
        const editor = page.locator('[data-slot="query-editor-expanded"] textarea')
        await expect(editor).toBeVisible()
        await settled(page)
        const open = await box(editor)
        const listOpen = await listBox(page)

        // Same slot: left edge and width; taller.
        expect(Math.abs(open.x - before.x)).toBeLessThanOrEqual(1)
        expect(Math.abs(open.width - before.width)).toBeLessThanOrEqual(1)
        const growth = open.height - before.height
        expect(growth).toBeGreaterThan(40)
        // The list moved down by the growth and nothing overlaps it.
        expect(Math.abs(listOpen.y - listBefore.y - growth)).toBeLessThanOrEqual(2)
        expect(open.y + open.height).toBeLessThanOrEqual(listOpen.y)
        // The mode switch and the field's own controls stay on the first line.
        expect(await box(mode)).toEqual(modeBefore)
        const c = await box(controls)
        expect(c.y).toBeGreaterThanOrEqual(open.y)
        expect(c.y + c.height).toBeLessThanOrEqual(open.y + before.height)
        // No auto-focus on touch beyond the tap that expanded it.
        if (touch) await expect(editor).not.toBeFocused()

        // Fold: the list returns to exactly where it was.
        await controls
          .getByRole('button', { name: /collapse the editor|thu gọn trình soạn/i })
          .click()
        await settled(page)
        await expect(page.locator('[data-slot="query-editor-expanded"]')).toHaveCount(0)
        expect((await listBox(page)).y).toBe(listBefore.y)
        expect(await box(field)).toEqual(before)
      })
    }
  })
}

test.describe('Expanded query editor height', { tag: ['@findings'] }, () => {
  test('a dragged height is kept for next time, within 4 to 16 lines', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings')
    await page.getByRole('button', { name: /^query$/i }).click()
    const field = page.locator('[data-slot="list-search-query"] [role="combobox"]')
    await expect(field).toBeEnabled({ timeout: 20_000 })
    await page.getByRole('button', { name: /expand the editor/i }).click()
    const editor = page.locator('[data-slot="query-editor-expanded"] textarea')
    await settled(page)
    // A drag, as the resize handle does it.
    await editor.evaluate((el: HTMLTextAreaElement) => (el.style.height = '120px'))
    await settled(page)
    expect(await page.evaluate(() => localStorage.getItem('query-editor-height'))).toBe('120')
    await page.getByRole('button', { name: /collapse the editor/i }).click()
    await settled(page)
    await page.getByRole('button', { name: /expand the editor/i }).click()
    await settled(page)
    expect(Math.round((await box(editor)).height)).toBe(120)
    // 16 lines at most (20 px lines, 6 px paddings, 1 px borders).
    await editor.evaluate((el: HTMLTextAreaElement) => (el.style.height = '2000px'))
    await settled(page)
    expect((await box(editor)).height).toBeLessThanOrEqual(16 * 20 + 14)
  })
})
