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
        // At least the second line it keeps for the next condition.
        const growth = open.height - before.height
        expect(growth).toBeGreaterThanOrEqual(18)
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
  test('follows its text within 2 to 8 lines and breaks lines at spaces only', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 768 })
    await page.goto('/findings')
    await page
      .locator(
        '[data-slot="list-search-mode-query"]:visible, button[data-slot="list-search-mode"]:visible'
      )
      .click()
    const field = page.locator('[data-slot="list-search-query"] [role="combobox"]')
    await expect(field).toBeEnabled({ timeout: 20_000 })
    // The one-line field is one line plus the editor's frame (paddings, borders).
    const oneLine = (await box(field)).height
    await page.getByRole('button', { name: /expand the editor/i }).click()
    const editor = page.locator('[data-slot="query-editor-expanded"] textarea')
    await settled(page)
    const lineH = await editor.evaluate((el) => parseFloat(getComputedStyle(el).lineHeight))
    // Two lines for a short text.
    await editor.fill('state=open')
    await settled(page)
    expect(Math.round((await box(editor)).height)).toBe(Math.round(oneLine + lineH))
    // A long text: eight lines at most, then it scrolls inside.
    await editor.fill(Array(40).fill('severity>=high state=open').join(' '))
    await settled(page)
    expect(Math.round((await box(editor)).height)).toBe(Math.round(oneLine + 7 * lineH))
    expect(
      await editor.evaluate((el: HTMLTextAreaElement) => el.scrollHeight > el.clientHeight)
    ).toBe(true)
    // No condition is cut across two lines: each one's boxes share one top.
    const split = await page.evaluate(() => {
      const copy = document.querySelector('[data-slot="query-highlight"]')!
      const text = copy.textContent ?? ''
      const walker = document.createTreeWalker(copy, NodeFilter.SHOW_TEXT)
      const nodes: { node: Text; start: number }[] = []
      let at = 0
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        nodes.push({ node: n as Text, start: at })
        at += (n as Text).length
      }
      const point = (i: number) => {
        let hit = nodes[0]
        for (const x of nodes) if (x.start <= i) hit = x
        return [hit.node, i - hit.start] as const
      }
      const cut: string[] = []
      for (const m of text.matchAll(/\S+/g)) {
        const range = document.createRange()
        range.setStart(...point(m.index))
        range.setEnd(...point(m.index + m[0].length - 1))
        const tops = new Set(
          Array.from(range.getClientRects())
            .filter((r) => r.width > 0)
            .map((r) => Math.round(r.top))
        )
        if (tops.size > 1) cut.push(m[0])
      }
      return cut
    })
    expect(split).toEqual([])
  })
})
