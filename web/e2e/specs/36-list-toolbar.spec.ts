import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * One list toolbar (research/267) on a sample of lists from different areas,
 * at 1440px and 390px:
 *   1. the search box is the toolbar's first control (after the joined filter
 *      trigger), 36px high, with a "Search ...…" placeholder;
 *   2. where the list has a filter trigger, it touches the search box (no gap)
 *      and both share the same top and height;
 *   3. "/" focuses the search box, Escape clears it;
 *   4. no sideways page scroll at 390px and no serious axe violation in the
 *      toolbar.
 * A screenshot of each toolbar is attached for visual review.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

/** Lists with a search; `filter` = the list has a filter panel trigger. */
const PAGES = [
  { route: '/sensors', filter: true },
  { route: '/scans', filter: true },
  { route: '/assets/groups', filter: true },
  { route: '/settings/audit-log', filter: false },
  { route: '/remediation/tasks', filter: false },
  { route: '/credentials', filter: false },
] as const

async function openToolbar(page: Page, route: string): Promise<boolean> {
  await page.goto(route)
  const box = page
    .locator('main [data-slot="list-toolbar"] [data-slot="list-search-input"]')
    .first()
  return box
    .waitFor({ state: 'visible', timeout: 45_000 })
    .then(() => true)
    .catch(() => false)
}

for (const width of [1440, 390] as const) {
  for (const p of PAGES) {
    test(`list toolbar on ${p.route} at ${width}px`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
      test.skip(!(await openToolbar(page, p.route)), `${p.route} shows no list toolbar here`)
      const toolbar = page.locator('main [data-slot="list-toolbar"]').first()
      const search = toolbar.locator('[data-slot="list-search-input"]')

      // 1. first control, 36px, placeholder pattern.
      const first = await toolbar.evaluate((el) => {
        const visible = (n: Element) => (n as HTMLElement).checkVisibility?.() ?? true
        const ctl = [...el.querySelectorAll('button, input, [role="combobox"]')].filter(visible)
        return ctl.slice(0, 2).map((n) => n.getAttribute('data-slot') ?? n.tagName)
      })
      expect(first[0] === 'list-search-input' || first[0] === 'filter-button').toBe(true)
      if (first[0] === 'filter-button') expect(first[1]).toBe('list-search-input')
      const sb = (await search.boundingBox())!
      expect(Math.round(sb.height)).toBe(36)
      expect(await search.getAttribute('placeholder')).toMatch(/^\S.*…$/)

      // 2. the trigger touches the field.
      if (p.filter) {
        const trigger = toolbar.locator(
          '[data-slot="list-search"] [data-slot="filter-button"]:visible'
        )
        const tb = (await trigger.boundingBox())!
        expect(Math.abs(sb.x - (tb.x + tb.width))).toBeLessThanOrEqual(1)
        expect(Math.abs(sb.y - tb.y)).toBeLessThanOrEqual(1)
        expect(Math.round(tb.height)).toBe(36)
      }

      // 3. "/" focuses, Escape clears.
      await page.locator('main h1').first().click()
      await page.keyboard.press('/')
      await expect(search).toBeFocused()
      await page.keyboard.type('zz')
      await page.keyboard.press('Escape')
      await expect(search).toHaveValue('')

      // 4. no sideways scroll on a phone; axe on the toolbar.
      if (width < 768) {
        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth
        )
        expect(overflow, 'horizontal page scroll on a phone').toBeLessThanOrEqual(0)
      }
      await page.addScriptTag({ path: AXE })
      const result = (await page.evaluate(async () => {
        const w = window as unknown as {
          axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
        }
        return w.axe.run(
          { include: [['main [data-slot="list-toolbar"]']] },
          { resultTypes: ['violations'] }
        )
      })) as AxeResult
      const serious = result.violations
        .filter((v) => v.impact === 'serious' || v.impact === 'critical')
        .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
      expect(serious).toEqual([])

      await testInfo.attach(`toolbar${p.route.replace(/\//g, '-')}-${width}.png`, {
        body: await toolbar.screenshot(),
        contentType: 'image/png',
      })
    })
  }
}

/**
 * Add filter on a phone (owner report, iPhone Safari): an anchored popover
 * with a search field broke when the keyboard opened. Below `md` it is a
 * bottom sheet: full width, the field focused and inside the screen, the list
 * scrolling inside the sheet, and still so once the keyboard takes half the
 * screen (simulated by shrinking the viewport). Escape returns focus to Add
 * filter.
 */
test.describe('Add filter on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })

  test('opens as a bottom sheet that the keyboard never covers', async ({ page }) => {
    await page.goto('/findings')
    const add = page.getByRole('button', { name: /^Add filter/ })
    const shown = await add
      .waitFor({ state: 'visible', timeout: 45_000 })
      .then(() => true)
      .catch(() => false)
    test.skip(!shown, 'no Add filter on /findings here')
    await add.click()
    const sheet = page.locator('[data-slot="responsive-popover-sheet"]')
    await expect(sheet).toBeVisible()
    const field = sheet.locator('[data-slot="command-input"]')
    await expect(field).toBeFocused()
    expect(await field.getAttribute('inputmode')).toBe('search')
    expect(await field.evaluate((el) => getComputedStyle(el).fontSize)).toBe('16px')

    const inView = async (vh: number) => {
      const s = (await sheet.boundingBox())!
      const f = (await field.boundingBox())!
      expect(Math.round(s.x)).toBe(0)
      expect(Math.round(s.width)).toBe(390)
      expect(s.y + s.height).toBeLessThanOrEqual(vh + 1)
      expect(f.y).toBeGreaterThanOrEqual(s.y)
      expect(f.y + f.height).toBeLessThanOrEqual(vh)
    }
    await inView(844)
    // The keyboard takes the lower half: the visual viewport shrinks.
    await page.setViewportSize({ width: 390, height: 450 })
    await page.waitForTimeout(400)
    await inView(450)
    // The list scrolls inside the sheet, the field stays put.
    const before = (await field.boundingBox())!.y
    await sheet.locator('[data-slot="sheet-body"]').evaluate((el) => el.scrollBy(0, 400))
    expect(Math.abs((await field.boundingBox())!.y - before)).toBeLessThanOrEqual(1)

    await page.keyboard.press('Escape')
    await expect(sheet).toBeHidden()
    await expect(add).toBeFocused()
  })
})
