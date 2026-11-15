import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Every shared table keeps its column header in view. When the table fits
 * (Mode A) the page scrolls and the header cells stick under the app header,
 * at the top of <main>, the page's scroller. When the table is wider than its
 * frame (Mode B) the frame scrolls on both axes and the header cells stick to
 * the frame's top. Skips a route whose list is too short to scroll here.
 */

const ROUTES = [
  { path: '/findings', tag: '@findings' },
  { path: '/assets', tag: '@assets' },
  { path: '/settings/members', tag: '@settings' },
]

/** Scrolls the table's scroller and returns where the first header cell sits against its top. */
async function headerAfterScroll(page: Page) {
  return page.evaluate(async () => {
    const frame = document.querySelector<HTMLElement>('main [data-scroll-mode]')
    const th = frame?.querySelector<HTMLElement>('thead th')
    const main = document.querySelector('main')
    if (!frame || !th || !main) return null
    const mode = frame.dataset.scrollMode
    const container = frame.querySelector<HTMLElement>('[data-slot="table-container"]')!
    const scroller: HTMLElement = mode === 'scroll' ? container : main
    const top = () => scroller.getBoundingClientRect().top
    // Mode B: bring the frame to the top of the page first, then scroll inside it.
    if (mode === 'scroll') {
      main.scrollTop += container.getBoundingClientRect().top - main.getBoundingClientRect().top
    }
    const before = th.getBoundingClientRect().top - top()
    const room = scroller.scrollHeight - scroller.clientHeight
    const table = th.closest('table')!
    const tableBottom = table.getBoundingClientRect().bottom - top()
    const by = Math.min(room, before + 120, tableBottom - 80)
    if (by <= before + 8) return { mode, scrolled: false, offset: 0 }
    scroller.scrollTop += by
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
    return { mode, scrolled: true, offset: Math.round(th.getBoundingClientRect().top - top()) }
  })
}

for (const { path, tag } of ROUTES) {
  for (const width of [1440, 1024]) {
    test(
      `${path} at ${width}: the column header stays at the top of what scrolls`,
      { tag: [tag] },
      async ({ page }) => {
        await page.setViewportSize({ width, height: 420 })
        await page.goto(path)
        await page.waitForLoadState('networkidle')
        const table = page.locator('main table').first()
        test.skip(!(await table.isVisible().catch(() => false)), 'No table on this stack')

        const r = await headerAfterScroll(page)
        test.skip(!r || !r.scrolled, 'List too short to scroll on this stack')
        expect(Math.abs(r!.offset), `header cell top (mode ${r!.mode})`).toBeLessThanOrEqual(1)
      }
    )
  }
}
