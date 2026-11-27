import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Below 768 px the page reserves no scrollbar gutter. With `scrollbar-gutter:
 * stable` on the document, a narrow desktop window (classic scrollbars) kept
 * 10 px free at the right of the layout viewport, so a full-width sheet ended
 * 10 px short of the screen's right edge and a menu's 16 px gutter was
 * measured from that shorter edge. Phones use overlay scrollbars and never
 * showed it.
 *
 * At 700 x 900 in desktop Chromium: the finding sheet reaches the right edge
 * of the window, and its More menu keeps 16 px from that edge.
 */

const GUTTER = 16

async function settledRect(el: Locator) {
  let last = ''
  await expect
    .poll(async () => {
      const now = await el.evaluate((n) => {
        const b = n.getBoundingClientRect()
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

async function anyFindingId(page: Page): Promise<string | null> {
  return page.evaluate(async () => {
    const res = await fetch('/api/v1/findings?per_page=5')
    const body = (await res.json().catch(() => null)) as { data?: Array<{ id: string }> } | null
    return body?.data?.[0]?.id ?? null
  })
}

test(
  'A sheet in a narrow desktop window reaches the right edge; its menu keeps the gutter',
  { tag: ['@findings', '@phone'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const id = await anyFindingId(page)
    test.skip(!id, 'No finding: seed findings to enable this test')

    await page.setViewportSize({ width: 700, height: 900 })
    await page.emulateMedia({ reducedMotion: 'reduce' })
    // The page reads the hash once, on load: leave first so this is a load.
    await page.goto('about:blank')
    await page.goto(`/findings#finding=${id}`)
    const sheet = page.getByRole('dialog')
    await expect(sheet).toBeVisible({ timeout: 45_000 })

    const width = await page.evaluate(() => window.innerWidth)
    const s = await settledRect(sheet)
    test.info().annotations.push({ type: 'sheet', description: JSON.stringify({ width, s }) })
    expect(s.right, 'sheet reaches the right edge of the window').toBe(width)

    const more = sheet.getByRole('button', { name: 'More actions' })
    await expect(more).toBeVisible()
    await more.click()
    const menu = page.getByRole('menu')
    await expect(menu).toBeVisible()
    const m = await settledRect(menu)
    test.info().annotations.push({ type: 'menu', description: JSON.stringify(m) })
    expect(m.right, 'menu keeps the gutter from the window edge').toBeLessThanOrEqual(
      width - GUTTER
    )
    expect(m.left).toBeGreaterThanOrEqual(GUTTER)
  }
)
