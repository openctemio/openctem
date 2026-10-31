import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The filter chips row under the list toolbar on a phone (owner report
 * 2026-10-25, /findings at 390px): the locked "Informational hidden / Show"
 * chip was drawn under the next chip. At 390px and 375px, with the locked chip
 * and one to three filter chips:
 *   1. no two items of the row overlap (locked chip, chips, "+N more", Add
 *      filter, the count) and none sticks out of the row;
 *   2. every filter chip is either shown or counted in "+N more";
 *   3. the page does not scroll sideways;
 *   4. the search box takes the toolbar's first line (the end buttons move
 *      under it), so its placeholder is not cut short.
 * The seed has no informational findings, so the quick views and the count
 * request are patched to report 12 left out, which shows the locked chip.
 */

const FILTERS = ['epss_score_gte=0.5', 'cvss_score_gte=4', 'last_seen_at_gte=-P30D']

async function patchInformationalCount(page: Page) {
  await page.route('**/api/v1/findings/quick-views*', async (route) => {
    const response = await route.fetch()
    const json = await response.json()
    json.include_informational = false
    for (const v of json.views ?? []) v.informational_hidden = 12
    await route.fulfill({ response, json })
  })
  await page.route(
    (url) =>
      url.pathname === '/api/v1/findings' &&
      url.searchParams.get('informational') === 'true' &&
      url.searchParams.get('per_page') === '1',
    async (route) => {
      const response = await route.fetch()
      const json = await response.json()
      json.total = 12
      await route.fulfill({ response, json })
    }
  )
}

for (const width of [390, 375] as const) {
  for (const n of [1, 2, 3]) {
    test(
      `filter chips row at ${width}px with the locked chip and ${n} chip(s)`,
      { tag: ['@findings'] },
      async ({ page }, testInfo) => {
        await page.setViewportSize({ width, height: 844 })
        await patchInformationalCount(page)
        await page.goto(`/findings?${FILTERS.slice(0, n).join('&')}`)
        const row = page.getByTestId('findings-filter-bar')
        await expect(row.getByTestId('informational-chip')).toBeVisible({ timeout: 45_000 })
        await expect(row.locator('[data-slot="filter-chips-end"]')).toBeVisible()
        // Folding settles after the chips are measured.
        await expect
          .poll(async () => {
            const shown = await row.getByTestId('filter-chip').count()
            const more = await row
              .locator('[data-slot="filter-chips-more"]')
              .textContent({
                timeout: 500,
              })
              .catch(() => null)
            return shown + (more ? Number(more.replace(/\D/g, '')) : 0)
          })
          .toBe(n)

        const defects = await row.evaluate((el) => {
          const items = Array.from(
            el.querySelectorAll<HTMLElement>(
              '[data-slot="locked-chip"], li[data-chip-key], [data-slot="filter-chips-more"], [data-slot="filter-chips-trailing"] > *, [data-slot="filter-chips-end"]'
            )
          )
            .map((e) => ({
              name: e.textContent?.trim().slice(0, 30) ?? '',
              r: e.getBoundingClientRect(),
            }))
            .filter((b) => b.r.width > 0)
          const rr = el.getBoundingClientRect()
          const out: string[] = []
          for (let i = 0; i < items.length; i++) {
            const a = items[i]
            if (a.r.left < rr.left - 0.5 || a.r.right > rr.right + 0.5) {
              out.push(`"${a.name}" sticks out of the row`)
            }
            for (let j = i + 1; j < items.length; j++) {
              const b = items[j]
              const w = Math.min(a.r.right, b.r.right) - Math.max(a.r.left, b.r.left)
              const h = Math.min(a.r.bottom, b.r.bottom) - Math.max(a.r.top, b.r.top)
              if (w > 0.5 && h > 0.5) out.push(`"${a.name}" overlaps "${b.name}"`)
            }
          }
          const doc = document.documentElement
          if (doc.scrollWidth > doc.clientWidth) {
            out.push(`page scrolls sideways by ${doc.scrollWidth - doc.clientWidth}px`)
          }
          return out
        })
        await testInfo.attach(`chips-${width}-${n}`, {
          body: await row.screenshot(),
          contentType: 'image/png',
        })
        expect(defects).toEqual([])

        // The search box and its joined filter trigger fill the toolbar's first line.
        // On a phone with a chips row the toolbar lends its controls to the
        // region around it (`display: contents`, no box of its own): measure
        // the region.
        const toolbar = page.locator('main [data-slot="list-toolbar"]').first()
        const toolbarBox = page
          .locator('main [data-slot="list-toolbar-region"], main [data-slot="list-toolbar"]')
          .first()
        await expect(toolbarBox).toBeVisible()
        const tb = (await toolbarBox.boundingBox())!
        const search = (await toolbar.locator('[data-slot="list-search"]').boundingBox())!
        expect(search.width).toBeGreaterThanOrEqual(tb.width - 1)
      }
    )
  }
}
