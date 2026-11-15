import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * A list toolbar on a phone is two lines, never more (owner report
 * 2026-10-25, /findings at 390px; owner report 2026-11-15, /vulnerabilities:
 * the save-view and refresh buttons wrapped to a third line under the chips).
 * At 375px and 390px, in English and Vietnamese:
 *   1. the search field has the first line to itself;
 *   2. the second line holds the filter tokens and chips at the start and the
 *      icon actions at the end, one height and one centre line, nothing on a
 *      third line;
 *   3. tokens and chips that do not fit scroll sideways in their strip, and
 *      a strip fades at its end exactly when more is hidden past it; no chip
 *      folds away into "+N more";
 *   4. nothing overlaps, nothing sticks out of the viewport, the page does
 *      not scroll sideways.
 * On /findings the seed has no informational findings, so the quick views and
 * the count request are patched to report 12 left out, which shows the
 * locked chip.
 */

const FILTERS = ['epss_score_gte=0.5', 'cvss_score_gte=4', 'last_seen_at_gte=-P30D']
/** A drill-down link from a rule: a context chip before the filter chips. */
const DEEP_LINK = 'rule_id=example-rule'

/** The pinned icon actions at the end of the phone toolbar's second line. */
async function endBoxes(page: Page) {
  return page.evaluate(() =>
    Array.from(
      document.querySelectorAll<HTMLElement>(
        'main [data-slot="list-toolbar-end"] > *, main [data-slot="list-toolbar-tokens"] [data-slot="add-filter"]'
      )
    )
      .filter((el) => el.getBoundingClientRect().width > 0)
      .map((el) => {
        const r = el.getBoundingClientRect()
        return {
          name: (el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 24),
          top: Math.round(r.top),
          height: Math.round(r.height),
        }
      })
  )
}

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

/** Defects of the phone toolbar of the first list on the page (empty = fine). */
async function toolbarDefects(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = []
    const vw = document.documentElement.clientWidth
    const region =
      document.querySelector<HTMLElement>('main [data-slot="list-toolbar-region"]') ??
      document.querySelector<HTMLElement>('main [data-slot="list-toolbar"]')
    if (!region) return ['no toolbar']
    const visible = (el: Element) => {
      const r = el.getBoundingClientRect()
      return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden'
    }
    const search = region.querySelector('[data-slot="list-search"]')
    if (!search) return ['no search field']
    const s = search.getBoundingClientRect()
    // Strips count as one item each: what scrolls inside them is checked apart.
    const strips = Array.from(
      region.querySelectorAll<HTMLElement>(
        '[data-slot="list-toolbar-tokens"], [data-slot="filter-chips-strip"][data-scroll]'
      )
    ).filter((el) => visible(el) && getComputedStyle(el).display !== 'contents')
    const inStrip = (el: Element) => strips.some((st) => st !== el && st.contains(el))
    const items = [
      ...strips,
      ...Array.from(
        region.querySelectorAll<HTMLElement>(
          '[data-slot="list-toolbar-tokens"] > *, [data-slot="filter-chips-trailing"] > *, [data-slot="list-toolbar-end"] > *'
        )
      ).filter((el) => visible(el) && !inStrip(el) && !strips.includes(el)),
    ]
    const boxes = items.map((el) => ({
      name: (el.getAttribute('aria-label') || el.textContent || el.dataset.slot || '')
        .trim()
        .slice(0, 30),
      r: el.getBoundingClientRect(),
    }))
    for (const b of boxes) {
      if (b.r.top < s.bottom - 0.5) out.push(`"${b.name}" shares the search line`)
      if (b.r.left < -0.5 || b.r.right > vw + 0.5)
        out.push(`"${b.name}" sticks out of the viewport`)
    }
    // The second line: every item on one centre line.
    const line = boxes
    const centres = line.map((b) => b.r.top + b.r.height / 2)
    if (centres.length > 1 && Math.max(...centres) - Math.min(...centres) > 2) {
      out.push(
        `second line wraps: ${line.map((b) => `${b.name}@${Math.round(b.r.top)}`).join(', ')}`
      )
    }
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i].r
        const b = boxes[j].r
        const w = Math.min(a.right, b.right) - Math.max(a.left, b.left)
        const h = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top)
        if (w > 0.5 && h > 0.5) out.push(`"${boxes[i].name}" overlaps "${boxes[j].name}"`)
      }
    }
    for (const st of strips) {
      const overflows = st.scrollWidth > st.clientWidth + 1
      if (overflows !== (st.dataset.fadeEnd === 'true')) {
        out.push(
          `strip ${st.dataset.slot ?? 'chips'}: fade ${st.dataset.fadeEnd} but overflow ${overflows}`
        )
      }
    }
    if (region.querySelector('[data-slot="filter-chips-more"]'))
      out.push('chips folded into +N more')
    const doc = document.documentElement
    if (doc.scrollWidth > doc.clientWidth) {
      out.push(`page scrolls sideways by ${doc.scrollWidth - doc.clientWidth}px`)
    }
    return out
  })
}

for (const locale of ['en', 'vi'] as const) {
  for (const width of [390, 375] as const) {
    for (const n of [0, 1, 2, 3]) {
      test(
        `/findings toolbar at ${width}px ${locale} with the locked chip and ${n} chip(s)`,
        { tag: ['@findings'] },
        async ({ page, baseURL }, testInfo) => {
          await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
          await page.setViewportSize({ width, height: 844 })
          await patchInformationalCount(page)
          // The icon actions with no filter: where they must stay.
          await page.goto('/findings')
          await expect(page.getByTestId('informational-chip')).toBeVisible({ timeout: 45_000 })
          await page.waitForTimeout(300)
          const before = await endBoxes(page)
          expect(before.length).toBeGreaterThan(0)
          // A deep-link chip (Rule ...) and n filter chips.
          await page.goto(`/findings?${[DEEP_LINK, ...FILTERS.slice(0, n)].join('&')}`)
          const row = page.getByTestId('findings-filter-bar')
          await expect(row.getByTestId('informational-chip')).toBeVisible({ timeout: 45_000 })
          await expect(row.getByTestId('filter-chip')).toHaveCount(n)
          // Let the strips measure and the fades settle.
          await page.waitForTimeout(300)
          const defects = await toolbarDefects(page)
          await testInfo.attach(`findings-${locale}-${width}-${n}`, {
            body: await page.locator('main').screenshot(),
            contentType: 'image/png',
          })
          expect(defects).toEqual([])
          // Same row, same place and height as without filters.
          const after = await endBoxes(page)
          expect(after.map((b) => b.name)).toEqual(before.map((b) => b.name))
          after.forEach((b, i) => {
            expect(Math.abs(b.top - before[i].top), `${b.name} moved down`).toBeLessThanOrEqual(1)
            expect(b.height, `${b.name} height`).toBe(before[i].height)
          })
          // The search field fills the first line.
          const box = (await page
            .locator('main [data-slot="list-toolbar-region"], main [data-slot="list-toolbar"]')
            .first()
            .boundingBox())!
          const search = (await page
            .locator('main [data-slot="list-search"]')
            .first()
            .boundingBox())!
          expect(search.width).toBeGreaterThanOrEqual(box.width - 1)
        }
      )
    }

    test(
      `/vulnerabilities toolbar at ${width}px ${locale}: tokens and actions on one line`,
      { tag: ['@vulnerabilities'] },
      async ({ page, baseURL }, testInfo) => {
        await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
        await page.setViewportSize({ width, height: 844 })
        await page.goto('/vulnerabilities')
        const tokens = page.locator('main [data-slot="list-toolbar-tokens"]').first()
        await expect(tokens).toBeVisible({ timeout: 45_000 })
        await page.waitForLoadState('networkidle')
        await page.waitForTimeout(300)
        const defects = await toolbarDefects(page)
        await testInfo.attach(`vulnerabilities-${locale}-${width}`, {
          body: await page.locator('main').screenshot(),
          contentType: 'image/png',
        })
        expect(defects).toEqual([])
      }
    )
  }
}
