import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * A list toolbar on a phone is two lines, never more (owner report
 * 2026-10-25, /findings at 390px; owner report 2026-11-15, /vulnerabilities:
 * the save-view and refresh buttons wrapped to a third line under the chips).
 * At 375px and 390px, in English and Vietnamese:
 *   1. the first line holds the search field and the icon actions (Views,
 *      Group) at its end, one centre line (owner report 2026-11-19: Views
 *      alone on a second line);
 *   2. the second line starts with the filter tokens, the chips after them
 *      (owner report 2026-11-20: tokens pushed to the end of an otherwise
 *      empty line), one height and one centre line, nothing on a third line;
 *   3. no filter token sits in a sideways strip (owner report 2026-11-20,
 *      /assets Activity: "Last 7 d..." cut at the strip's edge read as hidden
 *      buttons): the tokens are in the Filters sheet, and the ones that filter
 *      stay drawn on the second line; the chips wrap onto more lines when they
 *      do not fit (owner decision 2026-11-20: no chip hidden past an edge, no
 *      sideways scroll, no chip folds away into "+N more");
 *   4. nothing overlaps, nothing sticks out of the viewport, the page does
 *      not scroll sideways.
 * On /findings the seed has no informational findings, so the quick views and
 * the count request are patched to report 12 left out, which shows the
 * locked chip.
 */

const FILTERS = ['epss_score_gte=0.5', 'cvss_score_gte=4', 'last_seen_at_gte=-P30D']
/** A drill-down link from a rule: a context chip before the filter chips. */
const DEEP_LINK = 'rule_id=example-rule'

/** The pinned icon actions at the end of the phone toolbar's first line, and Add filter. */
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
      region.querySelectorAll<HTMLElement>('[data-slot="list-toolbar-tokens"]')
    ).filter((el) => visible(el) && getComputedStyle(el).display !== 'contents')
    const inStrip = (el: Element) => strips.some((st) => st !== el && st.contains(el))
    const box = (el: HTMLElement) => ({
      name: (el.getAttribute('aria-label') || el.textContent || el.dataset.slot || '')
        .trim()
        .slice(0, 30),
      r: el.getBoundingClientRect(),
    })
    const items = [
      ...strips,
      ...Array.from(
        region.querySelectorAll<HTMLElement>(
          '[data-slot="list-toolbar-tokens"] > *, [data-slot="filter-chips-trailing"] > *'
        )
      ).filter((el) => visible(el) && !inStrip(el) && !strips.includes(el)),
    ]
    const boxes = items.map(box)
    // The first line: the icon actions end the search's line, on its centre.
    const actions = Array.from(
      region.querySelectorAll<HTMLElement>('[data-slot="list-toolbar-end"] > *')
    )
      .filter(visible)
      .map(box)
    const searchCentre = s.top + s.height / 2
    for (const a of actions) {
      if (Math.abs(a.r.top + a.r.height / 2 - searchCentre) > 2)
        out.push(`"${a.name}" is not on the search line`)
      if (a.r.left < s.right - 0.5) out.push(`"${a.name}" overlaps the search field`)
    }
    for (const b of [...boxes, ...actions]) {
      if (b.r.left < -0.5 || b.r.right > vw + 0.5)
        out.push(`"${b.name}" sticks out of the viewport`)
    }
    for (const b of boxes) {
      if (b.r.top < s.bottom - 0.5) out.push(`"${b.name}" shares the search line`)
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
      // At rest a strip starts at its first item, fully inside its start edge
      // (owner report 2026-11-15: "nformational hidden" cut at the start, no
      // fade); only the end may fade. No box around it is shifted sideways.
      const name = st.dataset.slot ?? 'chips'
      if (Math.abs(st.scrollLeft) > 0.5)
        out.push(`strip ${name}: scrolled ${st.scrollLeft}px at rest`)
      if (st.dataset.fadeStart === 'true') out.push(`strip ${name}: fades at its start at rest`)
      const first = Array.from(st.querySelectorAll<HTMLElement>(':scope > *, :scope > * > *'))
        .filter(visible)
        .sort((a, b) => a.getBoundingClientRect().left - b.getBoundingClientRect().left)[0]
      const edge = st.getBoundingClientRect().left
      if (first && first.getBoundingClientRect().left < edge - 0.5)
        out.push(`strip ${name}: first item cut at the start`)
      for (let p = st.parentElement; p && p.tagName !== 'MAIN'; p = p.parentElement) {
        if (p.scrollLeft !== 0) out.push(`strip ${name}: ${p.dataset.slot ?? p.tagName} scrolled`)
      }
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
          // One filter entry on a phone (the Filters button joined to the
          // field): no Add filter and no list "..." in the toolbar, whose
          // pinned group is Views and Group (Select is in the list's More).
          await expect(
            page.locator('main [data-slot="add-filter"]').filter({ visible: true })
          ).toHaveCount(0)
          await expect(page.locator('main [data-slot="table-phone-more"]')).toHaveCount(0)
          expect(before).toHaveLength(2)
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
          // The row clips: focus or scrollIntoView cannot shift it sideways.
          const shifted = await page.evaluate(() => {
            const r = document.querySelector<HTMLElement>(
              'main [data-testid="findings-filter-bar"]'
            )
            if (!r) return -1
            r.scrollLeft = 40
            return r.scrollLeft
          })
          expect(shifted).toBe(0)
          // A leading chip wider than the strip shortens: it ends inside the strip.
          const lead = await page.evaluate(() => {
            const strip = document.querySelector('main [data-slot="filter-chips-strip"]')
            const chip = document.querySelector('main [data-testid="informational-chip"]')
            if (!strip || !chip) return null
            return chip.getBoundingClientRect().width - strip.getBoundingClientRect().width
          })
          expect(lead ?? 0).toBeLessThanOrEqual(0.5)
          // Same row, same place and height as without filters.
          const after = await endBoxes(page)
          expect(after.map((b) => b.name)).toEqual(before.map((b) => b.name))
          after.forEach((b, i) => {
            expect(Math.abs(b.top - before[i].top), `${b.name} moved down`).toBeLessThanOrEqual(1)
            expect(b.height, `${b.name} height`).toBe(before[i].height)
          })
          // The search field fills the first line up to the icon actions
          // (after the Basic | Query toggle, on a list with Query mode).
          const box = (await page
            .locator('main [data-slot="list-toolbar-region"], main [data-slot="list-toolbar"]')
            .first()
            .boundingBox())!
          const search = (await page
            .locator('main [data-slot="list-search"]')
            .first()
            .boundingBox())!
          const mode = await page
            .locator('main [data-slot="list-search-mode"]:visible')
            .boundingBox()
          const start = mode ? mode.x + mode.width + 8 : box.x
          expect(Math.abs(search.x - start)).toBeLessThanOrEqual(1)
          const actions = (await page
            .locator('main [data-slot="list-toolbar-end"]')
            .first()
            .boundingBox())!
          expect(Math.abs(search.x + search.width + 8 - actions.x)).toBeLessThanOrEqual(1)
          expect(actions.x + actions.width).toBeGreaterThanOrEqual(box.x + box.width - 1)
        }
      )
    }

    test(
      `/vulnerabilities toolbar at ${width}px ${locale}: actions on the search line, tokens on one line`,
      { tag: ['@vulnerabilities'] },
      async ({ page, baseURL }, testInfo) => {
        await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
        await page.setViewportSize({ width, height: 844 })
        await page.goto('/vulnerabilities')
        // Ready when the end actions are drawn. On a phone both selects of
        // this list live in the Filters sheet, so its token strip may hold
        // nothing and has no width (it starts the second line); toolbarDefects
        // checks whatever the line holds.
        const end = page.locator('main [data-slot="list-toolbar-end"]').first()
        await expect(end).toBeVisible({ timeout: 45_000 })
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

/**
 * The phone's one filter entry (the Filters button joined to the search field)
 * opens the Filters sheet. Kit policy on touch: nothing focuses a text field
 * on open (no keyboard until the user taps one), and a search field in the
 * sheet stays on screen once the keyboard is up (emulated by shrinking the
 * viewport to the part the keyboard leaves).
 */
for (const width of [390, 375] as const) {
  test.describe(`Filters sheet on a phone at ${width}px`, { tag: ['@findings'] }, () => {
    test.use({ hasTouch: true, isMobile: true })

    test('opens without focusing a text field; its search stays visible with the keyboard up', async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: 844 })
      await page.goto('/findings')
      const button = page
        .locator('main [data-slot="list-search"] [data-slot="filter-button"]')
        .filter({ visible: true })
      await expect(button).toBeVisible({ timeout: 45_000 })
      await button.click()
      const sheet = page.getByRole('dialog').filter({ visible: true }).last()
      await expect(sheet).toBeVisible()
      await page.waitForTimeout(500)
      const focusedTextField = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null
        return !!el && el.matches('input:not([type=checkbox]):not([type=radio]), textarea')
      })
      expect(focusedTextField, 'a text field has focus on open').toBe(false)
      const search = sheet
        .locator('input[type="search"], [role="searchbox"], [data-slot="command-input"]')
        .first()
      if ((await search.count()) > 0 && (await search.isVisible())) {
        await search.tap()
        await page.setViewportSize({ width, height: 420 })
        await page.waitForTimeout(500)
        const b = (await search.boundingBox())!
        expect(b.y).toBeGreaterThanOrEqual(0)
        expect(b.y + b.height).toBeLessThanOrEqual(420)
      }
    })
  })
}
