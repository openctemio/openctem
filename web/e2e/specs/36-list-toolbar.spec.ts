import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * One list toolbar (research/267) on a sample of lists from different areas,
 * at 1440px and 390px:
 *   1. the search box is the toolbar's first control (after the Basic | Query
 *      switch on a list with Query mode, and the joined filter trigger), at
 *      the field height of "Sizes" (32, 36 below 768px), with a "Search ...…"
 *      placeholder; the switch has the same height;
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

/**
 * Lists with a search; `filter` = the list has a filter panel trigger joined
 * to the field ('phone': only below 768px, where a list with Add filter keeps
 * the joined Filters button as its one filter entry).
 */
const PAGES = [
  { route: '/sensors', filter: true },
  { route: '/scans', filter: 'phone' },
  { route: '/assets/groups', filter: 'phone' },
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
    test(
      `list toolbar on ${p.route} at ${width}px`,
      { tag: ['@shell'] },
      async ({ page }, testInfo) => {
        await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
        test.skip(!(await openToolbar(page, p.route)), `${p.route} shows no list toolbar here`)
        const toolbar = page.locator('main [data-slot="list-toolbar"]').first()
        const search = toolbar.locator('[data-slot="list-search-input"]')

        // 1. first control at the field height, placeholder pattern.
        const first = await toolbar.evaluate((el) => {
          const visible = (n: Element) => (n as HTMLElement).checkVisibility?.() ?? true
          const ctl = [...el.querySelectorAll('button, input, [role="combobox"]')]
            .filter(visible)
            // The mode switch (segments or the phone toggle) counts once.
            .map((n) => (n.closest('[data-slot="list-search-mode"]') ? 'list-search-mode' : n))
            .filter((n, i, all) => n !== 'list-search-mode' || all.indexOf(n) === i)
          return ctl
            .slice(0, 3)
            .map((n) => (typeof n === 'string' ? n : (n.getAttribute('data-slot') ?? n.tagName)))
        })
        const mode = first[0] === 'list-search-mode'
        if (mode) first.shift()
        expect(first[0] === 'list-search-input' || first[0] === 'filter-button').toBe(true)
        if (first[0] === 'filter-button') expect(first[1]).toBe('list-search-input')
        const sb = (await search.boundingBox())!
        // The field height from the theme ("Sizes"): the row height on a
        // desktop, the phone height below 768px.
        const fieldHeight = await page.evaluate(() => {
          const name = window.innerWidth < 768 ? '--control-h-touch' : '--control-h-field'
          const probe = document.createElement('div')
          probe.style.height = `var(${name})`
          document.body.append(probe)
          const h = probe.getBoundingClientRect().height
          probe.remove()
          return Math.round(h)
        })
        expect(Math.round(sb.height)).toBe(fieldHeight)
        expect(await search.getAttribute('placeholder')).toMatch(/^\S.*…$/)
        if (mode) {
          const mb = (await toolbar
            .locator('[data-slot="list-search-mode"]:visible')
            .boundingBox())!
          expect(Math.round(mb.height)).toBe(fieldHeight)
          expect(Math.abs(mb.y - sb.y)).toBeLessThanOrEqual(1)
          expect(mb.x + mb.width).toBeLessThan(sb.x)
        }

        // 2. the trigger touches the field.
        if (p.filter === true || (p.filter === 'phone' && width < 768)) {
          const trigger = toolbar.locator(
            '[data-slot="list-search"] [data-slot="filter-button"]:visible'
          )
          const tb = (await trigger.boundingBox())!
          expect(Math.abs(sb.x - (tb.x + tb.width))).toBeLessThanOrEqual(1)
          expect(Math.abs(sb.y - tb.y)).toBeLessThanOrEqual(1)
          expect(Math.round(tb.height)).toBe(fieldHeight)
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
      }
    )
  }
}

/**
 * Search field corners (owner report 2026-11-15: square left corners on a
 * desktop list whose filter trigger is not drawn at that width). Alone, the
 * field has four equal round corners; joined to a drawn trigger, the outer
 * corners stay round and the two inner ones are square.
 */
const CORNER_ROUTES = ['/findings', '/assets', '/vulnerabilities', '/scans'] as const
for (const route of CORNER_ROUTES) {
  test(
    `search field corners on ${route} follow the drawn trigger`,
    { tag: ['@shell'] },
    async ({ page }) => {
      for (const width of [1440, 1280, 1024, 768, 390]) {
        await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
        if (width === 1440)
          test.skip(!(await openToolbar(page, route)), `${route} shows no list toolbar here`)
        await page.waitForTimeout(200)
        const c = await page.evaluate(() => {
          const ls = document.querySelector('main [data-slot="list-search"]')
          const field = ls?.querySelector<HTMLElement>(
            '[data-slot="list-search-input"], [data-slot="list-search-query"] input'
          )
          if (!ls || !field) return null
          const radii = (el: Element) => {
            const s = getComputedStyle(el)
            return [
              s.borderStartStartRadius,
              s.borderStartEndRadius,
              s.borderEndEndRadius,
              s.borderEndStartRadius,
            ].map((v) => parseFloat(v))
          }
          const trigger = Array.from(ls.querySelectorAll('[data-slot="filter-button"]')).find(
            (el) => el.getClientRects().length > 0
          )
          return { field: radii(field), trigger: trigger ? radii(trigger) : null }
        })
        expect(c, `${route} @${width}: search field`).not.toBeNull()
        const [ss, se, ee, es] = c!.field
        if (!c!.trigger) {
          expect([ss, se, ee, es], `${route} @${width}: four equal round corners`).toEqual([
            se,
            se,
            se,
            se,
          ])
          expect(se).toBeGreaterThan(0)
        } else {
          expect([ss, es], `${route} @${width}: inner corners square`).toEqual([0, 0])
          expect(Math.min(se, ee), `${route} @${width}: outer corners round`).toBeGreaterThan(0)
          const [ts, te, tee, tes] = c!.trigger
          expect([te, tee], `${route} @${width}: trigger inner corners square`).toEqual([0, 0])
          expect(Math.min(ts, tes)).toBeGreaterThan(0)
        }
      }
    }
  )
}

/**
 * One filter entry per width on a list with Add filter (owner decision
 * 2026-11-15): from 768 Add filter is a separate square immediately right of
 * the search field (the field alone, four round corners), the first token
 * before Practice and State, and its picker opens under it; on a phone the
 * Filters button joined to the field is the entry and no Add filter shows.
 */
for (const route of ['/findings', '/assets'] as const) {
  test(
    `${route}: Add filter sits right after the search field`,
    { tag: ['@shell'] },
    async ({ page }) => {
      for (const width of [1440, 1280, 1024, 768, 390]) {
        await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
        if (width === 1440)
          test.skip(!(await openToolbar(page, route)), `${route} shows no list toolbar here`)
        await page.waitForTimeout(200)
        const m = await page.evaluate(() => {
          const shown = (el: Element | null) => !!el && el.getClientRects().length > 0
          const ls = document.querySelector('main [data-slot="list-search"]')!
          const add = Array.from(document.querySelectorAll('main [data-slot="add-filter"]')).find(
            shown
          )
          const joined = Array.from(ls.querySelectorAll('[data-slot="filter-button"]')).some(shown)
          const s = ls.getBoundingClientRect()
          const a = add?.getBoundingClientRect()
          const tokens = Array.from(
            document.querySelectorAll('main [data-slot="list-toolbar-tokens"] > *')
          ).filter(shown)
          return {
            add: !!add,
            joined,
            gap: a ? Math.round(a.left - s.right) : null,
            sameLine: a ? Math.abs(a.top + a.height / 2 - (s.top + s.height / 2)) <= 1 : null,
            firstToken: tokens.length === 0 || tokens[0] === add,
          }
        })
        if (width >= 768) {
          expect(m, `${route} @${width}`).toMatchObject({
            add: true,
            joined: false,
            gap: 8,
            sameLine: true,
            firstToken: true,
          })
          // Its picker opens under it.
          const add = page.locator('main [data-slot="add-filter"]').filter({ visible: true })
          await add.click()
          const pop = page
            .locator('[data-slot="popover-content"]')
            .filter({ visible: true })
            .first()
          await expect(pop).toBeVisible()
          // Measured at rest: the opening animation slides and scales it in
          // (reduced motion does not stop the popover's), so wait for it.
          await pop.evaluate((el) => Promise.all(el.getAnimations().map((a) => a.finished)))
          const pb = (await pop.boundingBox())!
          const ab = (await add.boundingBox())!
          // Directly under its button (within the offset), overlapping the
          // button's x-range (start- or end-aligned), inside the viewport.
          const at = `${route} @${width}: picker`
          expect(pb.y, `${at} under its button`).toBeGreaterThanOrEqual(ab.y + ab.height - 0.5)
          expect(pb.y, `${at} next to its button`).toBeLessThanOrEqual(ab.y + ab.height + 8)
          expect(pb.x, `${at} reaches its button`).toBeLessThan(ab.x + ab.width)
          expect(pb.x + pb.width, `${at} reaches its button`).toBeGreaterThan(ab.x)
          expect(pb.x, `${at} inside the viewport`).toBeGreaterThanOrEqual(0)
          expect(pb.x + pb.width, `${at} inside the viewport`).toBeLessThanOrEqual(width)
          await page.keyboard.press('Escape')
        } else {
          expect(m, `${route} @${width}`).toMatchObject({ add: false, joined: true })
        }
      }
    }
  )
}
