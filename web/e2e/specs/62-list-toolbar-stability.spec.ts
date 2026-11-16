import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Nothing in a list's header jumps (owner rule): on Findings, Assets and
 * Scans, at 1440, 1024, 768 and 390 px, in English and Vietnamese, every
 * control of the toolbar row and of the title row keeps its box (0 px of
 * movement, 0 px of size change) through: a filter added, five more added
 * (the chips row folds them into "+N more"), one removed, a grouping chosen,
 * a view opened, the Basic | Query mode switched, text typed in the field and
 * the filters cleared.
 *
 * Allowed, and only these:
 * - the table moves down once when the chips row first appears, and back up
 *   when it goes, by exactly the row's height plus its gap;
 * - in Query mode the filter tokens (Add filter, Practice, State) stay in
 *   place, inert (checked);
 * - the title row's start (view name, count, Modified, Save view, Reset)
 *   follows the view's name and count; its buttons are checked never to
 *   disappear, and the title row's end (Refresh, Export, More) never moves.
 *
 * Measured after the page settles (network idle, reduced motion, two frames).
 */

type Box = { x: number; y: number; w: number; h: number }
type Snap = {
  controls: Record<string, Box>
  titleEnd: Record<string, Box>
  titleStart: string[]
  listTop: number | null
  chipsRow: number | null
}

/** Six filters per list (URL params the list's chips show). */
const LISTS = {
  '/findings': {
    filters: [
      ['severity', 'critical'],
      ['priority_class', 'P0,P1'],
      ['source', 'pentest'],
      ['is_in_kev', 'true'],
      ['sla_status', 'overdue'],
      ['asset_crown_jewel', 'true'],
    ],
    group: true,
  },
  '/assets': {
    filters: [
      ['criticalities', 'high'],
      ['statuses', 'active'],
      ['environments', 'production'],
      ['has_owner', 'true'],
      ['internet_facing', 'true'],
      ['is_crown_jewel', 'true'],
    ],
    group: false,
  },
  '/scans': {
    filters: [
      ['status', 'active'],
      ['origin', 'system'],
    ],
    group: false,
  },
} as const

async function settle(page: Page) {
  await page.waitForLoadState('networkidle').catch(() => undefined)
  await page.evaluate(
    () => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r())))
  )
  await page.waitForTimeout(350)
}

async function snap(page: Page): Promise<Snap> {
  return page.evaluate(() => {
    const shown = (el: Element | null | undefined): el is HTMLElement =>
      !!el && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden'
    const box = (el: Element): { x: number; y: number; w: number; h: number } => {
      const r = el.getBoundingClientRect()
      return {
        x: Math.round(r.x),
        y: Math.round(r.y),
        w: Math.round(r.width),
        h: Math.round(r.height),
      }
    }
    const main = document.querySelector('main')!
    const toolbar = main.querySelector('[data-slot="list-toolbar"]')!
    const region = toolbar.closest('[data-slot="list-toolbar-region"]') ?? toolbar
    const controls: Record<string, Box> = {}
    const mode = Array.from(toolbar.querySelectorAll('[data-slot="list-search-mode"]')).find(shown)
    if (mode) controls['mode switch'] = box(mode)
    const field = toolbar.querySelector('[data-slot="list-search"]')
    if (shown(field)) controls['search field'] = box(field)
    Array.from(toolbar.querySelectorAll('[data-slot="list-toolbar-tokens"] > *'))
      .filter(shown)
      .forEach((el, i) => {
        controls[`token ${i + 1}`] = box(el)
      })
    Array.from(toolbar.querySelectorAll('[data-slot="list-toolbar-end"] > *'))
      .filter(shown)
      .forEach((el, i) => {
        controls[`end ${i + 1}`] = box(el)
      })
    // The title row: the buttons above the toolbar in the list's own header.
    const top = region.getBoundingClientRect().top
    const head = Array.from(main.querySelectorAll('button')).filter(
      (b) =>
        shown(b) &&
        b.getBoundingClientRect().bottom <= top &&
        !b.closest('[data-slot="list-toolbar-region"], [data-slot="list-toolbar"], nav, header')
    )
    const name = (b: HTMLElement) =>
      (b.getAttribute('aria-label') || b.textContent || '').trim().replace(/\d[\d,.]*/g, '#')
    const mid = main.getBoundingClientRect().left + main.getBoundingClientRect().width / 2
    const titleEnd: Record<string, Box> = {}
    const titleStart: string[] = []
    for (const b of head) {
      if (b.getBoundingClientRect().left >= mid) titleEnd[name(b)] = box(b)
      else titleStart.push(name(b))
    }
    // What follows the toolbar (with its chips row): the table or the cards.
    let listTop: number | null = null
    let el: Element | null = region
    while (el && listTop === null) {
      for (let n = el.nextElementSibling; n; n = n.nextElementSibling) {
        const r = n.getBoundingClientRect()
        if (r.height > 0 && getComputedStyle(n).display !== 'none') {
          listTop = Math.round(r.top)
          break
        }
      }
      el = el.parentElement
    }
    const chips = Array.from(
      region.querySelectorAll('[data-slot="list-toolbar-below"], [data-slot="filter-chips-row"]')
    ).find((c) => shown(c) && c.getBoundingClientRect().height > 0)
    return {
      controls,
      titleEnd,
      titleStart,
      listTop,
      chipsRow: chips ? Math.round(chips.getBoundingClientRect().height) : null,
    }
  })
}

function compare(step: string, a: Snap, b: Snap) {
  const problems: string[] = []
  for (const [k, v] of Object.entries(a.controls)) {
    const w = b.controls[k]
    if (!w) {
      problems.push(`${k} disappeared`)
      continue
    }
    if (v.x !== w.x || v.y !== w.y) problems.push(`${k} moved ${w.x - v.x},${w.y - v.y}`)
    if (v.w !== w.w || v.h !== w.h) problems.push(`${k} resized ${w.w - v.w}x${w.h - v.h}`)
  }
  for (const k of Object.keys(b.controls)) {
    if (!a.controls[k]) problems.push(`${k} appeared`)
  }
  for (const [k, v] of Object.entries(a.titleEnd)) {
    const w = b.titleEnd[k]
    if (!w) problems.push(`title-row "${k}" disappeared`)
    else if (v.x !== w.x || v.y !== w.y || v.w !== w.w || v.h !== w.h)
      problems.push(`title-row "${k}" moved or resized`)
  }
  for (const k of a.titleStart) {
    if (!b.titleStart.includes(k) && !/^(Save view|Reset|Modified)/i.test(k)) {
      // A view's own buttons may follow the view; the rest stay.
      problems.push(`title-row "${k}" disappeared`)
    }
  }
  if (a.listTop !== null && b.listTop !== null && a.listTop !== b.listTop) {
    const rowCame = a.chipsRow === null && b.chipsRow !== null
    const rowWent = a.chipsRow !== null && b.chipsRow === null
    const step = (b.chipsRow ?? a.chipsRow ?? 0) + 8
    const delta = b.listTop - a.listTop
    if (!((rowCame && delta === step) || (rowWent && delta === -step)))
      problems.push(`list top moved ${delta}`)
  }
  expect(problems, `${step}: ${JSON.stringify({ before: a, after: b })}`).toEqual([])
}

async function setUrl(page: Page, search: URLSearchParams) {
  await page.evaluate((qs) => {
    const url = `${window.location.pathname}${qs ? `?${qs}` : ''}`
    window.history.replaceState(window.history.state, '', url)
  }, search.toString())
  await settle(page)
}

function headerHoldsStill(route: keyof typeof LISTS) {
  const list = LISTS[route]
  for (const locale of ['en', 'vi'] as const) {
    for (const width of [1440, 1024, 768, 390]) {
      test(`${route} header holds still at ${width}px ${locale}`, async ({ page, baseURL }) => {
        test.setTimeout(150_000)
        await page.emulateMedia({ reducedMotion: 'reduce' })
        await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
        await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
        await page.goto(route)
        await page
          .locator('main [data-slot="list-search-input"]')
          .first()
          .waitFor({ state: 'visible', timeout: 45_000 })
        await settle(page)
        const params = new URLSearchParams(await page.evaluate(() => window.location.search))
        let last = await snap(page)
        const step = async (name: string, act: () => Promise<void>) => {
          await act()
          await settle(page)
          const now = await snap(page)
          compare(`${route} ${width} ${locale}: ${name}`, last, now)
          last = now
        }

        // A filter, then five more (overflow), then one removed.
        const [first, ...more] = list.filters
        await step('add a filter', async () => {
          params.set(first[0], first[1])
          await setUrl(page, params)
        })
        await step('add five more', async () => {
          for (const [k, v] of more) params.set(k, v)
          await setUrl(page, params)
        })
        await step('remove one', async () => {
          params.delete(more[more.length - 1]?.[0] ?? first[0])
          await setUrl(page, params)
        })

        // Group (where the list groups from its toolbar).
        const group = page.getByRole('combobox', { name: /^(group findings|nhóm phát hiện)/i })
        if (list.group && (await group.isVisible())) {
          await step('choose a group', async () => {
            await group.click()
            await page.getByRole('option').nth(1).click()
          })
        }

        // A view: a quick view of the list in the sidebar, then the first
        // built-in view of the Views menu.
        const quick = page.locator(`[data-slot="sidebar"] a[href^="${route}?"]:visible`).nth(1)
        if (await quick.isVisible().catch(() => false)) {
          await step('open a quick view', async () => {
            await quick.click()
            await page.waitForURL((u) => u.search !== `?${params.toString()}`)
          })
          for (const k of [...params.keys()]) params.delete(k)
          new URLSearchParams(await page.evaluate(() => window.location.search)).forEach((v, k) =>
            params.set(k, v)
          )
        }
        const views = page.getByTestId('saved-views-trigger')
        if (await views.isVisible()) {
          await views.click()
          const item = page.getByRole('menuitemcheckbox').first()
          if (await item.isVisible().catch(() => false)) {
            await step('choose a view', async () => {
              await item.click()
              await page.keyboard.press('Escape')
            })
          } else {
            await page.keyboard.press('Escape')
          }
        }

        // Basic | Query and back.
        const toQuery = page.locator(
          'main [data-slot="list-search-mode-query"]:visible, main button[data-slot="list-search-mode"]:visible'
        )
        await step('switch to Query mode', async () => {
          await toQuery.click()
          await page
            .locator('main [data-slot="list-search-query"] [role="combobox"]')
            .waitFor({ state: 'visible', timeout: 20_000 })
          await page.locator('main h1').first().click({ force: true })
        })
        // The tokens stay, inert: the text owns the filter.
        const tokens = page.locator('main [data-slot="list-toolbar-tokens"]')
        if ((await tokens.count()) > 0) await expect(tokens.first()).toHaveAttribute('inert', '')
        const toBasic = page.locator(
          'main [data-slot="list-search-mode-basic"]:visible, main button[data-slot="list-search-mode"]:visible'
        )
        await step('switch back to Basic', async () => {
          await toBasic.click()
          await page
            .locator('main [data-slot="list-search-input"]')
            .waitFor({ state: 'visible', timeout: 20_000 })
        })

        await step('type in the field', async () => {
          await page.locator('main [data-slot="list-search-input"]').fill('zz-no-match')
        })
        await step('clear the text', async () => {
          await page.locator('main [data-slot="list-search-input"]').fill('')
        })

        await step('clear the filters', async () => {
          const clear = page.locator('main [data-slot="filter-chips-clear"]:visible')
          if (await clear.isVisible()) await clear.click()
          else await setUrl(page, new URLSearchParams())
        })
      })
    }
  }
}

/**
 * A list says its count once (owner rule): one `data-slot="list-count"`
 * beside the view name, and the same number with a noun ("26 findings")
 * nowhere else on the page, with and without a filter. Not counted: the
 * pager's range (navigation), tab counts (other queues), the rows and cards,
 * and text for assistive technology only.
 */
async function countPlaces(page: Page) {
  return page.evaluate(() => {
    const main = document.querySelector('main')!
    const shown = (el: Element) => el.getClientRects().length > 0 && !el.closest('.sr-only')
    const counts = Array.from(main.querySelectorAll('[data-slot="list-count"]')).filter(shown)
    // The number as shown (the sentence for screen readers is apart).
    const shownCount = counts[0]?.querySelector('[aria-hidden="true"]') ?? counts[0]
    const text = (shownCount?.textContent ?? '').replace(/\s+/g, ' ').trim()
    const number = text.match(/^[\d.,]+\+?/)?.[0]
    const others: string[] = []
    if (number) {
      // The count's own sentence ("26 findings"): said again anywhere else is
      // the count twice. A row's "1 run" is not the list's "1 scan
      // configuration", so the noun counts too.
      const sentence = (counts[0]?.querySelector('.sr-only')?.textContent ?? '')
        .replace(/\s+/g, ' ')
        .trim()
      const esc = (sentence || number).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const re = sentence
        ? new RegExp(`(^|\\s)${esc}(\\s|$|[.,;:])`, 'iu')
        : new RegExp(`(^|\\s)${esc}\\+?\\s+\\p{L}`, 'u')
      // An action's own label ("Add all 12 matching to group") names what it
      // acts on; it is not the list's count said again.
      const skip =
        '[data-slot="list-count"], [data-slot="data-table-pager"], [role="tablist"], [data-slot="table-container"], [data-slot="mobile-card"], nav, aside, .sr-only, [role="dialog"], button, a, [role="button"]'
      const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT)
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        const el = n.parentElement
        if (!el || el.closest(skip) || !shown(el)) continue
        const line = (el.textContent ?? '').replace(/\s+/g, ' ').trim()
        if (re.test(line)) others.push(line.slice(0, 60))
      }
    }
    return { counts: counts.length, text, number, others: [...new Set(others)] }
  })
}

function saysItsCountOnce(route: keyof typeof LISTS) {
  const list = LISTS[route]
  for (const width of [1440, 390]) {
    test(`${route} says its count once at ${width}px`, async ({ page }) => {
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
      for (const qs of ['', `?${list.filters[0][0]}=${encodeURIComponent(list.filters[0][1])}`]) {
        await page.goto(`${route}${qs}`)
        await expect(page.locator('main [data-slot="list-count"]:visible')).toHaveText(/\d/, {
          timeout: 45_000,
        })
        await settle(page)
        const r = await countPlaces(page)
        test
          .info()
          .annotations.push({ type: `${route}${qs} ${width}`, description: JSON.stringify(r) })
        expect(r.counts, `${route}${qs} at ${width}: one list count`).toBe(1)
        expect(r.number, `${route}${qs} at ${width}: the count shows a number`).toMatch(/^\d/)
        expect(r.others, `${route}${qs} at ${width}: the count said again`).toEqual([])
      }
    })
  }
}

/**
 * The sidebar's quick views: on the hovered row the pin takes the count's
 * place; the count is never drawn under it (counts of 1 to 4 digits).
 */
function quickViewPinNeverCoversTheCount() {
  test('a quick view row: the pin never covers its count', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.setViewportSize({ width: 1440, height: 900 })
    const counts = [7, 26, 345, 1234]
    await page.route('**/api/v1/findings/quick-views*', async (route) => {
      const response = await route.fetch()
      const json = await response.json()
      ;(json.views ?? []).forEach((v: { count?: number }, i: number) => {
        v.count = counts[i % counts.length]
      })
      await route.fulfill({ response, json })
    })
    await page.goto('/findings')
    const rows = page.locator(
      '[data-slot="sidebar"] [data-slot="sidebar-menu-sub-item"]:has([data-slot="pin-action"])'
    )
    await expect(rows.first()).toBeVisible({ timeout: 30_000 })
    const n = Math.min(await rows.count(), counts.length)
    expect(n).toBeGreaterThan(0)
    for (let i = 0; i < n; i++) {
      const row = rows.nth(i)
      await row.hover()
      await settle(page)
      const r = await row.evaluate((li) => {
        const pin = li.querySelector('[data-slot="pin-action"]')!.getBoundingClientRect()
        const count = li.querySelector('[data-slot="nav-count"]')
        if (!count) return { text: '', overlap: false, hidden: true }
        const c = count.getBoundingClientRect()
        const hidden = getComputedStyle(count).visibility === 'hidden'
        const overlap =
          c.right > pin.left && c.left < pin.right && c.bottom > pin.top && c.top < pin.bottom
        return { text: count.textContent ?? '', overlap, hidden }
      })
      expect(r.hidden || !r.overlap, `row ${i} (count ${r.text}): the pin covers the count`).toBe(
        true
      )
    }
  })
}

/**
 * One overflow menu per page, never one of a single item: wide, the view's
 * title row ends with its buttons and Copy link sits in the page header's
 * More; narrow, Export and Task fold into the title row's More with Copy
 * link, and the header's More does not repeat it.
 */
function oneOverflowMenu() {
  for (const width of [1440, 1024]) {
    test(`one overflow menu holds Copy link at ${width}px`, async ({ page }) => {
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/findings')
      const row = page.getByTestId('findings-toolbar-primary')
      await expect(row).toBeVisible({ timeout: 30_000 })
      await settle(page)
      const rowMore = row.getByRole('button', { name: 'More actions' })
      const header = page.locator('main header, main [data-slot="page-header"]').first()
      const headerMore = header.getByRole('button', { name: 'More actions' })
      const items = async (trigger: typeof rowMore) => {
        await trigger.click()
        const menu = page.getByRole('menu')
        await expect(menu).toBeVisible()
        const names = await menu.getByRole('menuitem').allInnerTexts()
        await page.keyboard.press('Escape')
        await expect(menu).toBeHidden()
        return names.map((n) => n.trim())
      }
      const rowShown = await rowMore.isVisible()
      const rowItems = rowShown ? await items(rowMore) : []
      const headerItems = (await headerMore.isVisible()) ? await items(headerMore) : []
      test.info().annotations.push({
        type: `menus at ${width}`,
        description: JSON.stringify({ rowItems, headerItems }),
      })
      for (const list of [rowItems, headerItems])
        expect(list.length === 0 || list.length >= 2).toBe(true)
      const copyIn = [rowItems, headerItems].filter((l) => l.includes('Copy link')).length
      expect(copyIn, 'Copy link in exactly one menu').toBe(1)
      if (width === 1440) expect(rowShown, 'no title-row More when wide').toBe(false)
    })
  }
}

test.describe('Findings list header', { tag: ['@findings'] }, () => {
  headerHoldsStill('/findings')
  saysItsCountOnce('/findings')
  quickViewPinNeverCoversTheCount()
  oneOverflowMenu()
})
test.describe('Assets list header', { tag: ['@assets'] }, () => {
  headerHoldsStill('/assets')
  saysItsCountOnce('/assets')
})
test.describe('Scans list header', { tag: ['@scans'] }, () => {
  headerHoldsStill('/scans')
  saysItsCountOnce('/scans')
})
