import fs from 'fs'
import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Page anatomy on EVERY page of the console (research/244, 249 R21).
 *
 * The routes are read from the app directory, so a new page is checked the
 * day it is added; nothing has to remember to list it. Each page is measured
 * at 1440px and at 390px from bounding boxes:
 *
 * - the page's blocks sit in a `PageStack`;
 * - page header to its tab strip 16px, every other gap between blocks 20px
 *   (nested stacks flattened, so a tab panel's blocks count);
 * - one tab row per page, no segmented control used as a row filter;
 * - tab icons: all tabs of a strip have one or none does, 16px; no tab label
 *   cut at the strip's edge (a strip that does not fit moves tabs to More);
 * - a metric strip: at most five tiles, each a link or a filter toggle, no
 *   sideways scroll, at most two rows on a phone;
 * - chips never wrap onto a second line and hold no " · ";
 * - an empty list shows no pagination ("Showing 0 - 0 of 0", "Page 1 of 0");
 * - a table's name column keeps a readable width at 1440px;
 * - no horizontal page scroll;
 * - the page renders: no error boundary ("Something went wrong") and no
 *   uncaught page error (a server page calling a client hook crashed
 *   /notifications on every visit with nothing visiting it).
 *
 * A page that cannot follow a rule is listed in EXCEPTIONS with the reason.
 */

const APP = path.resolve(__dirname, '../../src/app/(dashboard)')

/** Static routes of the dashboard shell, from its page files. */
function staticRoutes(): string[] {
  const out: string[] = []
  const walk = (dir: string, segs: string[]) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!e.isDirectory()) {
        if (e.name === 'page.tsx') out.push('/' + segs.filter(Boolean).join('/'))
        continue
      }
      if (e.name.startsWith('_') || e.name === '__tests__' || e.name.startsWith('@')) continue
      const seg = /^\(.*\)$/.test(e.name) ? '' : e.name
      walk(path.join(dir, e.name), [...segs, seg])
    }
  }
  walk(APP, [])
  return [...new Set(out)].filter((r) => !r.includes('[')).sort()
}

/**
 * Detail pages, opened on the first row the seeded organization has. The id
 * comes from the list endpoint through the console's own proxy.
 */
const DETAIL_ROUTES: { route: string; list: string }[] = [
  { route: '/assets/{id}', list: '/api/v1/assets?per_page=1' },
  { route: '/findings/{id}', list: '/api/v1/findings?per_page=1' },
  { route: '/scans/{id}', list: '/api/v1/scans?per_page=1' },
  { route: '/remediation/campaigns/{id}', list: '/api/v1/remediation/campaigns?per_page=1' },
]

/** Pages that are not a page of blocks, with the reason. */
const EXCEPTIONS: Record<string, string> = {
  // Not pages: they only redirect or finish a flow.
  '/settings/tenant/create': 'creates an organization, then leaves',
  '/ci-cd/github-app/callback': 'finishes the GitHub App install, then leaves',
}

/**
 * Detail and editor pages with their own header layout (DetailHeader, a
 * full-width editor): the block rhythm is not checked there, every other rule
 * is. Their text layout is covered by 30-drawer-text-layout.
 */
const OWN_LAYOUT = [/^\/findings\/(?!approvals$)[^/]+$/, /^\/remediation\/campaigns\/[^/]+$/]

const PAGE_GAP = 20
const TIGHT_GAP = 16
const NAME_MIN_1440 = 160

type Probe = {
  stack: boolean
  pairs: { from: string; to: string; gap: number }[]
  tabRows: number
  rowFilterSegmented: string[]
  strips: { tiles: number; interactive: number; overflowX: boolean; rows: number }[]
  tabStrips: { icons: number; count: number; iconSizes: number[]; clipped: string[] }[]
  wrappedChips: string[]
  middotChips: string[]
  emptyPagination: boolean
  nameColumns: { header: string; width: number }[]
  pageOverflowX: boolean
}

async function probe(page: Page): Promise<Probe> {
  return page.evaluate(() => {
    const main = document.querySelector('main') ?? document.body
    const overlay = (el: Element) =>
      !!el.closest('[role=dialog],[data-slot=sheet-content],[data-radix-popper-content-wrapper]')
    const shown = (el: Element) => {
      const r = el.getBoundingClientRect()
      const s = getComputedStyle(el)
      return r.width > 1 && r.height > 1 && s.visibility !== 'hidden' && s.display !== 'none'
    }
    const stack = main.querySelector('[data-slot="page-stack"]')
    const name = (el: Element) => el.getAttribute('data-slot') || el.tagName.toLowerCase()

    // Blocks: the stack's shown children, nested stacks flattened.
    const blocks: Element[] = []
    const walk = (el: Element) => {
      for (const c of Array.from(el.children)) {
        const cs = getComputedStyle(c)
        if (cs.display === 'contents') {
          walk(c)
          continue
        }
        if (cs.position === 'fixed' || cs.position === 'absolute' || !shown(c)) continue
        if (c.getAttribute('data-slot') === 'page-stack') walk(c)
        else blocks.push(c)
      }
    }
    if (stack) walk(stack)
    const pairs = []
    for (let i = 1; i < blocks.length; i++) {
      const a = blocks[i - 1].getBoundingClientRect()
      const b = blocks[i].getBoundingClientRect()
      if (b.top < a.bottom - 1) continue // side by side (a grid of blocks)
      pairs.push({
        from: name(blocks[i - 1]),
        to: name(blocks[i]),
        gap: Math.round(b.top - a.bottom),
      })
    }

    const strips = Array.from(
      main.querySelectorAll('nav[data-slot="page-tabs"], [role="tablist"]')
    ).filter((n) => shown(n) && !overlay(n))
    const pageRows = strips.filter((n) => !n.closest('[data-slot=card]'))
    const tabStrips = strips.map((n) => {
      const items = Array.from(
        n.matches('nav') ? n.querySelectorAll(':scope > a') : n.querySelectorAll('[role=tab]')
      ).filter(shown)
      const nr = n.getBoundingClientRect()
      const fades = n.getAttribute('data-fade-end') === 'true'
      return {
        count: items.length,
        icons: items.filter((x) => x.querySelector('svg')).length,
        iconSizes: items
          .map((x) => x.querySelector('svg')?.getBoundingClientRect().width ?? 0)
          .filter((w) => w > 0)
          .map(Math.round),
        // A Radix strip may scroll when it shows its fade; a route strip never cuts a label.
        clipped: items
          .filter((x) => {
            const r = x.getBoundingClientRect()
            return (r.right > nr.right + 1 || r.left < nr.left - 1) && !(fades && !n.matches('nav'))
          })
          .map((x) => (x.textContent ?? '').trim()),
      }
    })
    // A SegmentedLens on a page (the control that used to filter rows); radio
    // and toggle groups in forms and wizards are inputs, not row filters.
    const rowFilterSegmented = Array.from(main.querySelectorAll('[data-testid="segmented-lens"]'))
      .filter((n) => shown(n) && !overlay(n))
      .map((n) => n.getAttribute('aria-label') ?? '')

    const metricStrips = Array.from(main.querySelectorAll('[data-slot="metric-strip"]'))
      .filter(shown)
      .map((dl) => {
        const tiles = Array.from(dl.children)
        return {
          tiles: tiles.length,
          interactive: tiles.filter((t) => t.matches('a[href], button')).length,
          overflowX: dl.scrollWidth > dl.clientWidth + 1,
          rows: new Set(tiles.map((t) => Math.round(t.getBoundingClientRect().top))).size,
        }
      })

    const chips = Array.from(
      main.querySelectorAll(
        '[data-slot=badge],[data-slot=health-status],[data-slot=status-lozenge],[data-slot=signal-chip]'
      )
    ).filter((e) => shown(e) && !overlay(e))
    const wrappedChips = chips
      .filter((e) => {
        const cs = getComputedStyle(e)
        const line = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.5
        // The box height includes the border: a one-line bordered chip with
        // leading-none (SignalChip, 22px) is not a wrapped one.
        const pad =
          parseFloat(cs.paddingTop) +
          parseFloat(cs.paddingBottom) +
          (parseFloat(cs.borderTopWidth) || 0) +
          (parseFloat(cs.borderBottomWidth) || 0)
        return e.getBoundingClientRect().height > line * 1.5 + pad + 2
      })
      .map((e) => (e.textContent ?? '').trim())
    const middotChips = chips
      .filter((e) => /\s·\s/.test(e.textContent ?? ''))
      .map((e) => (e.textContent ?? '').trim())

    const nameColumns = Array.from(main.querySelectorAll('table thead th'))
      .filter(
        (th) => shown(th) && /^(name|title|asset|finding)$/i.test((th.textContent ?? '').trim())
      )
      .map((th) => ({
        header: (th.textContent ?? '').trim(),
        width: Math.round(th.getBoundingClientRect().width),
      }))

    return {
      stack: !!stack,
      pairs,
      tabRows: pageRows.length,
      rowFilterSegmented,
      strips: metricStrips,
      tabStrips,
      wrappedChips,
      middotChips,
      emptyPagination: /Page 1 of 0|Showing 0\s*[-–]\s*0 of 0/.test(main.textContent ?? ''),
      nameColumns,
      pageOverflowX: document.documentElement.scrollWidth > window.innerWidth + 1,
    }
  })
}

async function checkAt(page: Page, route: string, width: number) {
  await page.setViewportSize({ width, height: width < 600 ? 844 : 900 })
  // Let a resize settle (the tab strip re-measures what fits).
  await page.waitForTimeout(300)
  const r = await probe(page)
  const at = `${route} at ${width}px`

  const ownLayout = OWN_LAYOUT.some((re) => re.test(route.split('?')[0]))
  if (!ownLayout) expect(r.stack, `${at}: the page's blocks sit in a PageStack`).toBe(true)
  for (const p of ownLayout ? [] : r.pairs) {
    // Route tabs (page-tabs) and in-page tabs (tabs) both sit 16px under the header.
    const want =
      p.from === 'page-header' && (p.to === 'page-tabs' || p.to === 'tabs') ? TIGHT_GAP : PAGE_GAP
    expect
      .soft(Math.abs(p.gap - want), `${at}: ${p.from} -> ${p.to} is ${p.gap}px, want ${want}px`)
      .toBeLessThanOrEqual(1)
  }
  expect.soft(r.tabRows, `${at}: one tab row per page`).toBeLessThanOrEqual(1)
  expect
    .soft(r.rowFilterSegmented, `${at}: a row filter is a filter token, not a segmented control`)
    .toEqual([])
  for (const s of r.tabStrips) {
    expect.soft([0, s.count], `${at}: every tab has an icon or none has`).toContain(s.icons)
    for (const w of s.iconSizes) expect.soft(w, `${at}: tab icons are 16px`).toBe(16)
    expect.soft(s.clipped, `${at}: no tab label is cut at the strip's edge`).toEqual([])
  }
  for (const s of r.strips) {
    expect.soft(s.tiles, `${at}: at most five tiles`).toBeLessThanOrEqual(5)
    expect.soft(s.interactive, `${at}: every tile is a link or a filter toggle`).toBe(s.tiles)
    expect.soft(s.overflowX, `${at}: the strip never scrolls sideways`).toBe(false)
    if (width < 640)
      expect.soft(s.rows, `${at}: at most two rows on a phone`).toBeLessThanOrEqual(2)
  }
  expect.soft(r.wrappedChips, `${at}: chips stay on one line`).toEqual([])
  expect.soft(r.middotChips, `${at}: no " · " inside a chip`).toEqual([])
  expect.soft(r.emptyPagination, `${at}: no pagination on an empty list`).toBe(false)
  if (width >= 1440) {
    for (const c of r.nameColumns) {
      expect
        .soft(c.width, `${at}: the ${c.header} column is ${c.width}px wide`)
        .toBeGreaterThanOrEqual(NAME_MIN_1440)
    }
  }
  expect.soft(r.pageOverflowX, `${at}: no horizontal page scroll`).toBe(false)
}

async function open(page: Page, route: string): Promise<boolean> {
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => {
    // A render error the server or React reports, not a failed request.
    if (
      m.type() === 'error' &&
      /server component|useTranslation\(\) from the server|hydrat|Minified React error/i.test(
        m.text()
      )
    )
      errors.push(m.text())
  })
  const res = await page.goto(route)
  expect(res?.status() ?? 200, `${route} answers without a server error`).toBeLessThan(500)
  await expect(page.locator('main').first()).toBeVisible({ timeout: 45_000 })
  await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => {})
  await expect(
    page.getByText('Something went wrong', { exact: true }),
    `${route} renders the page, not the error boundary`
  ).toHaveCount(0)
  expect(errors, `${route} renders without a page error`).toEqual([])
  // A route that redirects is checked under the page it lands on.
  return new URL(page.url()).pathname === route.split('?')[0]
}

for (const route of staticRoutes()) {
  if (EXCEPTIONS[route]) continue
  test(`page anatomy on ${route}`, { tag: ['@shell'] }, async ({ page }, info) => {
    test.skip(!(await open(page, route)), `${route} redirects`)
    // The page renders a block layout once its header is drawn.
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 })
    for (const width of [1440, 390]) await checkAt(page, route, width)
    if (info.errors.length > 0) {
      await info.attach(route, { body: await page.screenshot(), contentType: 'image/png' })
    }
  })
}

for (const { route, list } of DETAIL_ROUTES) {
  test(`page anatomy on ${route}`, { tag: ['@shell'] }, async ({ page }) => {
    await page.goto('/')
    const id = await page.evaluate(async (url) => {
      const res = await fetch(url, { credentials: 'same-origin' })
      if (!res.ok) return null
      const body = await res.json()
      const rows = body.data ?? body.items ?? body
      return Array.isArray(rows) && rows[0]?.id ? String(rows[0].id) : null
    }, list)
    test.skip(!id, `no row to open for ${route}`)
    const url = route.replace('{id}', encodeURIComponent(id!))
    await open(page, url)
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 })
    for (const width of [1440, 390]) await checkAt(page, url, width)
  })
}
