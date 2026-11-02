import type { Page } from '@playwright/test'
import { expect } from '@playwright/test'

/**
 * Page anatomy checks, shared by every Playwright suite that walks pages: the
 * tenant app's (specs/31-page-rhythm) and the platform console's
 * (console/specs). One probe and one set of rules, so the two apps cannot
 * drift: the page's blocks sit in a PageStack, block gaps are 20px (16px from
 * the header to its tabs), one tab row, metric strips, chips, no sideways
 * scroll, no render error. The rules are described at the top of
 * specs/31-page-rhythm.spec.ts.
 */

/**
 * Settings pages that still save with a button of their own, each to move to
 * SettingsSaveBar (research/391). The list only shrinks: a page that moves is
 * removed, and a new page is never added.
 */
const SAVE_EXCEPTIONS = new Set<string>([
  '/account',
  '/account/notifications',
  '/account/preferences',
  '/settings/ai',
  '/settings/asset-sources',
  '/settings/finding-lifecycle',
  '/settings/mcp',
  '/settings/pentest',
  '/settings/scanning/content',
  '/settings/scanning/scan-approval',
  '/settings/scope',
  '/settings/trusted-organizations',
])

const PAGE_GAP = 20
const TIGHT_GAP = 16
const NAME_MIN_1440 = 160

type Probe = {
  stack: boolean
  pairs: { from: string; to: string; gap: number }[]
  tabRows: number
  rowFilterSegmented: string[]
  strips: {
    tiles: number
    interactive: number
    overflowX: boolean
    maxPhoneRows: number
    rows: number
  }[]
  tabStrips: { icons: number; count: number; iconSizes: number[]; clipped: string[] }[]
  wrappedChips: string[]
  middotChips: string[]
  emptyPagination: boolean
  nameColumns: { header: string; width: number }[]
  pageOverflowX: boolean
  restingSave: string[]
  handDenied: boolean
}

export async function probe(page: Page): Promise<Probe> {
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
    // and toggle groups in forms and wizards are inputs, not row filters, and a
    // lens in a route-lens wrapper switches between routes (navigation).
    const rowFilterSegmented = Array.from(main.querySelectorAll('[data-testid="segmented-lens"]'))
      .filter((n) => shown(n) && !overlay(n) && !n.closest('[data-slot="route-lens"]'))
      .map((n) => n.getAttribute('aria-label') ?? '')

    const metricStrips = Array.from(main.querySelectorAll('[data-slot="metric-strip"]'))
      .filter(shown)
      .map((dl) => {
        const tiles = Array.from(dl.children)
        // A tile that says why there is no figure ("Not measured") has nothing to open.
        const figures = tiles.filter((t) => t.getAttribute('data-state') !== 'not-measured')
        return {
          tiles: figures.length,
          interactive: figures.filter((t) => t.matches('a[href], button')).length,
          overflowX: dl.scrollWidth > dl.clientWidth + 1,
          // A detailed strip of five (or an odd count) takes three phone rows.
          maxPhoneRows: dl.hasAttribute('data-detailed') && tiles.length === 5 ? 3 : 2,
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
      restingSave: Array.from(main.querySelectorAll('button'))
        .filter((b) => shown(b) && !overlay(b) && !b.closest('[data-slot=settings-save-bar]'))
        .map((b) => (b.textContent ?? '').trim())
        .filter((label) => /^(Save( changes| policy| settings)?|Lưu( thay đổi)?)$/i.test(label)),
      handDenied: /Insufficient permissions|Access Denied/.test(main.textContent ?? ''),
    }
  })
}

export async function checkAt(
  page: Page,
  route: string,
  width: number,
  ownLayoutRoutes: RegExp[] = []
) {
  await page.setViewportSize({ width, height: width < 600 ? 844 : 900 })
  // Let a resize settle (the tab strip re-measures what fits).
  await page.waitForTimeout(300)
  const r = await probe(page)
  const at = `${route} at ${width}px`

  const ownLayout = ownLayoutRoutes.some((re) => re.test(route.split('?')[0]))
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
      expect.soft(s.rows, `${at}: at most two rows on a phone`).toBeLessThanOrEqual(s.maxPhoneRows)
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
  const path = route.split('?')[0]
  if (/^\/(settings|account)(\/|$)/.test(path) && !SAVE_EXCEPTIONS.has(path)) {
    expect.soft(r.restingSave, `${at}: a settings form saves through SettingsSaveBar`).toEqual([])
  }
  expect.soft(r.handDenied, `${at}: a refusal is the shared access notice`).toBe(false)
}

export async function open(page: Page, route: string): Promise<boolean> {
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
