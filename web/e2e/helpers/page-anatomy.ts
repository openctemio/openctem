import fs from 'fs'
import type { Page } from '@playwright/test'
import { expect } from '@playwright/test'

/**
 * Page anatomy checks, shared by every Playwright suite that walks pages: the
 * tenant app's (specs/31-page-rhythm) and the platform console's
 * (console/specs). One probe and one set of rules, so the two apps cannot
 * drift: the page's blocks sit in a PageStack, block gaps follow the spacing
 * tokens read from the page (--sp-page, 24px; --sp-section, 16px from the
 * header to its tabs), one tab row, metric strips, chips, no sideways
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

const NAME_MIN_1440 = 160

/**
 * Rows with controls of different heights that are still open, per
 * "route@width" (probeRowMix). The list only shrinks: each entry names the
 * owner of the fix. A route that is not listed may have none.
 */
const ROW_MIX_DEBT: Record<string, number> = {
  // DataTable's Display menu trigger (h-9 in data-table.tsx, 36 beside 32) and the
  // chip-shaped Add filter (28) beside Query (32): the list family's table and
  // toolbar PRs.
  '/assets@1440': 2,
  '/assets/changes@1440': 1,
  '/assets/groups@1440': 1,
  '/attack-surface/certificates@1440': 1,
  '/attack-surface/exposures@1440': 1,
  '/attack-surface/external@1440': 1,
  '/attack-surface/technologies@1440': 1,
  '/attack-surface/web@1440': 1,
  '/business-services@1440': 1,
  '/business-units@1440': 1,
  '/credentials@1440': 1,
  '/crown-jewels@1440': 1,
  '/exceptions@1440': 1,
  '/exposures@1440': 1,
  '/findings@1440': 2,
  '/findings/approvals@1440': 1,
  '/my-work@1440': 1,
  '/priority-rules@1440': 1,
  '/scans@1440': 1,
  '/scans/workflows@1440': 1,
  '/scans/runs@1440': 1,
  '/scope@1440': 1,
  '/sensors@1440': 1,
  '/settings/audit-log@1440': 1,
  '/settings/content@1440': 1,
  '/settings/members@1440': 1,
  '/settings/pentest/templates@1440': 1,
  '/settings/roles@1440': 1,
  '/settings/scanning/capabilities@1440': 1,
  '/settings/scanning/profiles@1440': 1,
  '/settings/scanning/tools@1440': 1,
  '/threat-intel/iocs@1440': 1,
  '/vulnerabilities@1440': 1,
  '/scans/{id}@1440': 1,
  // The Assign tile (two-line action tile, 34) beside its person picker (32).
  '/findings/triage@1440': 1,
  // Phone scan cards: the latest-run status chip (24) beside the row menu (36), one per card.
  '/scans@390': 3,
}

type Probe = {
  /** The spacing tokens as the page resolves them (src/styles/theme.css). */
  pageGap: number
  tightGap: number
  /** Icon-only buttons (an icon, no visible text) that are not square. */
  oblongIconButtons: { name: string; width: number; height: number }[]
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
    const tokenPx = (name: string) => {
      const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
      const rem = parseFloat(getComputedStyle(document.documentElement).fontSize)
      if (v.endsWith('rem')) return parseFloat(v) * rem
      if (v.endsWith('px')) return parseFloat(v)
      return Number.NaN
    }
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
      oblongIconButtons: Array.from(
        document.querySelectorAll<HTMLElement>(
          'header button, main button, header a[data-slot=button], main a[data-slot=button]'
        )
      )
        .filter((b) => {
          const r = b.getBoundingClientRect()
          return (
            r.width > 0 &&
            r.height > 0 &&
            // a select trigger with no value yet is not an icon button
            b.getAttribute('role') !== 'combobox' &&
            b.querySelector('svg') &&
            !(b.innerText ?? '').trim()
          )
        })
        .map((b) => {
          const r = b.getBoundingClientRect()
          return {
            name: b.getAttribute('aria-label') ?? b.title ?? '',
            width: Math.round(r.width),
            height: Math.round(r.height),
          }
        })
        .filter((b) => Math.abs(b.width - b.height) > 1),
      pageGap: tokenPx('--sp-page'),
      tightGap: tokenPx('--sp-section'),
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

/** One control of a row: its accessible name (or tag) and its drawn box. */
export type RowControl = { name: string; height: number; centre: number }
/** A row whose controls differ in height or do not share one centre line. */
export type MixedRow = { row: string; controls: RowControl[] }

/**
 * Controls side by side in one row are drawn at one height on one centre
 * line ("Sizes" in docs/ui-style-contract.md: every control in a row the same
 * height). A row is the controls of one container (a list toolbar, a page or
 * card header, a form row, a bulk bar, the app header; otherwise the widest
 * ancestor that is still one line high) whose boxes overlap vertically.
 * Controls: buttons, button-like links, text fields, selects and comboboxes.
 * Not compared: checkboxes, radios and switches, text links, what sits inside
 * a chip (its remove button), a button placed over a field (a search field's
 * clear button), and controls of different table cells.
 */
export async function probeRowMix(page: Page): Promise<MixedRow[]> {
  return page.evaluate(() => {
    const TOL = 0.5
    const CONTAINERS = [
      '[data-slot=list-toolbar-region]',
      '[data-slot=list-toolbar]',
      '[data-slot=page-header]',
      '[data-slot=card-header]',
      '[data-slot=bulk-action-bar]',
      '[data-slot=settings-save-bar]',
      '[data-slot=dialog-footer]',
      '[role=toolbar]',
      'header',
    ].join(',')
    const STOP = 'td,th,[role=cell],[role=gridcell],[role=columnheader],[role=row],li,main,body'
    const overlay = (el: Element) =>
      !!el.closest('[role=dialog],[data-slot=sheet-content],[data-radix-popper-content-wrapper]')
    const shown = (el: Element) => {
      const r = el.getBoundingClientRect()
      const s = getComputedStyle(el)
      return (
        r.width > 1 &&
        r.height > 1 &&
        s.visibility !== 'hidden' &&
        s.display !== 'none' &&
        s.opacity !== '0' &&
        !el.closest('[aria-hidden=true],.sr-only')
      )
    }
    const rawControls = Array.from(
      document.querySelectorAll<HTMLElement>(
        [
          'button',
          '[role=button]',
          'a[data-slot=button]',
          '[role=combobox]',
          'select',
          'input:not([type=checkbox]):not([type=radio]):not([type=hidden]):not([type=range]):not([type=file])',
        ].join(',')
      )
    ).filter((el) => {
      if (!shown(el) || overlay(el)) return false
      if (el.matches('[role=checkbox],[role=radio],[role=switch],[role=tab],[role=menuitem]'))
        return false
      if (el.closest('[data-slot=checkbox],[data-slot=switch],[data-slot=radio-group-item]'))
        return false
      // A link-styled button is a text link.
      if (el.getAttribute('data-variant') === 'link') return false
      // Inside a chip (its remove button) or over a field (a clear button).
      if (
        el.closest(
          '[data-testid^=filter-chip],[data-slot=locked-chip],[data-slot=badge],[data-slot=signal-chip],[data-slot=status-lozenge]'
        )
      )
        return false
      if (getComputedStyle(el).position === 'absolute') return false
      // A control nested in another control counts once (the outer one).
      const outer = el.parentElement?.closest('button,[role=button],a[data-slot=button]')
      if (outer && outer !== el) return false
      return true
    })
    // A bordered group is one control (a filter select with its clear
    // button, a view switcher's segments): measured by its box.
    const GROUPS = '[data-slot=filter-select],[data-slot=view-switcher]'
    const seen = new Set<HTMLElement>()
    const controls = rawControls
      .map((el) => el.closest<HTMLElement>(GROUPS) ?? el)
      .filter((el) => (seen.has(el) ? false : (seen.add(el), true)))
    const label = (el: Element) => {
      const n =
        el.getAttribute('aria-label') ||
        (el as HTMLElement).innerText?.trim().split('\n')[0] ||
        el.getAttribute('placeholder') ||
        el.getAttribute('title') ||
        ''
      const tag = el.getAttribute('data-slot') || el.tagName.toLowerCase()
      return `${tag}${n ? ` "${n.slice(0, 40)}"` : ''}`
    }
    const containerOf = (el: Element): Element => {
      const named = el.parentElement?.closest(CONTAINERS)
      const stop = el.parentElement?.closest(STOP)
      // A table cell, a list item or a row ends the search before a far-away container.
      if (named && !(stop && named.contains(stop))) return named
      // Otherwise the widest ancestor that is still one line high.
      let c: Element = el.parentElement ?? document.body
      const h = el.getBoundingClientRect().height
      while (c.parentElement && !c.matches(STOP) && !c.parentElement.matches(STOP)) {
        const ph = c.parentElement.getBoundingClientRect().height
        if (ph > h * 1.5 + 8) break
        c = c.parentElement
      }
      return c
    }
    const byContainer = new Map<Element, HTMLElement[]>()
    for (const el of controls) {
      const c = containerOf(el)
      byContainer.set(c, [...(byContainer.get(c) ?? []), el])
    }
    const describe = (c: Element) => {
      const slot = c.getAttribute('data-slot')
      if (slot) return slot
      const id = c.id ? `#${c.id}` : ''
      const lab = c.getAttribute('aria-label')
      return `${c.tagName.toLowerCase()}${id}${lab ? ` "${lab}"` : ''}`
    }
    const out: { row: string; controls: { name: string; height: number; centre: number }[] }[] = []
    for (const [c, els] of byContainer) {
      if (els.length < 2) continue
      const boxes = els
        .map((el) => ({ el, r: el.getBoundingClientRect() }))
        .sort((a, b) => a.r.top - b.r.top)
      // Rows: controls whose boxes overlap vertically (transitively).
      const rows: (typeof boxes)[] = []
      for (const b of boxes) {
        const row = rows.find((rw) =>
          rw.some((o) => b.r.top < o.r.bottom - 1 && b.r.bottom > o.r.top + 1)
        )
        if (row) row.push(b)
        else rows.push([b])
      }
      for (const rw of rows) {
        if (rw.length < 2) continue
        const hs = rw.map((b) => b.r.height)
        const cs = rw.map((b) => b.r.top + b.r.height / 2)
        const spread = (xs: number[]) => Math.max(...xs) - Math.min(...xs)
        if (spread(hs) <= TOL && spread(cs) <= TOL) continue
        rw.sort((a, b) => a.r.left - b.r.left)
        out.push({
          row: `${describe(c)} at y=${Math.round(rw[0].r.top)}`,
          controls: rw.map((b) => ({
            name: label(b.el),
            height: Math.round(b.r.height * 10) / 10,
            centre: Math.round((b.r.top + b.r.height / 2) * 10) / 10,
          })),
        })
      }
    }
    return out
  })
}

/** `list-toolbar at y=488: dropdown-menu-trigger "Views" 32px @504, button "Refresh" 36px @504` */
export function formatMixedRow(m: MixedRow): string {
  const parts = m.controls.map((c) => `${c.name} ${c.height}px @${c.centre}`)
  return `${m.row}: ${parts.join(', ')}`
}

export async function checkAt(
  page: Page,
  route: string,
  width: number,
  ownLayoutRoutes: RegExp[] = [],
  opts: { rowMix?: boolean } = {}
) {
  await page.setViewportSize({ width, height: width < 600 ? 844 : 900 })
  // Let a resize settle (the tab strip re-measures what fits).
  await page.waitForTimeout(300)
  const r = await probe(page)
  const at = `${route} at ${width}px`

  const ownLayout = ownLayoutRoutes.some((re) => re.test(route.split('?')[0]))
  if (!ownLayout) expect(r.stack, `${at}: the page's blocks sit in a PageStack`).toBe(true)
  expect(r.pageGap, `${at}: --sp-page resolves to a length`).toBeGreaterThan(0)
  expect(r.tightGap, `${at}: --sp-section resolves to a length`).toBeGreaterThan(0)
  for (const p of ownLayout ? [] : r.pairs) {
    // Route tabs (page-tabs) and in-page tabs (tabs) both sit 16px under the header.
    const want =
      p.from === 'page-header' && (p.to === 'page-tabs' || p.to === 'tabs') ? r.tightGap : r.pageGap
    expect
      .soft(Math.abs(p.gap - want), `${at}: ${p.from} -> ${p.to} is ${p.gap}px, want ${want}px`)
      .toBeLessThanOrEqual(1)
  }
  expect.soft(r.oblongIconButtons, `${at}: icon-only buttons are squares`).toEqual([])
  if (opts.rowMix) {
    const mixed = await probeRowMix(page)
    if (process.env.ROWMIX_OUT) {
      fs.appendFileSync(process.env.ROWMIX_OUT, JSON.stringify({ route, width, mixed }) + '\n')
    }
    const key = `${route.split('?')[0].replace(/\/[0-9a-f-]{36}(?=\/|$)/g, '/{id}')}@${width}`
    expect
      .soft(
        mixed.length,
        `${at}: controls in one row share one height and centre (allowed ${ROW_MIX_DEBT[key] ?? 0}):\n` +
          mixed.map(formatMixedRow).join('\n')
      )
      .toBeLessThanOrEqual(ROW_MIX_DEBT[key] ?? 0)
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
