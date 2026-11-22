import type { Page } from '@playwright/test'

/**
 * MVP acceptance v2 (agent-ops/ui-v2/MVP-ACCEPTANCE.md): the viewport matrix
 * and the detectors that the first acceptance pass missed at 390, 1024 and
 * 1440 px only (owner reports 2026-11-22):
 *   - the finding rail's watchers control ran past its column near 2000 px;
 *   - /my-work spent whole rows on "Updated ..." and "Top N of M" at iPad width;
 *   - /remediation/campaigns cut its Due column ("..., overd") with no ellipsis
 *     at 1024 px with the left sidebar expanded.
 *
 * Kinds (each a list of plain lines, empty when the page passes):
 *   pastPanel        a control whose box runs past its column, rail or frame
 *   cutText          text cut at a frame or table scroller edge, no ellipsis
 *   wastedRow        a toolbar row above the first data row that holds only
 *                    meta text or one small control and is mostly empty
 *   duplicateAction  two primary buttons with one name or one target
 *   wideStretch      at 1900 px and up: a field or text line wider than 960 px,
 *                    or a side rail more than 400 px from its content
 *   joined           a field and a button side by side less than 8 px apart
 *                    (the kit gap), not one segmented group: /scope's Filters
 *                    button against its search box
 */

export type MatrixBreaks = {
  pastPanel: string[]
  cutText: string[]
  wastedRow: string[]
  duplicateAction: string[]
  wideStretch: string[]
  joined: string[]
}

export const MATRIX_KINDS: (keyof MatrixBreaks)[] = [
  'pastPanel',
  'cutText',
  'wastedRow',
  'duplicateAction',
  'wideStretch',
  'joined',
]

/** Widths of the v2 matrix with the height of their device class. */
export const MATRIX_V2: { width: number; height: number }[] = [
  { width: 360, height: 780 },
  { width: 390, height: 844 },
  { width: 430, height: 932 },
  { width: 768, height: 1180 },
  { width: 820, height: 1180 },
  { width: 1024, height: 820 },
  { width: 1180, height: 820 },
  { width: 1280, height: 900 },
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
  { width: 2560, height: 1440 },
]

/** The reduced set for CI shards (LAYOUT_MATRIX=ci). */
export const MATRIX_CI = [390, 1024, 1440, 1920]

/**
 * Widths where the stored sidebar preference (cookie `sidebar_state`) changes
 * the layout: from 1024 px the sidebar is expanded or collapsed by that
 * preference. Below 1024 px it is always the icon rail (hooks/use-mobile.ts),
 * so 768 and 820 px have one layout only and run once.
 */
export const SIDEBAR_WIDTHS = [1024, 1180, 1280]

/** Signed-out pages: run in a fresh context, without the signed-in session. */
export const AUTH_ROUTES = [
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/verify-email',
  '/oauth/device',
]

/** Widths that also get the empty and one-row data and the main overlays. */
export const OVERLAY_WIDTHS = [390, 1440]

export function matrixWidths(mode: string | undefined): { width: number; height: number }[] {
  if (mode === 'ci') return MATRIX_V2.filter((w) => MATRIX_CI.includes(w.width))
  const only = process.env.LAYOUT_WIDTHS?.split(',').map(Number).filter(Boolean)
  return only?.length ? MATRIX_V2.filter((w) => only.includes(w.width)) : MATRIX_V2
}

/** List endpoints that give the first id of a detail route (`/findings/[id]`). */
const DETAIL_LISTS: { prefix: string; list: string; key?: string }[] = [
  { prefix: '/assets/groups/', list: '/api/v1/asset-groups?per_page=1' },
  { prefix: '/assets/', list: '/api/v1/assets?per_page=1' },
  { prefix: '/findings/', list: '/api/v1/findings?per_page=1' },
  { prefix: '/scans/', list: '/api/v1/scans?per_page=1' },
  { prefix: '/remediation/campaigns/', list: '/api/v1/remediation/campaigns?per_page=1' },
  { prefix: '/remediation/tasks/', list: '/api/v1/remediation/tasks?per_page=1' },
  { prefix: '/pentest/campaigns/', list: '/api/v1/pentest/campaigns?per_page=1' },
  {
    prefix: '/vulnerabilities/',
    list: '/api/v1/vulnerability-exposures?per_page=1',
    key: 'cve_id',
  },
]

const PLACEHOLDER = /\[[a-z]+\]|\{[a-z]+\}/i

/** Replaces `[id]` (or `{id}`, `[cve]`) with the first row's id; null when there is none. */
export async function resolveRoute(page: Page, route: string): Promise<string | null> {
  if (!PLACEHOLDER.test(route)) return route
  const at = route.search(PLACEHOLDER)
  const head = route.slice(0, at)
  const src = DETAIL_LISTS.find((d) => head === d.prefix)
  if (!src) return null
  await page.goto('/', { timeout: 60_000 }).catch(() => {})
  const id = await page.evaluate(
    async ({ url, field }) => {
      const res = await fetch(url, { credentials: 'same-origin' })
      if (!res.ok) return null
      const body = await res.json()
      const rows = body.data ?? body.items ?? body
      return Array.isArray(rows) && rows[0]?.[field] ? String(rows[0][field]) : null
    },
    { url: src.list, field: src.key ?? 'id' }
  )
  return id ? route.replace(PLACEHOLDER, encodeURIComponent(id)) : null
}

/** Folder name for a route: `/findings/[id]` -> `findings-id`, `/` -> `home`. */
export const routeSlug = (route: string) =>
  route.replace(/\W+/g, '-').replace(/^-|-$/g, '') || 'home'

/** Runs the v2 detectors on the page (scope: `main` or an overlay selector). */
export async function findMatrixBreaks(
  page: Page,
  { scope = 'main' }: { scope?: string } = {}
): Promise<MatrixBreaks> {
  return page.evaluate((scope) => {
    const out = {
      pastPanel: [] as string[],
      cutText: [] as string[],
      wastedRow: [] as string[],
      duplicateAction: [] as string[],
      wideStretch: [] as string[],
      joined: [] as string[],
    }
    const roots = Array.from(document.querySelectorAll(scope))
    if (!roots.length) return out
    const vw = document.documentElement.clientWidth
    const short = (s: string | null | undefined, n = 40) =>
      (s ?? '').replace(/\s+/g, ' ').trim().slice(0, n)
    const hidden = (el: Element): boolean => {
      for (let a: Element | null = el; a; a = a.parentElement) {
        const cs = getComputedStyle(a)
        if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return true
        if (a.getAttribute('aria-hidden') === 'true') return true
        const r = a.getBoundingClientRect()
        // Visually hidden (sr-only): a 1 px box that clips its content.
        if ((r.width <= 1 || r.height <= 1) && /hidden|clip/.test(cs.overflowX + cs.overflowY))
          return true
        if (cs.clip !== 'auto' && cs.clip !== '') return true
      }
      return false
    }
    const shown = (el: Element) => {
      const r = el.getBoundingClientRect()
      return r.width >= 1 && r.height >= 1 && !hidden(el)
    }
    const nameOf = (el: Element) =>
      short(
        el.getAttribute('aria-label') ||
          el.textContent ||
          el.getAttribute('title') ||
          el.getAttribute('placeholder'),
        30
      )
    const CONTROL =
      'button,a[href],[role=button],[role=tab],[role=combobox],[role=link],[role=switch],[role=checkbox],input:not([type=hidden]),select,textarea'
    const tracks = (el: Element) => {
      const cs = getComputedStyle(el)
      if (!/grid/.test(cs.display)) return 0
      return cs.gridTemplateColumns.split(' ').filter((t) => /px$/.test(t)).length
    }
    const isScroller = (el: Element) =>
      /auto|scroll|hidden|clip/.test(getComputedStyle(el).overflowX)
    const isRail = (el: Element) =>
      el.tagName === 'ASIDE' || /rail|sidebar/.test(el.getAttribute('data-slot') ?? '')

    // ---- pastPanel: a control past the column, rail or frame that holds it.
    // The container is the nearest grid column (a child of a grid with two
    // tracks or more), aside/rail, or overflow frame. A negative start margin
    // (a ghost button aligned to its text) may sit up to 12 px past the start.
    for (const root of roots) {
      for (const c of Array.from(root.querySelectorAll(CONTROL))) {
        const outer = c.parentElement?.closest(CONTROL)
        if (outer && root.contains(outer)) continue
        if (!shown(c)) continue
        const r = c.getBoundingClientRect()
        let box: Element | null = null
        let what = ''
        for (let a = c.parentElement; a && a !== document.body; a = a.parentElement) {
          // A display:contents box has no box of its own (0 x 0): not a frame.
          if (getComputedStyle(a).display === 'contents') continue
          if (isScroller(a)) {
            box = a
            what = 'frame'
            break
          }
          if (isRail(a)) {
            box = a
            what = 'rail'
            break
          }
          if (a.parentElement && tracks(a.parentElement) >= 2) {
            box = a
            what = 'column'
            break
          }
        }
        if (!box) continue
        const b = box.getBoundingClientRect()
        // A control wholly past a scroller's edge (a table column out of view)
        // is reachable by scrolling; a cut one is the clipped check's (and
        // cutText's) business. Here: a control drawn past its box.
        if (what === 'frame' && /auto|scroll/.test(getComputedStyle(box).overflowX)) continue
        const end = Math.round(r.right - b.right)
        const start = Math.round(b.left - r.left)
        if (end > 2 || start > 12) {
          out.pastPanel.push(
            `control past its ${what} by ${Math.max(end, start)}px: "${nameOf(c)}" (${Math.round(r.width)}px in ${Math.round(b.width)}px)`
          )
        }
      }
    }

    // ---- cutText: a text cut by the frame around it (overflow clip, hidden,
    // or a table scroller) as the page opens, with no ellipsis to say so:
    // "Apr 29, 2026, overd" at the edge of a table at 1024 px.
    const ellipsisOn = (from: Element, to: Element) => {
      for (let a: Element | null = from; a; a = a.parentElement) {
        const cs = getComputedStyle(a)
        if (
          (cs.textOverflow === 'ellipsis' && !/flex|grid/.test(cs.display)) ||
          (/\d/.test(cs.webkitLineClamp) && /-webkit-(inline-)?box/.test(cs.display))
        )
          return true
        if (a === to) break
      }
      return false
    }
    const frameOf = (el: Element) => {
      for (let a = el.parentElement; a && a !== document.documentElement; a = a.parentElement) {
        if (isScroller(a) && a.getBoundingClientRect().width > 0) return a
      }
      return null
    }
    const seenText = new Set<string>()
    for (const root of roots) {
      const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
      for (let n = w.nextNode(); n; n = w.nextNode()) {
        const host = n.parentElement
        if (!host || !(n.textContent ?? '').trim() || hidden(host)) continue
        const frame = host === root ? null : isScroller(host) ? host : frameOf(host)
        if (!frame) continue
        const f = frame.getBoundingClientRect()
        const rg = document.createRange()
        rg.selectNodeContents(n)
        const cut = Array.from(rg.getClientRects()).some(
          (b) =>
            b.width > 1 &&
            ((b.right > f.right + 1 && b.left < f.right - 1) ||
              (b.left < f.left - 1 && b.right > f.left + 1))
        )
        if (!cut || ellipsisOn(host, frame)) continue
        // The shared page tab strip may scroll: its edge fade says there is more.
        const strip = frame.closest<HTMLElement>('[data-tab-strip]')
        if (strip && (strip.dataset.fadeEnd === 'true' || strip.dataset.fadeStart === 'true'))
          continue
        const line = `text cut at a frame edge, no ellipsis: "${short(n.textContent)}"`
        if (!seenText.has(line)) out.cutText.push(line)
        seenText.add(line)
      }
    }

    // ---- wastedRow: rows between the page's tabs (or header) and the first
    // data row (or, with no rows, the first content block: the empty state).
    // With more than one such row, a row is wasted when it holds no field and
    // at most one small control beside its text: "Updated ...", "Top 5 of 40",
    // a caption with a lone Refresh button.
    for (const root of roots) {
      const rr = root.getBoundingClientRect()
      const anchorsAll = Array.from(
        // An overlay's title block (title and its one-line description) is
        // its header, not a wasted row.
        root.querySelectorAll(
          '[role=tablist], [data-slot="page-header"], h1, [data-slot="dialog-header"], [data-slot="sheet-header"], [data-slot="drawer-header"]'
        )
      ).filter(shown)
      let first: Element | undefined = Array.from(
        root.querySelectorAll(
          'tbody tr, [data-phone-card], [role=row]:not(:has([role=columnheader]))'
        )
      ).find(shown)
      let list: Element | null = first
        ? (first.closest('table, [role=table], [role=grid], ul, ol') ?? first.parentElement)
        : null
      // An overlay without a list is a form: its labels and notes are not
      // rows of a list's toolbar.
      if (
        !first &&
        root.closest(
          '[role=dialog], [data-slot="sheet-content"], [data-slot="drawer-content"]'
        )
      )
        continue
      if (!first) {
        const below = anchorsAll.length
          ? Math.max(...anchorsAll.map((a) => a.getBoundingClientRect().bottom))
          : rr.top
        first = Array.from(root.querySelectorAll('*'))
          .filter((el) => {
            if (!shown(el)) return false
            const r = el.getBoundingClientRect()
            return r.top > below + 4 && r.height >= 120 && r.width >= rr.width * 0.6
          })
          .sort((x, y) => x.getBoundingClientRect().top - y.getBoundingClientRect().top)[0]
        list = first ?? null
      }
      if (!first || !list) continue
      const fr = first.getBoundingClientRect()
      const lr = list.getBoundingClientRect()
      const anchors = anchorsAll.filter((a) => a.getBoundingClientRect().bottom <= fr.top)
      const top = anchors.length
        ? Math.max(...anchors.map((a) => a.getBoundingClientRect().bottom))
        : rr.top
      type Item = { r: DOMRect; control: boolean; field: boolean; heading: boolean; text: string }
      const items: Item[] = []
      for (const el of Array.from(root.querySelectorAll('*'))) {
        if (
          list.contains(el) ||
          el.closest(
            '[role=tablist], [data-slot="page-header"], [data-slot="dialog-header"], [data-slot="sheet-header"], [data-slot="drawer-header"]'
          )
        )
          continue
        const control = el.matches(CONTROL)
        const ownText = Array.from(el.childNodes).some(
          (k) => k.nodeType === 3 && (k.textContent ?? '').trim()
        )
        if (!control && !ownText) continue
        if (el.parentElement?.closest(CONTROL)) continue
        if (!shown(el)) continue
        // A text's own extent, not its block box: a paragraph is as wide as
        // its column, its words are not.
        let r = el.getBoundingClientRect()
        if (!control) {
          const rg = document.createRange()
          rg.selectNodeContents(el)
          r = rg.getBoundingClientRect()
        }
        if (r.top < top - 1 || r.bottom > fr.top + 1) continue
        if (r.right < lr.left || r.left > lr.right) continue
        items.push({
          r,
          control,
          field: el.matches('input, textarea, select, [role=combobox]'),
          heading: !!el.closest('h1, h2, h3, h4, h5, h6, [role=heading]'),
          text: short(el.getAttribute('aria-label') || el.textContent, 60),
        })
      }
      items.sort((a, b) => a.r.top - b.r.top)
      const rows: Item[][] = []
      for (const it of items) {
        const mid = (it.r.top + it.r.bottom) / 2
        const row = rows.find((g) => g.some((o) => mid > o.r.top && mid < o.r.bottom))
        if (row) row.push(it)
        else rows.push([it])
      }
      if (rows.length < 2) continue
      for (const row of rows) {
        // A field, a heading or a paragraph (more than two lines) is content.
        if (row.some((o) => o.field || o.heading || (!o.control && o.r.height > 44))) continue
        const controls = row.filter((o) => o.control)
        if (controls.length > 1) continue
        if (controls.length === 1 && controls[0].r.width >= lr.width * 0.4) continue
        out.wastedRow.push(
          `row of its own above the first ${list === first ? 'content' : 'data row'}: "${short(
            [...row]
              .sort((x, y) => x.r.left - y.r.left)
              .map((o) => o.text)
              .join(' | '),
            70
          )}"`
        )
      }
    }

    // ---- duplicateAction: primary buttons (kit default variant) with the
    // same name or the same link target.
    for (const root of roots) {
      const prim = Array.from(
        root.querySelectorAll('[data-slot="button"][data-variant="default"]')
      ).filter(shown)
      const byName = new Map<string, number>()
      const byHref = new Map<string, string[]>()
      for (const p of prim) {
        const n = nameOf(p).toLowerCase()
        if (n) byName.set(n, (byName.get(n) ?? 0) + 1)
        const h = p.getAttribute('href') ?? p.closest('a[href]')?.getAttribute('href')
        if (h && h !== '#') byHref.set(h, [...(byHref.get(h) ?? []), nameOf(p)])
      }
      for (const [n, k] of byName)
        if (k > 1) out.duplicateAction.push(`${k} primary buttons "${n}"`)
      for (const [h, names] of byHref) {
        if (names.length > 1 && new Set(names.map((x) => x.toLowerCase())).size > 1)
          out.duplicateAction.push(
            `${names.length} primary buttons to ${h}: "${names.join('", "')}"`
          )
      }
    }

    // ---- wideStretch: wide screens only.
    if (vw >= 1900) {
      for (const root of roots) {
        const fields = root.querySelectorAll(
          'input:not([type=checkbox]):not([type=radio]):not([type=hidden]):not([type=range]), textarea, select, [role=combobox]'
        )
        for (const f of Array.from(fields)) {
          if (!shown(f)) continue
          const w = f.getBoundingClientRect().width
          if (w > 960) out.wideStretch.push(`field ${Math.round(w)}px wide: "${nameOf(f)}"`)
        }
        const seen = new Set<Element>()
        const tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
        for (let n = tw.nextNode(); n; n = tw.nextNode()) {
          const host = n.parentElement
          if (!host || seen.has(host) || (n.textContent ?? '').trim().length < 40 || hidden(host))
            continue
          if (host.closest('table, pre, code, [role=grid]')) continue
          const rg = document.createRange()
          rg.selectNodeContents(n)
          const widest = Math.max(0, ...Array.from(rg.getClientRects()).map((b) => b.width))
          if (widest > 960) {
            seen.add(host)
            out.wideStretch.push(
              `text line ${Math.round(widest)}px wide: "${short(n.textContent)}"`
            )
          }
        }
        // A rail (narrow grid column, aside) far from the content beside it.
        const contentEdge = (col: Element, side: 'right' | 'left') => {
          let edge = side === 'right' ? -Infinity : Infinity
          const w = document.createTreeWalker(col, NodeFilter.SHOW_TEXT)
          for (let n = w.nextNode(); n; n = w.nextNode()) {
            if (!(n.textContent ?? '').trim() || !n.parentElement || hidden(n.parentElement))
              continue
            const rg = document.createRange()
            rg.selectNodeContents(n)
            for (const b of Array.from(rg.getClientRects())) {
              if (b.width < 1) continue
              edge = side === 'right' ? Math.max(edge, b.right) : Math.min(edge, b.left)
            }
          }
          for (const c of Array.from(col.querySelectorAll(CONTROL))) {
            if (!shown(c)) continue
            const b = c.getBoundingClientRect()
            edge = side === 'right' ? Math.max(edge, b.right) : Math.min(edge, b.left)
          }
          // Drawn content counts too: a chart, an image or a filled bar (the
          // dashboard's category bars run from the label to the value).
          for (const c of [col, ...Array.from(col.querySelectorAll('*'))]) {
            if (!shown(c)) continue
            const painted =
              c.matches('svg, img, canvas, [role=img], [role=progressbar], [role=meter]') ||
              // a filled leaf or a bar track (24 px high at most), not a card
              // or panel around other content
              ((c.children.length === 0 || c.getBoundingClientRect().height <= 24) &&
                !/^(transparent|rgba\(0, 0, 0, 0\))$/.test(getComputedStyle(c).backgroundColor))
            if (!painted) continue
            const b = c.getBoundingClientRect()
            if (b.width < 8 || b.height < 2) continue
            edge = side === 'right' ? Math.max(edge, b.right) : Math.min(edge, b.left)
          }
          return edge
        }
        for (const grid of Array.from(root.querySelectorAll('*'))) {
          if (tracks(grid) < 2 || !shown(grid)) continue
          const kids = Array.from(grid.children).filter(shown)
          for (const rail of kids) {
            const rr = rail.getBoundingClientRect()
            if (rr.width > 480) continue
            // The nearest content on either side, from every column beside
            // the rail (a bar between a label and its value is content), and
            // only when one of them is the wide content column.
            let wide = false
            let left = -Infinity
            let right = Infinity
            for (const other of kids) {
              if (other === rail) continue
              const or = other.getBoundingClientRect()
              if (or.bottom <= rr.top || or.top >= rr.bottom) continue
              if (or.width >= rr.width * 1.5) wide = true
              if (or.right <= rr.left) left = Math.max(left, contentEdge(other, 'right'))
              else if (or.left >= rr.right) right = Math.min(right, contentEdge(other, 'left'))
            }
            if (!wide) continue
            const gap = Math.min(
              Number.isFinite(left) ? rr.left - left : Infinity,
              Number.isFinite(right) ? right - rr.right : Infinity
            )
            if (Number.isFinite(gap) && gap > 400)
              out.wideStretch.push(
                `rail ${Math.round(gap)}px from its content: "${short(rail.textContent, 30)}"`
              )
          }
        }
      }
    }
    // ---- joined: a field with a button beside it closer than the kit gap.
    for (const root of roots) {
      const fields = Array.from(
        root.querySelectorAll(
          'input:not([type=checkbox]):not([type=radio]):not([type=hidden]), [role=combobox], select, textarea'
        )
      ).filter(shown)
      const buttons = Array.from(root.querySelectorAll('button, a[href], [role=button]')).filter(
        (b) => shown(b) && !b.closest('[role=combobox]')
      )
      for (const f of fields) {
        // The field's frame: the bordered wrapper around an input with an icon.
        let frame: Element = f
        for (let a = f.parentElement; a && a !== root; a = a.parentElement) {
          if (a.querySelector('button, a[href]') && a.contains(f)) break
          if (parseFloat(getComputedStyle(a).borderLeftWidth) > 0) frame = a
          if (a.getBoundingClientRect().width > f.getBoundingClientRect().width + 80) break
        }
        const fr = frame.getBoundingClientRect()
        for (const b of buttons) {
          if (frame.contains(b)) continue
          const br = b.getBoundingClientRect()
          if (br.bottom <= fr.top + 2 || br.top >= fr.bottom - 2) continue
          const gap =
            br.left >= fr.right - 1
              ? br.left - fr.right
              : fr.left >= br.right - 1
                ? fr.left - br.right
                : -1
          if (gap < 0 || gap >= 7.5) continue
          // One segmented control drawn in one shared frame is meant to touch;
          // two framed controls pressed together are not (/scope: the filter
          // button's border against the search box's).
          const group = b.closest('[role=group], [data-slot*="group"]')
          if (group && group.contains(f) && parseFloat(getComputedStyle(group).borderLeftWidth) > 0)
            continue
          out.joined.push(
            `button ${Math.round(gap)}px from a field: "${nameOf(b)}" | "${nameOf(f)}"`
          )
        }
      }
    }
    for (const k of Object.keys(out) as (keyof typeof out)[]) out[k] = [...new Set(out[k])]
    return out
  }, scope)
}
