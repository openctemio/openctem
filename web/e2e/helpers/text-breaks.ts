import fs from 'fs'
import path from 'path'
import type { Page, Route } from '@playwright/test'

/**
 * Detectors for the layout breaks that hide in real data (owner report
 * 2026-11-19, /assets at 390 px: a description in the card's type line
 * squeezed "IP Address" to "IP Addres / s" and ran under the Risk score).
 * Each detector returns short, readable findings; an empty list is a pass.
 *
 *   overlaps    a text box drawn over another text box or a control
 *   brokenWords a word of letters split over two lines (only tokens such as
 *               hashes, URLs and keys may break anywhere)
 *   clipped     text cut by an overflow clip with no ellipsis or line clamp,
 *               a button or link whose label a frame cuts ("Manage" shown as
 *               "Mana"), text past either edge of the screen, sideways page scroll,
 *               a control a sideways scroller cuts at its edge on load, and a
 *               one-line strip (a toolbar's tokens, chips) that scrolls
 *               sideways with controls out of view (owner report 2026-11-20:
 *               "Last 7 d..." faded at the edge read as hidden buttons)
 *   mixedRows   controls of different heights side by side in one row
 *   untranslated English catalog strings left on a Vietnamese page
 *   emptyLabels a label shown with no value beside it
 *   lopsided    a row bunched at one side: a phone card whose content all
 *               stops short of its end (nothing on the right: no state, no
 *               chevron, no action), or a list title row line that holds
 *               only end controls with nothing at its start, or (phone) a title
 *               row whose one control is an icon alone at its end
 *
 * `richData` makes the API answers of a page hard on the layout: long English
 * and Vietnamese names, 80+ characters without a break opportunity in the
 * middle, optional fields present on some rows and absent on others, and
 * 0, 1 or 200 rows.
 */

export type Breaks = {
  overlaps: string[]
  brokenWords: string[]
  clipped: string[]
  mixedRows: string[]
  untranslated: string[]
  emptyLabels: string[]
  lopsided: string[]
}

export const BREAK_KINDS: (keyof Breaks)[] = [
  'overlaps',
  'brokenWords',
  'clipped',
  'mixedRows',
  'untranslated',
  'emptyLabels',
  'lopsided',
]

// ---------- English strings that must not appear on a Vietnamese page ----------

let enOnly: string[] | null = null

/** en catalog values of two words or more that have no identical vi value. */
export function englishOnlyStrings(): string[] {
  if (enOnly) return enOnly
  const dir = path.resolve(__dirname, '../../src/lib/i18n/dictionaries')
  const flat = (o: unknown, acc: string[]) => {
    if (typeof o === 'string') acc.push(o)
    else if (o && typeof o === 'object') for (const v of Object.values(o)) flat(v, acc)
    return acc
  }
  const en = new Set<string>()
  const vi = new Set<string>()
  for (const f of fs.readdirSync(path.join(dir, 'en'))) {
    if (!f.endsWith('.json')) continue
    flat(JSON.parse(fs.readFileSync(path.join(dir, 'en', f), 'utf8')), []).forEach((s) => en.add(s))
    const viFile = path.join(dir, 'vi', f)
    if (fs.existsSync(viFile)) {
      flat(JSON.parse(fs.readFileSync(viFile, 'utf8')), []).forEach((s) => vi.add(s))
    }
  }
  enOnly = [...en].filter(
    (s) =>
      !vi.has(s) &&
      /^[A-Za-z][A-Za-z ,.'-]+$/.test(s) &&
      s.trim().split(/\s+/).length >= 2 &&
      !s.includes('{')
  )
  return enOnly
}

// ---------- detectors (run in the page) ----------

/**
 * Runs every detector on the elements matched by `scope` (default: the page's
 * main content). `vi` adds the untranslated-text check.
 */
export async function findBreaks(
  page: Page,
  { scope = 'main', vi = false }: { scope?: string; vi?: boolean } = {}
): Promise<Breaks> {
  return page.evaluate(
    ({ scope, enOnly }) => {
      const out = {
        overlaps: [] as string[],
        brokenWords: [] as string[],
        clipped: [] as string[],
        mixedRows: [] as string[],
        untranslated: [] as string[],
        emptyLabels: [] as string[],
        lopsided: [] as string[],
      }
      const roots = Array.from(document.querySelectorAll(scope))
      if (!roots.length) return out
      const short = (s: string | null | undefined, n = 40) =>
        (s ?? '').replace(/\s+/g, ' ').trim().slice(0, n)
      const shown = (el: Element) => {
        const r = el.getBoundingClientRect()
        if (r.width < 1 || r.height < 1) return false
        const cs = getComputedStyle(el)
        return cs.visibility !== 'hidden' && cs.opacity !== '0'
      }
      // Visually hidden text (a 1 px box that clips its content, or a clip
      // rect): read by a screen reader, never drawn.
      const vhCache = new Map<Element, boolean>()
      const visuallyHidden = (el: Element): boolean => {
        if (vhCache.has(el)) return vhCache.get(el)!
        const cs = getComputedStyle(el)
        const r = el.getBoundingClientRect()
        const own =
          (cs.clip !== 'auto' && cs.clip !== '') ||
          /inset\(50%\)/.test(cs.clipPath) ||
          ((r.width <= 1 || r.height <= 1) && /hidden|clip/.test(cs.overflowX + cs.overflowY))
        const v = own || (!!el.parentElement && visuallyHidden(el.parentElement))
        vhCache.set(el, v)
        return v
      }
      const hiddenByAncestor = (el: Element) =>
        !!el.closest(
          '.sr-only,[aria-hidden="true"],script,style,svg,[data-slot*=skeleton],[class*=animate-pulse],details:not([open]) > :not(summary)'
        ) || visuallyHidden(el)
      const isToken = (el: Element) =>
        !!el.closest('code,pre,kbd,.font-mono,[class*="font-mono"],input,textarea,[data-token]')

      // What the clipping ancestors of a node leave visible, up to its first
      // scrolling ancestor (what a scroller hides is still reachable).
      const clipCache = new Map<Element, DOMRect | null>()
      const clipOf = (node: Element): DOMRect | null => {
        if (clipCache.has(node)) return clipCache.get(node)!
        let box: DOMRect | null = null
        for (let a: Element | null = node; a && a !== document.body; a = a.parentElement) {
          const cs = getComputedStyle(a)
          if (/auto|scroll/.test(cs.overflowX + cs.overflowY)) break
          if (/hidden|clip/.test(cs.overflowX + cs.overflowY)) {
            const r = a.getBoundingClientRect()
            box = box
              ? new DOMRect(
                  Math.max(box.left, r.left),
                  Math.max(box.top, r.top),
                  Math.max(0, Math.min(box.right, r.right) - Math.max(box.left, r.left)),
                  Math.max(0, Math.min(box.bottom, r.bottom) - Math.max(box.top, r.top))
                )
              : r
          }
        }
        clipCache.set(node, box)
        return box
      }
      // The layer a node moves with: sticky/fixed boxes and scrollers. Text in
      // a scroller passes under a pinned header by design.
      const layerOf = (node: Element): Element => {
        for (let a: Element | null = node; a; a = a.parentElement) {
          const cs = getComputedStyle(a)
          if (cs.position === 'sticky' || cs.position === 'fixed') return a
          if (/auto|scroll/.test(cs.overflowX + cs.overflowY) && a !== document.documentElement)
            return a
        }
        return document.documentElement
      }
      const intersect = (r: DOMRect, c: DOMRect | null) => {
        if (!c) return r
        const left = Math.max(r.left, c.left)
        const right = Math.min(r.right, c.right)
        const top = Math.max(r.top, c.top)
        const bottom = Math.min(r.bottom, c.bottom)
        return right - left > 1 && bottom - top > 1
          ? new DOMRect(left, top, right - left, bottom - top)
          : null
      }

      type Box = { text: string; owner: Element; layer: Element; r: DOMRect }
      const texts: Box[] = []
      const enSet = new Set(enOnly)
      const untranslated = new Set<string>()
      const offStart = new Set<string>()
      const wordRe = /[\p{L}\p{N}]['’\p{L}\p{N}]*/gu

      for (const root of roots) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
          const text = n.textContent ?? ''
          const parent = n.parentElement
          if (!parent || !text.trim() || hiddenByAncestor(parent) || !shown(parent)) continue
          // translate="no" marks stored text (a dashboard's description): data, not catalog copy.
          if (enSet.size && enSet.has(text.trim()) && !parent.closest('[translate="no"]'))
            untranslated.add(text.trim())
          const clip = clipOf(parent)
          const range = document.createRange()
          range.selectNodeContents(n)
          // A large figure's em box reaches well above its digits: compare
          // from the cap height down.
          const fs = parseFloat(getComputedStyle(parent).fontSize) || 0
          const inset = fs >= 24 ? fs * 0.22 : 0
          for (const raw of Array.from(range.getClientRects())) {
            const r = intersect(
              inset ? new DOMRect(raw.left, raw.top + inset, raw.width, raw.height - inset) : raw,
              clip
            )
            if (r) texts.push({ text: short(text), owner: parent, layer: layerOf(parent), r })
            // Text that starts left of the screen: a right-aligned row wider
            // than the screen runs off the start edge, where nothing scrolls.
            if (raw.left < -1 && raw.width > 1 && layerOf(parent) === document.documentElement)
              offStart.add(short(text))
          }
          // (b) a word of letters split over two lines.
          if (!isToken(parent)) {
            for (const m of text.matchAll(wordRe)) {
              const w = m[0]
              if (w.length < 2 || w.length > 30 || !/\p{L}{2}/u.test(w)) continue
              const wr = document.createRange()
              wr.setStart(n, m.index!)
              wr.setEnd(n, m.index! + w.length)
              // Lines a clamp or a clipping frame hides do not count.
              const tops = new Set(
                Array.from(wr.getClientRects())
                  .filter((b) => b.width > 0.5 && intersect(b, clip))
                  .map((b) => Math.round(b.top))
              )
              if (tops.size > 1) out.brokenWords.push(`"${w}" in "${short(text, 50)}"`)
            }
          }
        }
        // Attributes a person reads too (vi only: enSet is empty otherwise).
        if (enSet.size) {
          for (const e of Array.from(root.querySelectorAll('[aria-label],[placeholder],[title]'))) {
            for (const a of ['aria-label', 'placeholder', 'title']) {
              const s = e.getAttribute(a)?.trim()
              if (s && enSet.has(s)) untranslated.add(`@${a}: ${s}`)
            }
          }
        }
      }
      out.untranslated = [...untranslated]

      // (a) overlaps: text over text, and text over a control it is not part of.
      const controls = roots
        .flatMap((root) =>
          Array.from(
            root.querySelectorAll(
              'button,input:not([type=hidden]),select,textarea,[role=combobox],[role=switch],[role=checkbox]'
            )
          )
        )
        .filter((c) => shown(c) && !hiddenByAncestor(c))
        .map((c) => {
          const r = intersect(c.getBoundingClientRect(), clipOf(c))
          return r && { el: c, layer: layerOf(c), r }
        })
        .filter((c): c is { el: Element; layer: Element; r: DOMRect } => !!c)
      // A text box is the font's whole em box, taller than its glyphs (a large
      // figure's box reaches into the caption above it): boxes overlap only
      // when they share a third of the smaller one's height.
      const area = (a: DOMRect, b: DOMRect) => {
        const x = Math.min(a.right, b.right) - Math.max(a.left, b.left)
        const y = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top)
        return x > 2 && y > Math.max(2, Math.min(a.height, b.height) / 3)
      }
      const seen = new Set<string>()
      const push = (msg: string) => {
        if (!seen.has(msg)) {
          seen.add(msg)
          out.overlaps.push(msg)
        }
      }
      for (let i = 0; i < texts.length; i++) {
        const a = texts[i]
        for (let j = i + 1; j < texts.length; j++) {
          const b = texts[j]
          if (a.owner === b.owner || a.layer !== b.layer) continue
          if (area(a.r, b.r)) push(`"${a.text}" over "${b.text}"`)
        }
        for (const c of controls) {
          if (c.layer !== a.layer || c.el.contains(a.owner) || a.owner.contains(c.el)) continue
          // A stretched card button (`after:inset-0`) is not a drawn control.
          if (c.el.matches('[class*="after:absolute"]')) continue
          if (area(a.r, c.r)) {
            push(
              `"${a.text}" over control "${short(c.el.getAttribute('aria-label') || c.el.textContent, 30)}"`
            )
          }
        }
      }

      // (c) clipped without an ellipsis, text past the screen, sideways scroll.
      for (const root of roots) {
        for (const e of Array.from(root.querySelectorAll('*'))) {
          if (!shown(e) || hiddenByAncestor(e) || !short(e.textContent)) continue
          const cs = getComputedStyle(e)
          if (!/hidden|clip/.test(cs.overflowX)) continue
          if (/auto|scroll/.test(cs.overflowX)) continue
          if (e.scrollWidth <= e.clientWidth + 2 || e.clientWidth === 0) continue
          // An ellipsis is drawn only by a block box (text sitting directly in a
          // flex or grid box is cut with no mark), and a line clamp only on a
          // -webkit-box: a select value with `line-clamp-1` and `flex` showed
          // "Các mục một lần đư" with nothing to say it was cut.
          const flexOrGrid = /flex|grid/.test(cs.display)
          if (cs.textOverflow === 'ellipsis' && !flexOrGrid) continue
          if (/\d/.test(cs.webkitLineClamp) && /-webkit-(inline-)?box/.test(cs.display)) continue
          // Only text cut: a child box (an icon, a chip row) wider than its frame
          // whose text still fits is the frame's own decision.
          const r = e.getBoundingClientRect()
          const w = document.createTreeWalker(e, NodeFilter.SHOW_TEXT)
          let cut = false
          for (let n = w.nextNode(); n && !cut; n = w.nextNode()) {
            if (
              !(n.textContent ?? '').trim() ||
              !n.parentElement ||
              hiddenByAncestor(n.parentElement)
            )
              continue
            const rg = document.createRange()
            rg.selectNodeContents(n)
            cut = Array.from(rg.getClientRects()).some(
              (b) => b.width > 1 && (b.right > r.right + 1 || b.left < r.left - 1)
            )
          }
          if (cut)
            out.clipped.push(
              `cut, no ellipsis: "${short(e.textContent)}" ${e.clientWidth}/${e.scrollWidth}`
            )
        }
      }
      // (c2) a button or link whose label is cut by the frame around it (a
      // table frame, a cell, a card) at its start or end edge: "Manage" shown
      // as "Mana" at the table's right edge. A label that ends in an ellipsis
      // by design (truncate) is not cut; a scroller's content is reachable.
      for (const root of roots) {
        const controls = root.querySelectorAll(
          'button, a[href], [role="button"], [role="link"], [role="menuitem"]'
        )
        for (const el of Array.from(controls)) {
          if (!shown(el) || hiddenByAncestor(el) || !short(el.textContent)) continue
          const clip = clipOf(el)
          if (!clip) continue
          const w = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
          let cutBy = 0
          for (let n = w.nextNode(); n && !cutBy; n = w.nextNode()) {
            const host = n.parentElement
            if (!(n.textContent ?? '').trim() || !host || hiddenByAncestor(host)) continue
            let ellipsis = false
            for (let a: Element | null = host; a; a = a.parentElement) {
              const cs = getComputedStyle(a)
              if (cs.textOverflow === 'ellipsis' || /\d/.test(cs.webkitLineClamp)) ellipsis = true
              if (a === el) break
            }
            if (ellipsis) continue
            const rg = document.createRange()
            rg.selectNodeContents(n)
            for (const b of Array.from(rg.getClientRects())) {
              if (b.width <= 1) continue
              if (b.right > clip.right + 1) cutBy = Math.round(b.right - clip.right)
              else if (b.left < clip.left - 1) cutBy = Math.round(clip.left - b.left)
              if (cutBy) break
            }
          }
          if (cutBy)
            out.clipped.push(`control cut by its frame by ${cutBy}px: "${short(el.textContent)}"`)
        }
      }
      // (c3) sideways scrollers, as the page opens. Reachable by a swipe is not
      // seen: nothing tells a person a strip scrolls. A one-line strip (56 px
      // high at most, no table) may hide no control at all; a taller scroller
      // (a wide table) may hold columns past its edge, but never cuts one.
      const CONTROL =
        'button,a[href],[role=button],[role=tab],[role=combobox],[role=link],input:not([type=hidden]),select'
      for (const root of roots) {
        for (const sc of Array.from(root.querySelectorAll('*'))) {
          const cs = getComputedStyle(sc)
          if (!/auto|scroll/.test(cs.overflowX)) continue
          if (sc.scrollWidth <= sc.clientWidth + 2 || sc.clientWidth === 0) continue
          if (!shown(sc) || hiddenByAncestor(sc)) continue
          // A page tab strip (marked by the shared component) that shows its edge
          // fade tells a person there are more tabs: it may scroll. Toolbars,
          // filters and action rows have no such cue and may not.
          const ds = (sc as HTMLElement).dataset
          if (ds.tabStrip !== undefined && (ds.fadeEnd === 'true' || ds.fadeStart === 'true'))
            continue
          const sr = sc.getBoundingClientRect()
          const strip = sr.height <= 56 && !sc.querySelector('table')
          for (const c of Array.from(sc.querySelectorAll(CONTROL))) {
            // The outermost control only (a clear button inside a token).
            const outer = c.parentElement?.closest(CONTROL)
            if (outer && sc.contains(outer)) continue
            if (hiddenByAncestor(c)) continue
            const r = c.getBoundingClientRect()
            if (r.width < 1 || r.height < 1) continue
            const pastEnd = r.right > sr.right + 1
            const pastStart = r.left < sr.left - 1
            if (!pastEnd && !pastStart) continue
            const cut = (pastEnd && r.left < sr.right - 1) || (pastStart && r.right > sr.left + 1)
            const name = short(
              c.getAttribute('aria-label') || c.textContent || c.getAttribute('title'),
              30
            )
            if (strip)
              out.clipped.push(
                `${cut ? 'control cut at the edge of' : 'control hidden in'} a sideways strip: "${name}"`
              )
            else if (cut) out.clipped.push(`control cut by a scroller's edge: "${name}"`)
          }
        }
      }
      const vw = document.documentElement.clientWidth
      for (const t of texts) {
        if (t.r.right > vw + 1 && t.layer === document.documentElement) {
          out.clipped.push(`past the screen edge: "${t.text}" right=${Math.round(t.r.right)}`)
        }
      }
      for (const text of offStart) out.clipped.push(`past the start edge: "${text}"`)
      const doc = document.scrollingElement ?? document.documentElement
      if (doc.scrollWidth > doc.clientWidth + 1) {
        out.clipped.push(`page scrolls sideways by ${doc.scrollWidth - doc.clientWidth}px`)
      }
      out.clipped = [...new Set(out.clipped)]

      // (d) controls side by side in one row with different heights.
      // A segmented control (buttons inside one bordered frame) counts as one
      // control of the frame's height.
      const framed = new Map<Element, { el: Element; layer: Element; r: DOMRect }>()
      for (const c of controls) {
        const frame = c.el.closest(
          '[role=group],[role=radiogroup],[data-slot=view-switcher],[data-slot=toggle-group]'
        )
        const fr = frame?.getBoundingClientRect()
        if (frame && fr && fr.height <= 44 && fr.height > c.r.height) {
          if (!framed.has(frame)) framed.set(frame, { el: frame, layer: c.layer, r: fr })
        } else framed.set(c.el, c)
      }
      const fields = controls.filter((c) => c.el.matches('input,textarea,[role=combobox]'))
      const insideField = (c: { el: Element; r: DOMRect }) =>
        fields.some(
          (f) =>
            f.el !== c.el &&
            c.r.left >= f.r.left - 1 &&
            c.r.right <= f.r.right + 1 &&
            c.r.top >= f.r.top - 1 &&
            c.r.bottom <= f.r.bottom + 1
        )
      // A multi-line field (textarea) is not a one-line control; a button drawn
      // inside a field (Show password, Clear) is part of the field.
      const rowControls = [...framed.values()].filter(
        (c) =>
          !c.el.matches('[role=switch],[role=checkbox],[type=checkbox],[type=radio],textarea') &&
          c.r.height <= 48 &&
          !insideField(c) &&
          !c.el.closest(
            '[role=tablist],[role=menu],[role=listbox],table,[data-slot=badge],nav,[data-slot=segment]'
          ) &&
          c.r.height > 14
      )
      const byParent = new Map<Element, typeof rowControls>()
      for (const c of rowControls) {
        // The row is the nearest flex or grid container holding the control.
        let p = c.el.parentElement
        while (p && !/flex|grid/.test(getComputedStyle(p).display)) p = p.parentElement
        if (!p) continue
        const list = byParent.get(p) ?? []
        list.push(c)
        byParent.set(p, list)
      }
      // Controls of sibling groups in one row share the row's container too.
      for (const [row, list] of byParent) {
        const all = new Set(list)
        for (const [other, more] of byParent)
          if (other !== row && row.contains(other)) more.forEach((m) => all.add(m))
        const items = [...all]
        if (items.length < 2) continue
        const lines: (typeof items)[] = []
        for (const c of items) {
          const mid = c.r.top + c.r.height / 2
          const line = lines.find((l) => Math.abs(l[0].r.top + l[0].r.height / 2 - mid) < 6)
          if (line) line.push(c)
          else lines.push([c])
        }
        for (const line of lines) {
          if (line.length < 2) continue
          const hs = line.map((c) => Math.round(c.r.height))
          if (Math.max(...hs) - Math.min(...hs) > 2) {
            const names = line.map(
              (c) =>
                `${short(c.el.getAttribute('aria-label') || c.el.textContent || c.el.tagName, 18)} ${Math.round(c.r.height)}`
            )
            out.mixedRows.push(names.join(' | '))
          }
        }
      }
      out.mixedRows = [...new Set(out.mixedRows)]

      // (f) a label with no value: dl pairs and phone card fields.
      for (const root of roots) {
        for (const dd of Array.from(root.querySelectorAll('dd'))) {
          if (!shown(dd) || hiddenByAncestor(dd)) continue
          const hasValue =
            short(dd.textContent) ||
            dd.querySelector(
              'svg,img,input,button,canvas,[role=switch],[role=meter],[role=progressbar],[aria-busy=true]'
            )
          if (!hasValue) {
            let dt = dd.previousElementSibling
            while (dt && dt.tagName !== 'DT') dt = dt.previousElementSibling
            dt = dt ?? dd.parentElement?.querySelector('dt') ?? null
            out.emptyLabels.push(`"${short(dt?.textContent, 30)}" has no value`)
          }
        }
      }

      // (g) lopsided rows. The drawn boxes of an element: its text (line by
      // line) and its controls, icons and images.
      const drawn = (root: Element): DOMRect[] => {
        const boxes: DOMRect[] = []
        const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
        for (let n = walk.nextNode(); n; n = walk.nextNode()) {
          const parent = n.parentElement
          if (!n.textContent?.trim() || !parent || !shown(parent) || hiddenByAncestor(parent))
            continue
          const range = document.createRange()
          range.selectNodeContents(n)
          for (const r of Array.from(range.getClientRects())) if (r.width > 0.5) boxes.push(r)
        }
        for (const el of Array.from(
          root.querySelectorAll(
            'button,input,select,textarea,a[href],img,svg,[role=checkbox],[data-slot=person-card-chevron]'
          )
        )) {
          if (shown(el) && !el.closest('.sr-only')) boxes.push(el.getBoundingClientRect())
        }
        return boxes
      }
      for (const root of roots) {
        // A phone card (300 px and wider) whose content stops more than 40 px
        // short of its end: all of it bunched at the start, nothing (a state,
        // a chevron, an action, text that runs on) balancing the end. Only the
        // first screens are measured, as a person sees them.
        for (const card of Array.from(root.querySelectorAll('[data-phone-card]'))) {
          if (!shown(card)) continue
          const c = card.getBoundingClientRect()
          if (c.width < 300 || c.top > innerHeight * 2) continue
          const boxes = drawn(card)
          if (!boxes.length) continue
          const end = Math.max(...boxes.map((b) => b.right))
          if (end < c.right - 40) {
            out.lopsided.push(
              `card "${short(card.textContent, 30)}" ends at ${Math.round((100 * (end - c.left)) / c.width)}% of its width`
            )
          }
        }
        // A list title row (300 px and wider) with a line whose start is empty
        // (more than a quarter of the width and 80 px): controls pushed to the
        // end of a line of their own. A line always starts with its content.
        for (const row of Array.from(root.querySelectorAll('[data-slot="list-title-row"]'))) {
          if (!shown(row) || hiddenByAncestor(row)) continue
          const r = row.getBoundingClientRect()
          if (r.width < 300) continue
          const lines: { top: number; bottom: number; left: number }[] = []
          for (const b of drawn(row).sort((x, y) => x.top - y.top)) {
            const line = lines.find((l) => b.top < l.bottom - 2 && b.bottom > l.top + 2)
            if (line) {
              line.left = Math.min(line.left, b.left)
              line.bottom = Math.max(line.bottom, b.bottom)
            } else lines.push({ top: b.top, bottom: b.bottom, left: b.left })
          }
          for (const l of lines) {
            if (l.left - r.left > Math.max(80, r.width / 4)) {
              out.lopsided.push(
                `title row line at y ${Math.round(l.top)} holds only end controls (starts at ${Math.round((100 * (l.left - r.left)) / r.width)}%)`
              )
            }
          }
          // A phone title row whose one control is an icon (Refresh) standing
          // alone at its end: it belongs in the toolbar's end (a list's "..." menu included).
          if (innerWidth < 768) {
            const ctrls = Array.from(row.querySelectorAll('button,a[href],[role=button]')).filter(
              (c) =>
                shown(c) &&
                !hiddenByAncestor(c) &&
                !(c.parentElement?.closest('button,a[href],[role=button]') ?? null)
            )
            const icon = ctrls[0]
            const visibleText = (el: Element) => {
              const w = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
              for (let n = w.nextNode(); n; n = w.nextNode())
                if (n.textContent?.trim() && n.parentElement && !hiddenByAncestor(n.parentElement))
                  return true
              return false
            }
            if (ctrls.length === 1 && !visibleText(icon)) {
              out.lopsided.push(
                `title row holds one icon control alone: "${short(icon.getAttribute('aria-label') || icon.getAttribute('title'), 30)}"`
              )
            }
          }
        }
      }
      out.lopsided = [...new Set(out.lopsided)]
      return out
    },
    { scope, enOnly: vi ? englishOnlyStrings() : [] }
  )
}

/** One line per finding, "kind: finding", for messages and reports. */
export function formatBreaks(b: Breaks): string[] {
  return BREAK_KINDS.flatMap((k) => b[k].map((x) => `${k}: ${x}`))
}

// ---------- rich data ----------

export type Scenario = 'rich' | 'empty' | 'one'

const LONG_EN =
  'Payments platform external perimeter: every production hostname of the checkout and refunds services'
const LONG_VI =
  'Hệ thống thanh toán trực tuyến của Tổng công ty Bưu chính Viễn thông: toàn bộ máy chủ sản xuất và dịch vụ hoàn tiền'
const LONG_HOST =
  'checkout-refunds-payments-gateway-production-eu-west-1.internal-services.example.com'
const LONG_TEXT =
  'Không có cảm biến nào đang trực tuyến giữ quyền với các mục tiêu này; scan window closed until Monday 06:00'
const NAMEY =
  /^(name|title|display_name|scan_name|asset_name|hostname|full_name|label|summary|workflow_name|group_name|subject_name|target)$/
const OPTIONAL =
  /^(description|error_message|message|owner|owner_name|owner_email|notes|reason|assignee|assignee_name|group_name|triggered_by_name)$/
const COUNTY = /(_count|^count)$/
const SKIP =
  /\/(me|auth|permissions|modules|tenants|preferences|features|license|nav|nav-pins|saved-views|notifications\/unread|settings|i18n|session|sessions\/current|users\/me|health|dashboard)(\/|\?|$)/

function vary(row: unknown, i: number, depth = 0): unknown {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return row
  const o: Record<string, unknown> = { ...(row as Record<string, unknown>) }
  for (const [k, v] of Object.entries(o)) {
    if (k === 'id' && typeof v === 'string' && v.length > 8) {
      o.id = v.slice(0, -6) + String(i).padStart(6, '0')
    } else if (typeof v === 'string' && NAMEY.test(k) && depth === 0) {
      o[k] = [v, LONG_EN, LONG_VI, 'x', LONG_HOST, `${v} ${i}`][i % 6]
    } else if (typeof v === 'number' && COUNTY.test(k)) {
      o[k] = [0, 1, v || 7, 12840][i % 4]
    } else if (v && typeof v === 'object' && !Array.isArray(v) && depth < 2) {
      o[k] = vary(v, i, depth + 1)
    }
    // Optional text: absent on some rows, long on others, as sent.
    if (OPTIONAL.test(k) && (typeof v === 'string' || v === null || v === undefined)) {
      if (i % 4 === 3) o[k] = null
      else if (i % 4 === 1) o[k] = LONG_TEXT
    }
  }
  // A description the API leaves out when empty: present on some rows.
  if (depth === 0 && i % 4 === 1 && !('description' in o) && 'name' in o) o.description = LONG_TEXT
  return o
}

/** The array keys of a list answer; a list that names its rows is added here. */
const LIST_KEYS = ['data', 'items', 'roles', 'groups', 'rules']

/** The stored dashboard snapshot the home reads (the one request that opens `/`). */
const DASHBOARD_DATA = /\/api\/v1\/(me|organization)\/dashboards\/(home|[^/]+\/data)$/

/**
 * Makes one widget result of a dashboard snapshot hard on the layout: long
 * English, Vietnamese and host-name titles in its lists, five-digit figures,
 * long category names. Only results the server sent as ready are changed
 * (a building or not measured widget keeps its reason); the shape is kept.
 */
function richWidget(w: Record<string, unknown>): Record<string, unknown> {
  if (w.state !== 'ready') return w
  const o: Record<string, unknown> = { ...w }
  const big = (v: unknown) => (typeof v === 'number' && v > 0 ? v * 1000 + 840 : v)
  const scalar = o.scalar as Record<string, unknown> | undefined
  if (scalar) o.scalar = { ...scalar, value: big(scalar.value), previous: big(scalar.previous) }
  const items = o.items as { rows?: Record<string, unknown>[]; total?: number } | undefined
  if (items?.rows?.length) {
    const rows = Array.from({ length: 10 }, (_, i) => {
      const r = items.rows![i % items.rows!.length]
      return {
        ...r,
        id: `${String(r.id ?? 'row').slice(0, 24)}-${i}`,
        title: [r.title, LONG_EN, LONG_VI, LONG_HOST][i % 4],
        asset_name: [r.asset_name, LONG_HOST, LONG_VI, 'x'][i % 4],
      }
    })
    o.items = { ...items, rows, total: 12840 }
  }
  const category = o.category as { rows?: Record<string, unknown>[] } | undefined
  if (category?.rows?.length) {
    o.category = {
      ...category,
      rows: category.rows.map((r, i) => ({
        ...r,
        value: big(r.value),
        ...(typeof r.label === 'string' ? { label: [r.label, LONG_EN, LONG_VI][i % 3] } : {}),
      })),
    }
  }
  const stages = o.stages as { stages?: Record<string, unknown>[] } | undefined
  if (stages?.stages?.length) {
    o.stages = { ...stages, stages: stages.stages.map((x) => ({ ...x, value: big(x.value) })) }
  }
  return o
}

/** Every widget list inside a dashboard answer (the home nests the snapshot). */
function richDashboard(body: unknown): unknown {
  if (!body || typeof body !== 'object') return body
  if (Array.isArray(body)) return body.map(richDashboard)
  const o: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
    o[k] =
      k === 'widgets' && Array.isArray(v)
        ? v.map((w) => (w && typeof w === 'object' ? richWidget(w as Record<string, unknown>) : w))
        : richDashboard(v)
  }
  return o
}

/**
 * Rewrites the JSON list answers of the page's API calls: 200 rows (or 0, or 1)
 * built from the seed rows, with long and Vietnamese names and optional fields
 * present and absent. Only GET answers of the shape `{data|items: [...]}`, and
 * the lists that name their rows (`LIST_KEYS`).
 */
export async function richData(page: Page, scen: Scenario = 'rich') {
  await page.route('**/api/v1/**', async (route: Route) => {
    const req = route.request()
    const url = new URL(req.url())
    if (req.method() === 'GET' && scen === 'rich' && DASHBOARD_DATA.test(url.pathname)) {
      const res = await route.fetch().catch(() => null)
      if (!res) return route.fallback()
      const body = await res.json().catch(() => null)
      return body === null
        ? route.fulfill({ response: res })
        : route.fulfill({ response: res, json: richDashboard(body) })
    }
    if (req.method() !== 'GET' || SKIP.test(url.pathname)) return route.fallback()
    let res
    try {
      res = await route.fetch()
    } catch {
      return route.fallback()
    }
    let body: Record<string, unknown>
    try {
      body = await res.json()
    } catch {
      return route.fulfill({ response: res })
    }
    const key = LIST_KEYS.find((k) => Array.isArray(body?.[k])) ?? null
    const rows = key ? (body[key] as unknown[]) : []
    if (!key || !rows.length || typeof rows[0] !== 'object')
      return route.fulfill({ response: res, json: body })
    const total = scen === 'empty' ? 0 : scen === 'one' ? 1 : 200
    const per = Number(
      url.searchParams.get('per_page') ?? url.searchParams.get('limit') ?? (body.per_page || 25)
    )
    const pg = Number(url.searchParams.get('page') ?? 1)
    const n = Math.max(0, Math.min(per, total - (pg - 1) * per))
    const data = Array.from({ length: n }, (_, k) =>
      vary(rows[((pg - 1) * per + k) % rows.length], (pg - 1) * per + k)
    )
    const out: Record<string, unknown> = { ...body, [key]: data }
    for (const t of ['total', 'total_count', 'count']) if (t in body) out[t] = total
    if ('total_pages' in body) out.total_pages = Math.ceil(total / per)
    if ('has_more' in body) out.has_more = pg * per < total
    return route.fulfill({ response: res, json: out })
  })
}
