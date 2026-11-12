/**
 * DOM checks of the layout pass, run in the page (page.evaluate). They read
 * boxes only, so the same DOM gives the same answer every run:
 *
 *   sideways  the document is wider than the viewport (horizontal page scroll)
 *   clipped   an element cuts its own text off: overflow hidden or clip with
 *             content wider or taller than its box, and no ellipsis or line
 *             clamp (intended truncation is allowed); a control whose text
 *             spills outside it; or text or a field pushed past the edge of
 *             an ancestor that clips (a card, a dialog)
 *   overlap   two visible interactive elements cover each other by more than
 *             2 px in both directions (line boxes, so wrapped links count
 *             per line), neither inside the other; a button drawn inside a
 *             field (show password, clear) is an adornment, not an overlap
 *
 * Elements hidden from everyone (display none, visibility hidden, opacity 0,
 * zero size) and screen-reader-only text (clipped to 1 px on purpose) are
 * skipped.
 */

export interface LayoutIssue {
  kind: 'sideways' | 'clipped' | 'overlap'
  detail: string
}

export function layoutIssues(): LayoutIssue[] {
  const issues: LayoutIssue[] = []
  const label = (el: Element): string => {
    const text = (el as HTMLElement).innerText?.trim().replace(/\s+/g, ' ').slice(0, 40)
    const aria = el.getAttribute('aria-label')
    const slot = el.getAttribute('data-slot')
    return `<${el.tagName.toLowerCase()}${slot ? ` data-slot=${slot}` : ''}> "${text || aria || ''}"`
  }
  const visible = (el: Element): boolean => {
    const r = el.getBoundingClientRect()
    if (r.width < 2 || r.height < 2) return false
    for (let e: Element | null = el; e; e = e.parentElement) {
      const s = getComputedStyle(e)
      if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') return false
    }
    return true
  }

  const doc = document.documentElement
  if (doc.scrollWidth > doc.clientWidth + 1) {
    issues.push({
      kind: 'sideways',
      detail: `page is ${doc.scrollWidth}px wide in a ${doc.clientWidth}px viewport`,
    })
  }

  const ownText = (el: Element) =>
    [...el.childNodes].some((n) => n.nodeType === Node.TEXT_NODE && n.textContent?.trim())
  const fields = 'input:not([type="hidden"]), textarea, select'
  /** The nearest ancestor that clips its content (overflow hidden or clip), and on which axes. */
  const clipper = (el: Element): { box: Element; x: boolean; y: boolean } | null => {
    for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
      const s = getComputedStyle(p)
      const x = /hidden|clip/.test(s.overflowX)
      const y = /hidden|clip/.test(s.overflowY)
      if ((x || y) && p.clientWidth > 1) return { box: p, x, y }
    }
    return null
  }
  /** True when an element between `el` and `box` (or `el` itself) truncates with an ellipsis. */
  const truncated = (el: Element, box: Element): boolean => {
    for (let p: Element | null = el; p && p !== box; p = p.parentElement) {
      if (getComputedStyle(p).textOverflow === 'ellipsis') return true
    }
    return false
  }
  const controls =
    'button, a[href], [role="button"], [role="tab"], [role="menuitem"], [data-slot="badge"]'
  for (const el of document.body.querySelectorAll<HTMLElement>('*')) {
    if (!visible(el)) continue
    const s = getComputedStyle(el)
    const hides = /hidden|clip/.test(s.overflowX + s.overflowY)
    const truncates = s.textOverflow === 'ellipsis' || s.webkitLineClamp !== 'none'
    const srOnly = s.position === 'absolute' && el.clientWidth <= 1
    if (srOnly) continue
    const wide = el.scrollWidth > el.clientWidth + 1
    const tall = el.scrollHeight > el.clientHeight + 1
    if (hides && !truncates && (wide || tall) && ownText(el)) {
      issues.push({ kind: 'clipped', detail: `${label(el)} cuts its text off` })
    } else if (!hides && wide && el.matches(controls) && ownText(el)) {
      issues.push({ kind: 'clipped', detail: `${label(el)} text spills out of the control` })
    } else if (ownText(el) || el.matches(fields)) {
      // Text or a field pushed past the edge of a box that clips it (a card,
      // a dialog): visible nowhere, scrollable nowhere.
      const clip = clipper(el)
      if (clip) {
        const r = el.getBoundingClientRect()
        const c = clip.box.getBoundingClientRect()
        const outX = clip.x && (r.right > c.right + 1 || r.left < c.left - 1)
        const outY = clip.y && (r.bottom > c.bottom + 1 || r.top < c.top - 1)
        if ((outX || outY) && !truncated(el, clip.box)) {
          issues.push({ kind: 'clipped', detail: `${label(el)} is cut off by ${label(clip.box)}` })
        }
      }
    }
  }

  const interactive = [
    ...document.body.querySelectorAll<HTMLElement>(
      'a[href], button, input:not([type="hidden"]), select, textarea, [role="button"], [role="link"], [role="checkbox"], [role="tab"], [role="switch"], [role="menuitem"]'
    ),
  ].filter(visible)
  // Line boxes, not the bounding box: a link that wraps covers two partial
  // lines, and its bounding box would claim the whole width of both.
  const boxes = (el: Element) => [...el.getClientRects()].filter((r) => r.width > 2 && r.height > 2)
  const inside = (r: DOMRect, outer: DOMRect) =>
    r.left >= outer.left - 1 &&
    r.right <= outer.right + 1 &&
    r.top >= outer.top - 1 &&
    r.bottom <= outer.bottom + 1
  const field = (el: Element) => el.matches('input, textarea, select')
  for (let i = 0; i < interactive.length; i++) {
    const a = interactive[i]
    for (let j = i + 1; j < interactive.length; j++) {
      const b = interactive[j]
      if (a.contains(b) || b.contains(a)) continue
      const hit = boxes(a).some((ra) =>
        boxes(b).some((rb) => {
          const w = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left)
          const h = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top)
          if (w <= 2 || h <= 2) return false
          // A button placed inside a field (show password, clear) is an adornment.
          if (field(a) && inside(rb, ra)) return false
          if (field(b) && inside(ra, rb)) return false
          return true
        })
      )
      if (hit) issues.push({ kind: 'overlap', detail: `${label(a)} overlaps ${label(b)}` })
    }
  }
  return issues
}
