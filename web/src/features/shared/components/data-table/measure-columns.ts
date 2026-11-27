/**
 * Measures the natural width of each visible column of a DataTable: the
 * widest of its header and its rows on screen, laid out on one line, cell
 * padding included. Feeds `allocateColumnWidths` (column-sizing.ts).
 *
 * One pass, no layout thrash: all reads of computed styles first, then one
 * hidden measuring box is written with a copy of every cell's content (one
 * stack per column, `width: max-content`, so the stack is as wide as its
 * widest cell), then one read per column, then the box is removed. Cost is
 * O(columns x rendered rows) node copies and one layout, before paint.
 */

/** Natural widths keyed by column id; empty when nothing could be measured (no layout, e.g. jsdom). */
export interface ColumnMeasurement {
  widths: Map<string, number>
  /** At least one data row was measured (not only headers). */
  rows: boolean
}

/** Classes whose effect would hide the content's real width in the copy. */
const DROP_CLASS = /(^|:)\[?contain|(^|:)sticky$|truncate$|line-clamp|^max-w-|^w-/

function padding(cs: CSSStyleDeclaration): number {
  return (parseFloat(cs.paddingInlineStart) || 0) + (parseFloat(cs.paddingInlineEnd) || 0)
}

/**
 * `root`: the table's frame (holds the `<table>`). `ids`: the visible column
 * ids to measure (others are skipped, e.g. the fixed checkbox column).
 */
export function measureColumns(root: HTMLElement, ids: readonly string[]): ColumnMeasurement {
  const empty: ColumnMeasurement = { widths: new Map(), rows: false }
  const table = root.querySelector('table')
  if (!table) return empty
  const want = new Set(ids)
  const byColumn = new Map<string, HTMLElement[]>()
  const push = (el: HTMLElement) => {
    const id = el.dataset.columnId
    if (!id || !want.has(id)) return
    const list = byColumn.get(id)
    if (list) list.push(el)
    else byColumn.set(id, [el])
  }
  table.querySelectorAll<HTMLElement>('thead th[data-column-id]').forEach(push)
  const rows = table.querySelectorAll<HTMLElement>('tbody tr[data-row-id]')
  rows.forEach((tr) =>
    tr.querySelectorAll<HTMLElement>(':scope > td[data-column-id]').forEach(push)
  )
  if (byColumn.size === 0) return empty

  // Reads: font and padding per column, once from the header and once from
  // the first body cell (the header has its own type role).
  const sample = (el: HTMLElement) => {
    const cs = getComputedStyle(el)
    return { font: cs.font, letter: cs.letterSpacing, pad: padding(cs) }
  }
  const firstOf = new Map<
    string,
    { head?: ReturnType<typeof sample>; body?: ReturnType<typeof sample> }
  >()
  for (const [id, cells] of byColumn) {
    const head = cells.find((c) => c.tagName === 'TH')
    const body = cells.find((c) => c.tagName === 'TD')
    firstOf.set(id, { head: head && sample(head), body: body && sample(body) })
  }

  // Writes: one hidden box, one stack per column.
  const box = document.createElement('div')
  box.setAttribute('aria-hidden', 'true')
  box.setAttribute('data-measure-columns', '')
  box.style.cssText =
    'position:absolute;inset-inline-start:0;top:0;width:0;height:0;overflow:hidden;visibility:hidden;pointer-events:none;contain:layout style size'
  const stacks = new Map<string, HTMLElement>()
  for (const [id, cells] of byColumn) {
    const stack = document.createElement('div')
    stack.style.cssText = 'position:absolute;top:0;width:max-content;white-space:nowrap'
    const first = firstOf.get(id)!
    for (const cell of cells) {
      const s = (cell.tagName === 'TH' ? first.head : first.body) ?? first.body ?? first.head
      if (!s) continue
      const line = document.createElement('div')
      line.style.cssText = `display:flow-root;width:max-content;font:${s.font};letter-spacing:${s.letter}`
      line.className = cell.className
        .split(/\s+/)
        .filter((c) => c && !DROP_CLASS.test(c))
        .join(' ')
      // Keep the cell's text rules but drop its box: the copy is laid out at
      // its content's own width, padding added below.
      line.style.padding = '0'
      line.style.overflow = 'visible'
      line.style.maxWidth = 'none'
      line.style.minWidth = '0'
      line.style.position = 'static'
      for (const child of Array.from(cell.childNodes)) line.appendChild(child.cloneNode(true))
      // Copies of truncating boxes show their whole text.
      line.querySelectorAll<HTMLElement>('*').forEach((el) => {
        el.removeAttribute('id')
        // A size container (`@container`) or `contain` has no content width
        // of its own: lift both so the copy shows how wide the value is.
        el.style.containerType = 'normal'
        el.style.contain = 'none'
        if (el.style.maxWidth) el.style.maxWidth = 'none'
      })
      line
        .querySelectorAll<HTMLElement>('.truncate, [class*="line-clamp"], [class*="max-w-"]')
        .forEach((el) => {
          el.style.maxWidth = 'none'
          el.style.overflow = 'visible'
          el.style.display = el.classList.contains('truncate') ? 'inline-block' : el.style.display
          el.style.webkitLineClamp = 'unset'
        })
      stack.appendChild(line)
    }
    stacks.set(id, stack)
    box.appendChild(stack)
  }
  root.appendChild(box)

  // Reads: one per column (one layout for all of them).
  const widths = new Map<string, number>()
  let any = false
  for (const [id, stack] of stacks) {
    const first = firstOf.get(id)!
    const pad = Math.max(first.body?.pad ?? 0, first.head?.pad ?? 0)
    const w = stack.getBoundingClientRect().width
    if (w > 0) any = true
    widths.set(id, Math.ceil(w + pad))
  }
  box.remove()
  if (!any) return empty
  return { widths, rows: rows.length > 0 }
}
