/**
 * Narrow the columns that have a range so the table fits its frame before it
 * scrolls sideways. One rule for every table:
 *
 * - A column's room is its width (a fixed column) or its floor (a column
 *   without a width, such as a title, which takes what is left). Widths hold
 *   their cell padding, so the sum of the rooms is the table's width.
 * - When the sum is wider than the frame, the columns whose floor is below
 *   their width give way, in proportion to their range, never below their
 *   floor. What they cannot give, the frame scrolls (Mode B).
 * - When the frame is wider than the sum, the columns whose cap is above
 *   their width (a page asks for it with `maxWidth`, e.g. a location that
 *   truncates) grow first, in proportion to their range, up to their cap.
 *   The column without a width (the title) keeps its floor and takes what is
 *   left, so spare width is never empty space beside a cut value.
 */

export interface FitColumnInput {
  id: string
  /** Fixed width in px. */
  width?: number
  /** Floor in px. */
  minWidth?: number
  /** Cap in px; above `width`, the column grows into spare frame width. */
  maxWidth?: number
}

/** Shares `amount` among `cols` by their spans, the last taking the rounding. */
function share(cols: { id: string; span: number }[], amount: number): Map<string, number> {
  const out = new Map<string, number>()
  const total = cols.reduce((s, c) => s + c.span, 0)
  if (total === 0 || amount <= 0) return out
  const give = Math.min(amount, total)
  let left = give
  cols.forEach((c, i) => {
    const part = i === cols.length - 1 ? left : Math.ceil((give * c.span) / total)
    const taken = Math.min(part, c.span, left)
    left -= taken
    out.set(c.id, taken)
  })
  return out
}

/**
 * The narrowed (or grown) widths (px) of the columns that change, keyed by
 * column id, for a frame `frame` px wide (0 when not measured yet: nothing
 * changes).
 */
export function fitColumnWidths(
  columns: readonly FitColumnInput[],
  frame: number
): Map<string, number> {
  const fitted = new Map<string, number>()
  if (frame <= 0) return fitted
  const need = columns.reduce((sum, c) => sum + (c.width ?? c.minWidth ?? 0), 0)
  const deficit = need - frame
  if (deficit < 0) {
    const growing = columns
      .filter((c) => c.width !== undefined && c.maxWidth !== undefined && c.maxWidth > c.width)
      .map((c) => ({ id: c.id, span: c.maxWidth! - c.width! }))
    const widths = new Map(columns.map((c) => [c.id, c.width ?? 0]))
    for (const [id, add] of share(growing, -deficit)) fitted.set(id, widths.get(id)! + add)
    return fitted
  }
  if (deficit === 0) return fitted
  const ranged = columns
    .filter((c) => c.width !== undefined && c.minWidth !== undefined && c.minWidth < c.width)
    .map((c) => ({ id: c.id, span: c.width! - c.minWidth! }))
  const widths = new Map(columns.map((c) => [c.id, c.width ?? 0]))
  for (const [id, taken] of share(ranged, deficit)) fitted.set(id, widths.get(id)! - taken)
  return fitted
}
