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
 */

export interface FitColumnInput {
  id: string
  /** Fixed width in px. */
  width?: number
  /** Floor in px. */
  minWidth?: number
}

/**
 * The narrowed widths (px) of the columns that give way, keyed by column id,
 * for a frame `frame` px wide (0 when not measured yet: nothing narrows).
 */
export function fitColumnWidths(
  columns: readonly FitColumnInput[],
  frame: number
): Map<string, number> {
  const fitted = new Map<string, number>()
  if (frame <= 0) return fitted
  const need = columns.reduce((sum, c) => sum + (c.width ?? c.minWidth ?? 0), 0)
  const deficit = need - frame
  if (deficit <= 0) return fitted
  const ranged = columns.filter(
    (c) => c.width !== undefined && c.minWidth !== undefined && c.minWidth < c.width
  )
  const range = ranged.reduce((sum, c) => sum + (c.width! - c.minWidth!), 0)
  if (range === 0) return fitted
  const give = Math.min(deficit, range)
  let left = give
  ranged.forEach((c, i) => {
    const span = c.width! - c.minWidth!
    // The last column takes the rounding, so the total given is exact.
    const share = i === ranged.length - 1 ? left : Math.ceil((give * span) / range)
    const taken = Math.min(share, span, left)
    left -= taken
    fitted.set(c.id, c.width! - taken)
  })
  return fitted
}
