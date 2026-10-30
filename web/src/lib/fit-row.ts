/**
 * How many items of a one-line row fit in `avail` pixels, keeping room for a
 * "+N" opener when not all of them do. Items keep their order (the caller
 * sorts them by priority) and are never cut: an item that does not fit
 * whole, and everything after it, folds into "+N".
 *
 * Shared by every chip row that folds instead of wrapping (the filter chips
 * row, the asset list's service facts), so they fold by the same rule.
 *
 * @param avail  width of the row
 * @param widths width of each item, in order
 * @param gap    space between two items (and between the last item and "+N")
 * @param more   width kept for the "+N" opener
 */
export function foldToFit(avail: number, widths: number[], gap: number, more: number): number {
  const n = widths.length
  const all = widths.reduce((s, w) => s + w, 0) + gap * Math.max(0, n - 1)
  if (all <= avail) return n
  let fit = 0
  let used = more
  for (const w of widths) {
    if (used + w + gap > avail) break
    used += w + gap
    fit += 1
  }
  return fit
}
