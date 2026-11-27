/**
 * Which columns freeze at the start of a table that scrolls sideways, and
 * where. One rule for every table:
 *
 * - The checkbox column, when first, is frozen with the group.
 * - Columns marked `pin: 'start'` follow in order while the frozen group stays
 *   within `PIN_START_SHARE` of the table's frame; the first marked column is
 *   always frozen. A table without marked columns freezes its first data
 *   column (its name), as before.
 * - A marked column without a fixed width (a title) is frozen at its floor
 *   and capped at `PIN_FLEX_MAX` and at what the share leaves; it ends the
 *   group, since the columns after it could not know their offset.
 */

/** The largest share of the frame the frozen start group may take. */
export const PIN_START_SHARE = 0.45
/** Widest a frozen column without a fixed width may get, in px. */
export const PIN_FLEX_MAX = 420
/** Width of the selection column, so the frozen columns after it know their offset. */
export const PIN_SELECT_WIDTH = 40

export interface PinColumnInput {
  id: string
  pin?: 'start'
  /** Fixed width in px. */
  width?: number
  /** Floor in px (a column without a fixed width). */
  minWidth?: number
}

export interface StartPin {
  /** Inline-start offset in px. */
  start: number
  /** The group's last column (carries the edge shadow). */
  last: boolean
  /** Cap for a frozen column without a fixed width, in px. */
  maxWidth?: number
  /** Frozen by the table's fallback (first data column), not by `pin`. */
  fallback?: boolean
}

/**
 * The frozen start columns of the visible columns (in order) for a table
 * frame `frame` px wide (0 when not measured yet: only the first is frozen).
 */
export function pinStartColumns(
  columns: readonly PinColumnInput[],
  frame: number
): Map<string, StartPin> {
  const pins = new Map<string, StartPin>()
  const select = columns[0]?.id === 'select' ? columns[0] : undefined
  const data = columns.filter((c) => c.id !== 'select' && c.id !== 'actions')
  const marked = data.filter((c) => c.pin === 'start')
  const budget = frame > 0 ? frame * PIN_START_SHARE : 0
  let offset = select ? PIN_SELECT_WIDTH : 0
  const chosen: { id: string; start: number; maxWidth?: number; fallback?: boolean }[] = []
  if (marked.length === 0) {
    if (data[0]) chosen.push({ id: data[0].id, start: offset, fallback: true })
  } else {
    for (const [i, col] of marked.entries()) {
      const fixed = col.width
      const need = fixed ?? col.minWidth ?? 0
      if (i > 0 && offset + need > budget) break
      if (fixed !== undefined) {
        chosen.push({ id: col.id, start: offset })
        offset += fixed
        continue
      }
      const room = budget > 0 ? Math.floor(budget - offset) : PIN_FLEX_MAX
      chosen.push({
        id: col.id,
        start: offset,
        maxWidth: Math.max(col.minWidth ?? 0, Math.min(PIN_FLEX_MAX, room)),
      })
      break
    }
  }
  if (chosen.length === 0) return pins
  if (select) pins.set(select.id, { start: 0, last: false })
  chosen.forEach((c, i) =>
    pins.set(c.id, {
      start: c.start,
      last: i === chosen.length - 1,
      ...(c.maxWidth !== undefined ? { maxWidth: c.maxWidth } : {}),
      ...(c.fallback ? { fallback: true } : {}),
    })
  )
  return pins
}
