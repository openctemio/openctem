/**
 * Content-aware column widths of the shared DataTable (`columnSizing="content"`).
 * Spec of record: docs/ui-style-contract.md, "Tables" (column sizing).
 *
 * A column declares what it holds (its kind), never a width in px. Each kind
 * has a floor, a cap and a flex weight (`KIND_SIZING`). The table measures the
 * header and the rows on screen (`measure-columns.ts`) and this module turns
 * those natural widths into one width per column for the frame:
 *
 * 1. Each column asks for its natural width clamped to [min, max].
 * 2. Room to spare: first the columns whose content is longer than their cap
 *    grow toward their content (nothing is cut while there is room), then the
 *    flexible columns (weight > 0: the title first) share the rest by weight.
 * 3. Room short: the flexible columns give way first (the heavier, the
 *    less: the title gives least), down to
 *    their floor (a title ends in an ellipsis with its full text in a
 *    tooltip); then the other shrinkable columns (status, owner) down to
 *    theirs. A column that holds a whole value (a chip, a date, a number)
 *    never goes below its content. What is still missing, the frame scrolls.
 *
 * Pure functions only: the same inputs always give the same widths, so a
 * resize recomputes without measuring again.
 */
import type { ColumnKind } from './column-meta'

export interface KindSizing {
  /** Floor in px (cell padding included). */
  min: number
  /** Cap in px for what the column asks before spare room is shared. */
  max: number
  /** Share of the spare room and of the shortfall; 0 = sized by its content. */
  weight: number
  /** May go below its content when room is short (it truncates or wraps). */
  shrink: boolean
}

/**
 * Floors, caps and weights per kind. Floors and caps hold the cell padding
 * (12 px at the row's ends, 6 px between cells); they bound what content
 * measuring may ask, they are not the widths themselves.
 */
export const KIND_SIZING: Record<ColumnKind, KindSizing> = {
  // The row's title: takes the spare room first and gives way first.
  name: { min: 192, max: 640, weight: 4, shrink: true },
  // Free text (a description, a source, a path): ellipsis + title when cut.
  text: { min: 96, max: 320, weight: 1, shrink: true },
  // A target name and its address: truncates in the middle of long hosts.
  asset: { min: 128, max: 360, weight: 2, shrink: true },
  // Chips that fold into "+N": never cut, they fold.
  tags: { min: 112, max: 280, weight: 1, shrink: true },
  // A person or team: wraps between words when narrow.
  owner: { min: 112, max: 240, weight: 0, shrink: true },
  // A status lozenge whole (a sub-status beside it truncates inside the cell).
  status: { min: 88, max: 260, weight: 0, shrink: false },
  'status-edit': { min: 120, max: 240, weight: 0, shrink: false },
  // Whole values: as wide as their longest value on screen.
  id: { min: 72, max: 240, weight: 0, shrink: false },
  priority: { min: 48, max: 112, weight: 0, shrink: false },
  risk: { min: 88, max: 176, weight: 0, shrink: false },
  severity: { min: 80, max: 160, weight: 0, shrink: false },
  'datetime-recent': { min: 80, max: 184, weight: 0, shrink: false },
  date: { min: 88, max: 160, weight: 0, shrink: false },
  due: { min: 88, max: 176, weight: 0, shrink: false },
  number: { min: 48, max: 136, weight: 0, shrink: false },
  signals: { min: 80, max: 240, weight: 0, shrink: false },
  masked: { min: 160, max: 280, weight: 0, shrink: false },
  select: { min: 40, max: 40, weight: 0, shrink: false },
  actions: { min: 0, max: 200, weight: 0, shrink: false },
  decisions: { min: 0, max: 400, weight: 0, shrink: false },
}

/** The name floor on a narrow viewport: min(12rem, 36vw), as before. */
export function nameFloor(viewport: number): number {
  return viewport > 0 ? Math.min(192, Math.round(viewport * 0.36)) : 192
}

export interface SizingColumn {
  id: string
  kind: ColumnKind
  /** Measured width of the widest cell or the header (px, padding included). */
  natural?: number
  /** A page override: exactly this wide, never measured. */
  fixed?: number
  /** Page overrides of the kind's floor and cap. */
  min?: number
  max?: number
}

interface Resolved {
  id: string
  natural: number
  desired: number
  floor: number
  weight: number
  shrink: boolean
  fixed: boolean
}

/**
 * Shares `amount` px among `items` by weight, each up to its `room`, refilling
 * from the others when one is full (water filling). Integer px; the result
 * never exceeds `amount` or an item's room.
 */
export function distribute(
  amount: number,
  items: readonly { id: string; weight: number; room: number }[]
): Map<string, number> {
  const out = new Map<string, number>()
  let left = Math.max(0, Math.floor(amount))
  let open = items.filter((i) => i.room > 0 && i.weight > 0)
  while (left > 0 && open.length > 0) {
    const total = open.reduce((s, i) => s + i.weight, 0)
    let given = 0
    const parts = open.map((i) => {
      const exact = (left * i.weight) / total
      const room = i.room - (out.get(i.id) ?? 0)
      const part = Math.min(Math.floor(exact), room)
      return { i, part, frac: exact - Math.floor(exact), room }
    })
    for (const p of parts) {
      out.set(p.i.id, (out.get(p.i.id) ?? 0) + p.part)
      given += p.part
    }
    // Rounding: whole px to the largest remainders that still have room.
    let rest = Math.min(left - given, left)
    if (given === 0 || rest > 0) {
      const byFrac = [...parts].sort((a, b) => b.frac - a.frac)
      for (const p of byFrac) {
        if (rest <= 0) break
        if ((out.get(p.i.id) ?? 0) < p.i.room) {
          out.set(p.i.id, (out.get(p.i.id) ?? 0) + 1)
          given++
          rest--
        }
      }
    }
    if (given === 0) break
    left -= given
    open = open.filter((i) => (out.get(i.id) ?? 0) < i.room)
  }
  return out
}

/**
 * One width (px) per column for a frame `frame` px wide, or `null` while the
 * frame or the columns are not measured yet (the table then keeps its kind
 * defaults). The widths sum to the frame when everything fits, to more when
 * the frame must scroll.
 */
export function allocateColumnWidths(
  columns: readonly SizingColumn[],
  frame: number,
  viewport = 0
): Map<string, number> | null {
  if (frame <= 0 || columns.length === 0) return null
  if (columns.some((c) => c.fixed === undefined && c.natural === undefined)) return null
  const cols: Resolved[] = columns.map((c) => {
    const kind = KIND_SIZING[c.kind]
    if (c.fixed !== undefined) {
      const w = Math.round(c.fixed)
      return { id: c.id, natural: w, desired: w, floor: w, weight: 0, shrink: false, fixed: true }
    }
    const kindMin = c.kind === 'name' ? nameFloor(viewport) : kind.min
    const min = Math.round(c.min ?? kindMin)
    const max = Math.max(min, Math.round(c.max ?? kind.max))
    const natural = Math.ceil(c.natural ?? min)
    const desired = Math.min(max, Math.max(min, natural))
    return {
      id: c.id,
      natural,
      desired,
      // A whole value never goes below its content (or its floor).
      floor: kind.shrink ? min : desired,
      weight: kind.weight,
      shrink: kind.shrink,
      fixed: false,
    }
  })
  const widths = new Map(cols.map((c) => [c.id, c.desired]))
  const sum = () => [...widths.values()].reduce((s, w) => s + w, 0)
  let gap = Math.floor(frame) - sum()

  if (gap > 0) {
    // (a) Content longer than its cap: give it its content first.
    const cut = cols
      .filter((c) => !c.fixed && c.natural > c.desired)
      .map((c) => ({ id: c.id, weight: Math.max(1, c.weight), room: c.natural - c.desired }))
    for (const [id, add] of distribute(gap, cut)) widths.set(id, widths.get(id)! + add)
    gap = Math.floor(frame) - sum()
    // (b) The rest to the flexible columns by weight; without any, to the
    // columns sized by content (never the checkbox or the row menu).
    if (gap > 0) {
      const flex = cols.filter((c) => !c.fixed && c.weight > 0)
      const takers =
        flex.length > 0
          ? flex.map((c) => ({ id: c.id, weight: c.weight, room: Number.MAX_SAFE_INTEGER }))
          : cols
              .filter((c) => !c.fixed && c.id !== 'select' && c.id !== 'actions')
              .map((c) => ({ id: c.id, weight: 1, room: Number.MAX_SAFE_INTEGER }))
      const fallback =
        takers.length > 0
          ? takers
          : cols.slice(-1).map((c) => ({ id: c.id, weight: 1, room: Number.MAX_SAFE_INTEGER }))
      for (const [id, add] of distribute(gap, fallback)) widths.set(id, widths.get(id)! + add)
    }
    return widths
  }

  if (gap < 0) {
    // (1) Flexible columns give way by weight, (2) then the other shrinkable ones.
    for (const pass of [(c: Resolved) => c.weight > 0, (c: Resolved) => c.weight === 0]) {
      const need = -(Math.floor(frame) - sum())
      if (need <= 0) break
      const givers = cols
        .filter((c) => !c.fixed && c.shrink && pass(c))
        .map((c) => ({
          id: c.id,
          // In proportion to what it can give, the title (the heaviest
          // weight) giving the least: it is the row's name.
          weight: (widths.get(c.id)! - c.floor) / Math.max(1, c.weight),
          room: widths.get(c.id)! - c.floor,
        }))
      for (const [id, take] of distribute(need, givers)) widths.set(id, widths.get(id)! - take)
    }
  }
  return widths
}

/**
 * Merges a new measurement into the kept natural widths without visible
 * jumps (hysteresis):
 * - a column measured for the first time takes its measurement;
 * - a flexible column (weight > 0) keeps its width once rows were measured:
 *   later pages, sorts and refreshes do not move the title;
 * - a column sized by content only grows, and only by more than `HYSTERESIS`
 *   px (a longer chip on page 2 is shown whole, a 1 px wobble is ignored).
 * Returns the same map when nothing changed.
 */
export const HYSTERESIS = 2

export function mergeNatural(
  kept: ReadonlyMap<string, number>,
  measured: ReadonlyMap<string, number>,
  kinds: ReadonlyMap<string, ColumnKind>,
  rowsMeasured: boolean
): ReadonlyMap<string, number> {
  let next: Map<string, number> | null = null
  for (const [id, w] of measured) {
    const prev = kept.get(id)
    let value: number | undefined
    if (prev === undefined) value = w
    else if (!rowsMeasured) value = undefined
    else {
      const kind = kinds.get(id)
      const flexible = kind ? KIND_SIZING[kind].weight > 0 : false
      if (!flexible && w > prev + HYSTERESIS) value = w
    }
    if (value !== undefined && value !== prev) {
      next ??= new Map(kept)
      next.set(id, value)
    }
  }
  return next ?? kept
}

/**
 * The title width optional columns must leave (px): below it, the next
 * optional column drops rather than cutting the title further.
 */
export const NAME_COMFORT = 320

/** The narrowest a column may get before the frame scrolls (px). */
export function columnFloor(c: SizingColumn, viewport = 0): number {
  if (c.fixed !== undefined) return Math.round(c.fixed)
  const kind = KIND_SIZING[c.kind]
  const min = Math.round(c.min ?? (c.kind === 'name' ? nameFloor(viewport) : kind.min))
  if (kind.shrink) return min
  const max = Math.max(min, Math.round(c.max ?? kind.max))
  return Math.min(max, Math.max(min, Math.ceil(c.natural ?? min)))
}

/**
 * Column priority by content: the columns a frame `frame` px wide cannot
 * hold at their floors, dropped in priority order (`drop`, the column's
 * `meta.dropOrder`: 1 drops first, then 2; columns without one always stay) until the floors fit. A column
 * not measured yet counts at its kind floor and is checked again once
 * measured (before paint).
 */
export function columnsToDrop(
  columns: readonly (SizingColumn & { drop?: number })[],
  frame: number,
  viewport = 0
): Set<string> {
  const out = new Set<string>()
  if (frame <= 0) return out
  // An optional column shows only while the title keeps a readable width
  // (its content up to NAME_COMFORT): fuller titles before more columns.
  const room = (c: SizingColumn) =>
    c.kind === 'name' && c.fixed === undefined
      ? Math.max(columnFloor(c, viewport), Math.min(NAME_COMFORT, Math.ceil(c.natural ?? 0)))
      : columnFloor(c, viewport)
  let need = columns.reduce((s, c) => s + room(c), 0)
  const droppable = columns.filter((c) => c.drop !== undefined).sort((a, b) => a.drop! - b.drop!)
  for (const c of droppable) {
    if (need <= frame) break
    out.add(c.id)
    need -= room(c)
  }
  return out
}
