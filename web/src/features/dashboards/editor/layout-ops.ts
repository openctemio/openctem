/**
 * Layout edits the editor offers by pointer and by keyboard. A layout is in
 * reading order; each widget has a width on the 12-unit grid (`w`, mapped to
 * the dashboard's columns) and a height in rows (`h`). Every function returns
 * a new array and leaves the input alone.
 */

import type { DashboardWidget } from '../api/dashboards.types'
import { colSpanFor, normalizeColumns, widthFromSpan } from '../layout'
import { newWidgetId, type WidgetSpec } from '../api/widget-spec'

export const MIN_ROWS = 1
export const MAX_ROWS = 6

export function move(layout: DashboardWidget[], from: number, to: number): DashboardWidget[] {
  if (from === to || from < 0 || from >= layout.length) return layout
  const target = Math.max(0, Math.min(layout.length - 1, to))
  const next = [...layout]
  const [w] = next.splice(from, 1)
  next.splice(target, 0, w)
  return next.map((x, i) => ({ ...x, y: i }))
}

/** Widens (+1) or narrows (-1) a widget by one column of the dashboard. */
export function resizeWidth(
  layout: DashboardWidget[],
  index: number,
  delta: number,
  columns: number | undefined
): DashboardWidget[] {
  const w = layout[index]
  if (!w) return layout
  const cols = normalizeColumns(columns)
  const span = Math.max(1, Math.min(cols, colSpanFor(w.w, cols) + delta))
  const width = widthFromSpan(span, cols)
  if (width === w.w) return layout
  return layout.map((x, i) => (i === index ? { ...x, w: width } : x))
}

/** Makes a widget taller (+1) or shorter (-1) by one row. */
export function resizeHeight(
  layout: DashboardWidget[],
  index: number,
  delta: number
): DashboardWidget[] {
  const w = layout[index]
  if (!w) return layout
  const h = Math.max(MIN_ROWS, Math.min(MAX_ROWS, (w.h || 1) + delta))
  if (h === w.h) return layout
  return layout.map((x, i) => (i === index ? { ...x, h } : x))
}

export function remove(layout: DashboardWidget[], index: number): DashboardWidget[] {
  if (index < 0 || index >= layout.length) return layout
  return layout.filter((_, i) => i !== index).map((x, i) => ({ ...x, y: i }))
}

/** The spec ids already used in a layout (typed widgets only). */
export function takenIds(layout: DashboardWidget[]): Set<string> {
  const out = new Set<string>()
  for (const w of layout) {
    const id = (w.config as { id?: unknown } | undefined)?.id
    if (typeof id === 'string') out.add(id)
  }
  return out
}

/** A copy of a widget right after it, with a new spec id. */
export function duplicate(layout: DashboardWidget[], index: number): DashboardWidget[] {
  const w = layout[index]
  if (!w) return layout
  const copy: DashboardWidget = { ...w }
  if (w.config && typeof (w.config as { id?: unknown }).id === 'string') {
    const spec = structuredClone(w.config) as unknown as WidgetSpec
    spec.id = newWidgetId(takenIds(layout))
    copy.config = spec as unknown as Record<string, unknown>
  }
  const next = [...layout]
  next.splice(index + 1, 0, copy)
  return next.map((x, i) => ({ ...x, y: i }))
}

export function insert(
  layout: DashboardWidget[],
  widget: DashboardWidget,
  at = layout.length
): DashboardWidget[] {
  const next = [...layout]
  next.splice(Math.max(0, Math.min(layout.length, at)), 0, widget)
  return next.map((x, i) => ({ ...x, y: i }))
}

export function replaceAt(
  layout: DashboardWidget[],
  index: number,
  widget: DashboardWidget
): DashboardWidget[] {
  return layout.map((x, i) => (i === index ? widget : x))
}
