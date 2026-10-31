/**
 * Building and changing widget specs in the gallery and the config panel.
 * Every change keeps the spec inside what the server accepts: the
 * visualization stays when it still fits the shape, otherwise the shape's
 * default; lists take no time range, comparison or target.
 */

import type { DashboardWidget } from '../api/dashboards.types'
import {
  WIDGET_SPEC_VERSION,
  keepOrDefaultViz,
  newWidgetId,
  shapeFor,
  vizzesFor,
  type CatalogMetric,
  type Dimension,
  type ResultShape,
  type VizType,
  type WidgetFilter,
  type WidgetSpec,
} from '../api/widget-spec'

export const NOTE_MAX_LENGTH = 2000
export const TITLE_MAX_LENGTH = 120

/** Default size of a new widget by result shape (12-unit width, rows). */
export function defaultSize(shape: ResultShape | undefined): { w: number; h: number } {
  switch (shape) {
    case 'scalar':
    case 'ratio':
    case 'duration':
      return { w: 3, h: 1 }
    case 'items':
      return { w: 6, h: 3 }
    // Story widgets read across the whole row (three levers, five figures,
    // the flow diagram, intake per source); at half width they are cramped.
    case 'kpis':
    case 'levers':
      return { w: 12, h: 1 }
    case 'flow':
      return { w: 12, h: 4 }
    case 'intake':
      return { w: 12, h: 3 }
    default:
      return { w: 6, h: 2 }
  }
}

export function newMetricSpec(metric: CatalogMetric, taken: ReadonlySet<string>): WidgetSpec {
  return {
    v: WIDGET_SPEC_VERSION,
    id: newWidgetId(taken),
    data: { kind: 'metric', metric: metric.id, filter: {}, time: {} },
    viz: { type: vizzesFor(metric, 0)[0] ?? 'stat', options: {} },
  }
}

export function newNoteSpec(text: string, taken: ReadonlySet<string>): WidgetSpec {
  return {
    v: WIDGET_SPEC_VERSION,
    id: newWidgetId(taken),
    data: { kind: 'note', filter: {}, time: {}, text },
    viz: { type: 'note', options: {} },
  }
}

export function widgetFromSpec(spec: WidgetSpec, shape: ResultShape | undefined): DashboardWidget {
  const size = defaultSize(spec.data.kind === 'note' ? 'scalar' : shape)
  return {
    widget_type: spec.data.kind,
    x: 0,
    y: 0,
    ...size,
    config: spec as unknown as Record<string, unknown>,
  }
}

/** The result shape of a spec under its metric. */
export function specShape(
  spec: WidgetSpec,
  metric: CatalogMetric | undefined
): ResultShape | undefined {
  if (!metric) return undefined
  return shapeFor(metric, spec.data.group_by?.length ?? 0)
}

/** Switches the metric: filters and group-by the new metric cannot take are dropped. */
export function withMetric(spec: WidgetSpec, metric: CatalogMetric): WidgetSpec {
  const filter: WidgetFilter = {}
  for (const [k, v] of Object.entries(spec.data.filter ?? {})) {
    const dim = (k === 'asset_group_id' ? 'asset_group' : k) as Dimension
    if (metric.filters.includes(dim)) (filter as Record<string, unknown>)[k] = v
  }
  const groupBy = (spec.data.group_by ?? [])
    .filter((d) => metric.group_bys.includes(d))
    .slice(0, metric.max_group_by)
  const next: WidgetSpec = {
    ...spec,
    data: {
      ...spec.data,
      metric: metric.id,
      filter,
      group_by: groupBy.length ? groupBy : undefined,
    },
    viz: { ...spec.viz, type: keepOrDefaultViz(metric, groupBy.length, spec.viz.type) },
  }
  return normalizeForShape(next, metric)
}

export function withGroupBy(
  spec: WidgetSpec,
  metric: CatalogMetric,
  groupBy: Dimension[]
): WidgetSpec {
  const gb = groupBy.filter((d) => metric.group_bys.includes(d)).slice(0, metric.max_group_by)
  const next: WidgetSpec = {
    ...spec,
    data: { ...spec.data, group_by: gb.length ? gb : undefined },
    viz: { ...spec.viz, type: keepOrDefaultViz(metric, gb.length, spec.viz.type) },
  }
  return normalizeForShape(next, metric)
}

export function withViz(spec: WidgetSpec, metric: CatalogMetric, viz: VizType): WidgetSpec {
  const valid = vizzesFor(metric, spec.data.group_by?.length ?? 0)
  if (!valid.includes(viz)) return spec
  return { ...spec, viz: { ...spec.viz, type: viz } }
}

/** Sets or clears one filter dimension (empty list or undefined clears it). */
export function withFilter(
  spec: WidgetSpec,
  key: keyof WidgetFilter,
  value: string[] | boolean | undefined
): WidgetSpec {
  const filter = { ...spec.data.filter } as Record<string, unknown>
  if (value === undefined || (Array.isArray(value) && value.length === 0)) delete filter[key]
  else filter[key] = value
  return { ...spec, data: { ...spec.data, filter: filter as WidgetFilter } }
}

/** Lists take no time window, comparison or target; only single figures take a target. */
function normalizeForShape(spec: WidgetSpec, metric: CatalogMetric): WidgetSpec {
  const shape = specShape(spec, metric)
  let next = spec
  if (shape === 'items') next = { ...next, data: { ...next.data, time: {} } }
  if (shape !== 'scalar' && shape !== 'ratio' && shape !== 'duration' && next.target) {
    next = { ...next }
    delete next.target
  }
  return next
}

/** True when the spec can take a target (single figures only). */
export function takesTarget(spec: WidgetSpec, metric: CatalogMetric | undefined): boolean {
  const s = specShape(spec, metric)
  return s === 'scalar' || s === 'ratio' || s === 'duration'
}

/** True when the spec reads a time window and comparison (everything but lists). */
export function takesTime(spec: WidgetSpec, metric: CatalogMetric | undefined): boolean {
  return specShape(spec, metric) !== 'items'
}
