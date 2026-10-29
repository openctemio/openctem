/**
 * Typed dashboard widgets (api docs/architecture/dashboards.md, "Widget spec").
 *
 * A typed widget is `widget_type: 'metric' | 'note'` with a `config` that is a
 * WidgetSpec: a metric from the catalog (GET /api/v1/me/dashboards/widget-catalog),
 * a filter and group-by on fact dimensions, a time window, and how to draw it.
 * The server validates every spec strictly and stores the normalized form;
 * these types and helpers only build specs the server will accept.
 */

'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { DashboardWidget } from './dashboards.types'

export const WIDGET_SPEC_VERSION = 2

export type WidgetKind = 'metric' | 'note'
export type ResultShape =
  | 'scalar'
  | 'ratio'
  | 'duration'
  | 'category'
  | 'time_series'
  | 'matrix'
  | 'items'
  | 'stages'
  | 'paths'
  | 'flow'
  | 'intake'
  | 'levers'
  | 'brief'
  | 'kpis'
export type VizType =
  | 'stat'
  | 'progress'
  | 'bar'
  | 'column'
  | 'area'
  | 'line'
  | 'diverging'
  | 'table'
  | 'heatmap'
  | 'list'
  | 'donut'
  | 'note'
  | 'loop'
  | 'paths'
  | 'flow'
  | 'intake'
  | 'levers'
  | 'brief'
  | 'kpi'
export type Dimension =
  | 'severity'
  | 'priority_class'
  | 'source'
  | 'sla_state'
  | 'age_band'
  | 'kev'
  | 'reachable'
  | 'asset_group'
export type Polarity = 'lower_better' | 'higher_better' | 'neutral'

export interface WidgetFilter {
  severity?: string[]
  priority_class?: string[]
  source?: string[]
  sla_state?: string[]
  age_band?: string[]
  kev?: boolean
  reachable?: boolean
  asset_group_id?: string[]
}

export interface WidgetSpec {
  v: typeof WIDGET_SPEC_VERSION
  id: string
  title?: string
  data: {
    kind: WidgetKind
    metric?: string
    filter: WidgetFilter
    group_by?: Dimension[]
    time: { range?: string; bucket?: string; compare?: string }
    limit?: number
    text?: string
  }
  viz: {
    type: VizType
    options: {
      orientation?: 'horizontal' | 'vertical'
      stacked?: boolean
      show_table?: boolean
      sparkline?: boolean
    }
  }
  target?: { op: '<=' | '>='; value: number }
  drill?: 'auto' | 'none'
  pin_filters?: boolean
}

export interface CatalogMetric {
  id: string
  group: string
  filters: Dimension[]
  group_bys: Dimension[]
  max_group_by: number
  default_group_by: Dimension[]
  default_filter: WidgetFilter
  polarity: Polarity
  timed: boolean
  flow: boolean
  /** Group-by count ("0", "1", "2") → result shape and valid visualizations, default first. */
  shapes: Record<string, { shape: ResultShape; vizzes: VizType[] }>
}

export interface WidgetCatalog {
  spec_version: number
  metrics: CatalogMetric[]
  dimensions: Partial<Record<Dimension, string[]>>
  time_ranges: string[]
  time_buckets: string[]
  comparisons: string[]
  target_ops: string[]
}

export const WIDGET_CATALOG_KEY = '/api/v1/me/dashboards/widget-catalog'

/** The typed widget catalog (static per release; cached for the session). */
export function useWidgetCatalog() {
  const { currentTenant } = useTenant()
  return useSWR<WidgetCatalog>(
    currentTenant ? WIDGET_CATALOG_KEY : null,
    (url: string) => get<WidgetCatalog>(url),
    { revalidateOnFocus: false, dedupingInterval: 60 * 60 * 1000 }
  )
}

/** True for a widget the server validates as a spec (not a legacy tile id). */
export function isTypedWidget(w: Pick<DashboardWidget, 'widget_type'>): boolean {
  return w.widget_type === 'metric' || w.widget_type === 'note'
}

/** A widget id unique within a dashboard, in the form the server accepts. */
export function newWidgetId(taken: ReadonlySet<string> = new Set()): string {
  for (;;) {
    const id = `w_${Math.random().toString(36).slice(2, 10)}`
    if (/^w_[a-z0-9]{1,16}$/.test(id) && !taken.has(id)) return id
  }
}

/** The visualizations valid for a metric with `groupBy` dimensions, default first. */
export function vizzesFor(metric: CatalogMetric, groupByCount: number): VizType[] {
  return metric.shapes[String(groupByCount)]?.vizzes ?? []
}

/** The result shape of a metric with `groupBy` dimensions. */
export function shapeFor(metric: CatalogMetric, groupByCount: number): ResultShape | undefined {
  return metric.shapes[String(groupByCount)]?.shape
}

/**
 * Keeps the chosen visualization when it still fits after a group-by change,
 * otherwise falls back to the default for the new shape.
 */
export function keepOrDefaultViz(
  metric: CatalogMetric,
  groupByCount: number,
  current: VizType
): VizType {
  const valid = vizzesFor(metric, groupByCount)
  return valid.includes(current) ? current : (valid[0] ?? current)
}

/** A new metric widget with the metric's defaults, placed at (x, y). */
export function newMetricWidget(
  metric: CatalogMetric,
  at: { x: number; y: number; w: number; h: number },
  taken?: ReadonlySet<string>
): DashboardWidget {
  const spec: WidgetSpec = {
    v: WIDGET_SPEC_VERSION,
    id: newWidgetId(taken),
    data: { kind: 'metric', metric: metric.id, filter: {}, time: {} },
    viz: { type: vizzesFor(metric, 0)[0] ?? 'stat', options: {} },
  }
  return { widget_type: 'metric', ...at, config: spec as unknown as Record<string, unknown> }
}
