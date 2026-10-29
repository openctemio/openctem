/**
 * What the web knows about each catalog metric (api docs/architecture/dashboards.md,
 * "Widget spec"): its name and definition (message keys in the `dashboards`
 * namespace), the unit of its figure, the skeleton it loads with, and the
 * group-by the server applies when a widget names none. The server catalog
 * stays the authority on filters, group-bys and visualizations.
 */

import type { MetricUnit } from '@/lib/format-metric'
import type { Polarity as KitPolarity, SkeletonKind } from '@/components/dashboard-kit'
import type { Dimension, Polarity, ResultShape, WidgetSpec } from './api/widget-spec'

export type MetricGroup = 'ctem' | 'exposure' | 'remediation' | 'threat_intel'

export interface MetricMeta {
  id: string
  group: MetricGroup
  unit: MetricUnit
  /** Group-by the server applies when the widget names none. */
  defaultGroupBy: Dimension[]
}

/** Every catalog metric, in gallery order. A test checks this against the server catalog. */
export const METRICS: readonly MetricMeta[] = [
  { id: 'findings.open', group: 'exposure', unit: 'count', defaultGroupBy: [] },
  { id: 'exposure.priority_open', group: 'exposure', unit: 'count', defaultGroupBy: [] },
  {
    id: 'exposure.open_by_priority',
    group: 'exposure',
    unit: 'count',
    defaultGroupBy: ['priority_class'],
  },
  { id: 'fix.next', group: 'exposure', unit: 'count', defaultGroupBy: [] },
  { id: 'intel.kev_open', group: 'threat_intel', unit: 'count', defaultGroupBy: [] },
  {
    id: 'findings.age_bands',
    group: 'remediation',
    unit: 'count',
    defaultGroupBy: ['severity', 'age_band'],
  },
  { id: 'sla.within', group: 'remediation', unit: 'percent', defaultGroupBy: [] },
  { id: 'fix.time_to_fix', group: 'remediation', unit: 'hours', defaultGroupBy: [] },
  { id: 'flow.new_vs_fixed', group: 'remediation', unit: 'count', defaultGroupBy: [] },
  { id: 'sla.at_risk', group: 'remediation', unit: 'count', defaultGroupBy: [] },
  { id: 'crown_jewels.exposed', group: 'ctem', unit: 'count', defaultGroupBy: [] },
  { id: 'coverage.discovery', group: 'ctem', unit: 'percent', defaultGroupBy: [] },
  { id: 'ctem.loop', group: 'ctem', unit: 'count', defaultGroupBy: [] },
  { id: 'attack_paths.to_crown_jewels', group: 'ctem', unit: 'count', defaultGroupBy: [] },
  { id: 'exposure.flow', group: 'ctem', unit: 'count', defaultGroupBy: [] },
  { id: 'ingest.intake', group: 'ctem', unit: 'count', defaultGroupBy: [] },
]

export const METRIC_GROUPS: readonly MetricGroup[] = [
  'ctem',
  'exposure',
  'remediation',
  'threat_intel',
]

const BY_ID = new Map(METRICS.map((m) => [m.id, m]))

export function metricMeta(id: string | undefined): MetricMeta | undefined {
  return id ? BY_ID.get(id) : undefined
}

/** Message key of a metric's name ("dashboards.metric.findings_open.name"). */
export function metricNameKey(id: string): string {
  return `dashboards.metric.${id.replace(/\./g, '_')}.name`
}

/** Message key of a metric's plain-words definition. */
export function metricDefinitionKey(id: string): string {
  return `dashboards.metric.${id.replace(/\./g, '_')}.definition`
}

/** Message key of a dimension's name. */
export function dimensionNameKey(dim: Dimension): string {
  return `dashboards.dimension.${dim}.name`
}

/**
 * Message key of one value of a dimension ("critical", "P0", "0-30",
 * "breached", "true"). Unknown values fall back to the raw value.
 */
export function dimensionValueKey(dim: Dimension | undefined, value: string): string {
  return `dashboards.dimension.${dim ?? 'value'}.values.${value.replace(/[^a-zA-Z0-9_]/g, '_')}`
}

/** Dimensions whose values have a natural order (keep it, never sort by size). */
export const ORDINAL_DIMENSIONS: ReadonlySet<Dimension> = new Set([
  'severity',
  'priority_class',
  'age_band',
  'sla_state',
])

/** The group-by of a widget: its own, or the metric's default. */
export function groupByOf(spec: Pick<WidgetSpec, 'data'> | undefined): Dimension[] {
  const own = spec?.data.group_by
  if (own && own.length > 0) return own
  return metricMeta(spec?.data.metric)?.defaultGroupBy ?? []
}

/** The kit's polarity for a catalog polarity. */
export function kitPolarity(p: Polarity | undefined): KitPolarity {
  switch (p) {
    case 'lower_better':
      return 'down_good'
    case 'higher_better':
      return 'up_good'
    default:
      return 'neutral'
  }
}

/** The skeleton a widget of this shape loads with. */
export function skeletonFor(shape: ResultShape | undefined): SkeletonKind {
  switch (shape) {
    case 'scalar':
    case 'ratio':
    case 'duration':
      return 'stat'
    case 'items':
    case 'paths':
      return 'list'
    case 'stages':
      return 'stages'
    case 'flow':
    case 'intake':
      return 'chart'
    case 'matrix':
      return 'grid'
    default:
      return 'chart'
  }
}

/**
 * The next step for a metric that has nothing to show yet: the figures come
 * from findings (bring some in) or from scan coverage (run a scan). The form
 * is opened on its own page, behind that page's permission, so the action is
 * offered only to a caller who may use it (`needs`). Metrics with no fitting
 * step (a note, an unknown metric) return undefined: no dead link.
 */
export interface MetricEmptyAction {
  labelKey: string
  fallback: string
  form: 'import' | 'scan'
  path: string
  needs: readonly string[]
}

const IMPORT_ACTION: MetricEmptyAction = {
  labelKey: 'dashboards.empty.import',
  fallback: 'Import results',
  form: 'import',
  path: '/findings',
  needs: ['findings:write', 'assets:write', 'assets:import'],
}
const SCAN_ACTION: MetricEmptyAction = {
  labelKey: 'dashboards.empty.scan',
  fallback: 'Set up a scan',
  form: 'scan',
  path: '/scans',
  needs: ['scans:write'],
}
const SCAN_METRICS = new Set(['coverage.discovery', 'attack_paths.to_crown_jewels'])

export function metricEmptyAction(id: string | undefined): MetricEmptyAction | undefined {
  const meta = metricMeta(id)
  if (!meta) return undefined
  return SCAN_METRICS.has(meta.id) ? SCAN_ACTION : IMPORT_ACTION
}
