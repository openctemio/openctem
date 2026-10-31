/**
 * Turns one widget result of the data endpoint (WidgetValue) into what the
 * dashboard kit draws: a frame state and, when there are figures, a result
 * shape. Null and missing figures stay "not measured", never 0.
 */

import type {
  CategoryResult,
  DurationResult,
  FlowFigure as KitFigure,
  FlowResult,
  IntakeData,
  IntakeResult,
  IntakeSourceRow,
  ItemsResult,
  MatrixResult,
  PathsResult,
  RatioResult,
  ScalarResult,
  StageState,
  StagesResult,
  TimeSeriesResult,
  WidgetResult,
  BriefResult,
  KpisResult,
  LeverRow,
  LeversResult,
  WidgetState as KitState,
} from '@/components/dashboard-kit'
import { safeInternalHref } from '@/lib/safe-href'
import {
  dimensionValueKey,
  groupByOf,
  kitPolarity,
  metricMeta,
  ORDINAL_DIMENSIONS,
} from '../metrics'
import type { FlowFigure, IntakeSource, IntakeValue, LeverValue, WidgetValue } from './widget-data'
import type { Dimension, VizType, WidgetSpec } from './widget-spec'

export interface WidgetModel {
  state: KitState
  /** Message key (in `dashboards`) of the reason a widget has no figures. */
  reasonKey?: string
  result?: WidgetResult
  viz?: VizType
  /** Same-origin list the figure counts (absent when the list cannot express it). */
  drill?: string
}

/** Message key of a server reason code (not measured, building, unsupported, failed). */
export function reasonKeyOf(reason: string | undefined): string {
  switch (reason) {
    case 'no_denominator':
    case 'no_crown_jewels':
    case 'no_tracked_assets':
    case 'no_relationship_data':
    case 'too_few_fixed':
    case 'legacy_tile':
    case 'forbidden':
    case 'facts_building':
    case 'timeout':
    case 'empty':
    case 'pending':
    case 'organization_only':
    case 'no_receipts':
    case 'no_certificates':
    case 'no_closures':
    case 'no_active_campaigns':
    case 'too_few_closed':
      return `dashboards.reason.${reason}`
    default:
      return 'dashboards.reason.failed'
  }
}

function figure(f: FlowFigure | undefined): KitFigure {
  return { key: f?.key, value: f?.value ?? 0, drill: safeInternalHref(f?.drill) ?? null }
}

function leverRow(l: LeverValue): LeverRow {
  return {
    kind: l.kind,
    count: l.count,
    assets: l.assets,
    title: l.title,
    effect: l.effect,
    href: safeInternalHref(l.drill) ?? null,
  }
}

function sourceRow(s: IntakeSource): IntakeSourceRow {
  return {
    id: `${s.origin}:${s.tool}`,
    origin: s.origin,
    tool: s.tool,
    receipts: s.receipts,
    received: s.received,
    created: s.created,
    still_detected: s.still_detected,
    reopened: s.reopened,
    closed: s.closed,
    suppressed: s.suppressed,
    not_stored: s.not_stored,
    last_at: s.last_at && !s.last_at.startsWith('0001-') ? s.last_at : null,
    last_status: s.last_status,
    health: s.health === 'stale' || s.health === 'failed' ? s.health : 'ok',
    expected_every_seconds: s.expected_every_seconds ?? null,
    drill: safeInternalHref(s.drill) ?? null,
  }
}

function intakeData(v: IntakeValue, days: number): IntakeData {
  return {
    since: v.since,
    days,
    sources: v.sources.map(sourceRow),
    totals: sourceRow(v.totals),
    noise: v.noise,
    failing: v.failing,
    stale: v.stale,
    drill: safeInternalHref(v.drill) ?? null,
    false_positive: figure(v.false_positive),
  }
}

function stagesResult(st: NonNullable<WidgetValue['stages']>): StagesResult {
  return {
    shape: 'stages',
    focus: st.focus,
    stages: st.stages.map((s) => ({
      key: s.key,
      label_key: `dashboards.loop.stage.${s.key}`,
      label: s.key,
      value: s.value,
      unit: s.unit,
      state: stageState(s.state),
      drill: safeInternalHref(s.drill) ?? null,
      reason_key: s.reason ? `dashboards.loop.reason.${s.reason}` : undefined,
      flag_key: s.flag ? `dashboards.loop.flag.${s.flag}` : undefined,
      detail: s.detail
        ? {
            label_key: `dashboards.loop.detail.${s.detail.key}`,
            value: s.detail.value,
            drill: safeInternalHref(s.detail.drill) ?? null,
          }
        : undefined,
    })),
  }
}

function seriesLabel(dim: Dimension | undefined, key: string) {
  return { key, label_key: dimensionValueKey(dim, key), label: key }
}

function toResult(v: WidgetValue, spec: WidgetSpec | undefined): WidgetResult | undefined {
  const groupBy = groupByOf(spec)
  switch (v.shape) {
    case 'scalar': {
      if (!v.scalar) return undefined
      const out: ScalarResult = {
        shape: 'scalar',
        value: v.scalar.value,
        previous: v.scalar.previous ?? null,
        delta: v.scalar.delta ?? null,
        series: v.scalar.series,
        target: v.target ? { op: v.target.op, value: v.target.value, source: 'widget' } : null,
      }
      return out
    }
    case 'ratio': {
      if (!v.ratio) return undefined
      const out: RatioResult = {
        shape: 'ratio',
        num: v.ratio.num,
        den: v.ratio.den,
        value_pct: v.ratio.value_pct,
        target: v.target ? { op: v.target.op, value: v.target.value, source: 'widget' } : null,
      }
      return out
    }
    case 'duration': {
      if (!v.duration) return undefined
      const out: DurationResult = {
        shape: 'duration',
        median: v.duration.median_hours,
        p90: v.duration.p90_hours,
        n: v.duration.n,
        previous_median: v.duration.previous_median_hours ?? null,
        target: v.target ? { op: v.target.op, value: v.target.value, source: 'widget' } : null,
      }
      return out
    }
    case 'category': {
      // A duration grouped by one dimension also arrives as category rows.
      const c = v.category
      if (!c) return undefined
      const dim = groupBy[0]
      // A breakdown (no group-by) names its keys with its own prefix.
      const meta = dim ? undefined : metricMeta(v.metric)
      const out: CategoryResult = {
        shape: 'category',
        rows: c.rows.map((r) => ({
          key: r.key,
          // A server-given label (a campaign name) is shown as is.
          label_key: r.label
            ? undefined
            : meta?.keyPrefix
              ? `${meta.keyPrefix}.${r.key.replace(/[^a-zA-Z0-9_]/g, '_')}`
              : dimensionValueKey(dim, r.key),
          label: r.label || r.key,
          value: r.value,
          previous: r.previous ?? null,
        })),
        total: c.total,
        ordinal: dim ? ORDINAL_DIMENSIONS.has(dim) : (meta?.ordinal ?? false),
      }
      return out
    }
    case 'time_series': {
      const s = v.series
      if (!s) return undefined
      const flow = v.metric === 'flow.new_vs_fixed'
      const dim = flow ? undefined : groupBy[0]
      const out: TimeSeriesResult = {
        shape: 'time_series',
        bucket: s.bucket === 'week' || s.bucket === 'month' ? s.bucket : 'day',
        kind: flow ? 'flow' : 'stock',
        series: s.series.map((line) => ({
          ...(flow
            ? { key: line.key, label_key: `dashboards.flow.${line.key}`, label: line.key }
            : seriesLabel(dim, line.key)),
          points: line.points,
        })),
      }
      return out
    }
    case 'matrix': {
      const m = v.matrix
      if (!m) return undefined
      const [rowDim, colDim] = groupBy
      const out: MatrixResult = {
        shape: 'matrix',
        rows: m.rows.map((k) => seriesLabel(rowDim, k)),
        cols: m.cols.map((k) => seriesLabel(colDim, k)),
        cells: m.cells,
      }
      return out
    }
    case 'items': {
      const it = v.items
      if (!it) return undefined
      const out: ItemsResult = {
        shape: 'items',
        rows: it.rows.map((r) => ({
          id: r.id,
          // A finding stored without a title arrives as null or empty; the
          // list shows a named placeholder instead of a blank row.
          title: r.title ?? '',
          priority: r.priority_class || null,
          severity: r.severity || null,
          asset: r.asset_name ?? null,
          due_at: r.sla_deadline ?? null,
          kev: r.kev,
          epss: typeof r.epss === 'number' ? r.epss : null,
          href: `/findings/${encodeURIComponent(r.id)}`,
        })),
        total: typeof it.total === 'number' ? it.total : null,
      }
      return out
    }
    case 'stages':
      return v.stages ? stagesResult(v.stages) : undefined
    case 'paths': {
      const p = v.paths
      if (!p) return undefined
      const out: PathsResult = {
        shape: 'paths',
        reachable: p.reachable,
        designated: p.designated,
        rows: p.rows.map((r) => ({
          id: r.asset_id,
          name: r.name,
          kind: r.asset_type || null,
          criticality: r.criticality || null,
          reachable_from: r.reachable_from,
          entry_point: r.entry_point,
          score: r.score,
          href: `/assets/${encodeURIComponent(r.asset_id)}`,
        })),
      }
      return out
    }
    case 'flow': {
      const f = v.flow
      if (!f) return undefined
      const out: FlowResult = {
        shape: 'flow',
        since: f.since,
        days: v.window?.days ?? 30,
        intake: f.intake ? intakeData(f.intake, v.window?.days ?? 30) : null,
        intake_reason_key: f.intake_reason ? `dashboards.reason.${f.intake_reason}` : undefined,
        actionable: figure(f.actionable),
        classes: (f.classes ?? []).map(figure),
        open: figure(f.open),
        severity: (f.severity ?? []).map(figure),
        past_sla: figure(f.past_sla),
        in_progress: figure(f.in_progress),
        fixed: figure(f.fixed),
        accepted: figure(f.accepted),
        false_positive: figure(f.false_positive),
        stages: f.stages ? stagesResult(f.stages) : null,
      }
      return out
    }
    case 'intake': {
      if (!v.intake) return undefined
      const out: IntakeResult = {
        shape: 'intake',
        intake: intakeData(v.intake, v.window?.days ?? 30),
      }
      return out
    }
    case 'levers': {
      if (!v.levers) return undefined
      const out: LeversResult = { shape: 'levers', levers: (v.levers.levers ?? []).map(leverRow) }
      return out
    }
    case 'brief': {
      if (!v.brief) return undefined
      const out: BriefResult = {
        shape: 'brief',
        since: v.brief.since,
        items: (v.brief.items ?? []).map((it) => ({
          kind: it.kind,
          variant: it.variant,
          chips: (it.chips ?? []).map((c) => ({
            key: c.key,
            value: c.value,
            href: safeInternalHref(c.drill) ?? null,
          })),
          lever: it.lever ? leverRow(it.lever) : undefined,
        })),
      }
      return out
    }
    case 'kpis': {
      if (!v.kpis) return undefined
      const out: KpisResult = {
        shape: 'kpis',
        tiles: (v.kpis.tiles ?? []).map((k) => ({
          key: k.key,
          metric: k.metric,
          measured: k.state === 'ready' && k.value != null,
          reason_key: k.state === 'ready' ? undefined : reasonKeyOf(k.reason),
          value: k.value,
          previous: k.previous ?? null,
          unit: k.unit,
          polarity: kitPolarity(k.polarity),
          href: safeInternalHref(k.drill) ?? null,
        })),
      }
      return out
    }
    default:
      return undefined
  }
}

function stageState(s: string): StageState {
  return s === 'good' || s === 'warn' || s === 'crit' ? s : 'unmeasured'
}

/** True when a ready result has nothing to draw (no findings yet for this widget). */
function isEmpty(r: WidgetResult): boolean {
  switch (r.shape) {
    case 'category':
      return r.rows.length === 0
    case 'items':
      return r.rows.length === 0
    case 'matrix':
      return r.rows.length === 0 || r.cols.length === 0
    case 'time_series':
      return r.series.length === 0
    default:
      return false
  }
}

/**
 * The frame state and figures of one widget. `stale` is the dashboard's
 * freshness (the snapshot is older than twice its schedule, or its last
 * refresh failed): the last good figures stay, marked stale.
 */
export function widgetModel(
  v: WidgetValue | undefined,
  spec: WidgetSpec | undefined,
  stale: boolean
): WidgetModel {
  if (!v) return { state: 'loading' }
  const viz = v.viz ?? spec?.viz.type
  const drill = safeInternalHref(v.drill) ?? undefined
  switch (v.state) {
    case 'building':
      return { state: 'no_data_yet', reasonKey: reasonKeyOf(v.reason ?? 'facts_building') }
    case 'not_measured':
      return {
        state: 'not_measured',
        reasonKey: reasonKeyOf(v.reason),
        result: toResult(v, spec),
        viz,
        drill,
      }
    case 'unsupported':
      return { state: 'not_measured', reasonKey: reasonKeyOf(v.reason) }
    case 'ready': {
      const result = toResult(v, spec)
      if (!result) return { state: 'error', reasonKey: reasonKeyOf('failed') }
      if (isEmpty(result))
        return { state: 'no_data_yet', reasonKey: 'dashboards.reason.empty', viz, drill }
      return { state: stale ? 'stale' : 'ready', result, viz, drill }
    }
    default:
      return { state: 'error', reasonKey: reasonKeyOf(v.reason) }
  }
}

/** The widget spec of a typed layout entry (undefined for a legacy tile). */
export function specOf(widget: { widget_type: string; config?: Record<string, unknown> }) {
  if (widget.widget_type !== 'metric' && widget.widget_type !== 'note') return undefined
  const c = widget.config as unknown as WidgetSpec | undefined
  return c && typeof c === 'object' && c.data ? c : undefined
}

/** The unit of a widget's main figure. */
export function unitOf(v: WidgetValue | undefined) {
  if (v?.shape === 'ratio') return 'percent' as const
  if (v?.shape === 'duration') return 'hours' as const
  return metricMeta(v?.metric)?.unit ?? 'count'
}
