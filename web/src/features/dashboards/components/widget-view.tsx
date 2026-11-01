'use client'

/**
 * One typed widget: its frame (title, definition, freshness, state) and the
 * visualization the spec chose, drawn from the widget's stored result.
 */

import type { ReactNode } from 'react'
import {
  AreaLineViz,
  BarViz,
  BriefViz,
  CategoryTable,
  ColumnViz,
  DivergingViz,
  ExposureFlowViz,
  HeatmapViz,
  IntakeViz,
  ItemsTable,
  ItemsViz,
  KpiStripViz,
  LeversViz,
  LoopViz,
  MatrixTable,
  PathsTable,
  PathsViz,
  ProgressViz,
  StagesTable,
  StatViz,
  TimeSeriesTable,
  WidgetFrame,
  type CategoryResult,
  type DrillFn,
  type WidgetResult,
} from '@/components/dashboard-kit'
import { MarkdownPreview } from '@/components/ui/markdown-editor'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissionsSafe } from '@/context/permission-provider'
import { openFormHref } from '@/lib/open-form'
import { safeInternalHref } from '@/lib/safe-href'
import type { WidgetValue } from '../api/widget-data'
import type { VizType, WidgetSpec } from '../api/widget-spec'
import { reasonKeyOf, specOf, unitOf, widgetModel, type WidgetModel } from '../api/widget-adapter'
import {
  defaultWidgetTitle,
  kitPolarity,
  metricDefinitionKey,
  metricEmptyAction,
  metricNameKey,
  skeletonFor,
} from '../metrics'

/** The list a mark opens: a category row's own drill-down, else the widget's. */
function drillFor(v: WidgetValue | undefined, fallback?: string): DrillFn {
  // A matrix cell or a time bucket has its own total; the widget's generic
  // list has another, so these marks open nothing until per-mark lists exist.
  if (v?.shape === 'matrix' || v?.shape === 'time_series') return () => undefined
  return ({ key }) => {
    const row = key ? v?.category?.rows.find((r) => r.key === key) : undefined
    return safeInternalHref(row?.drill) ?? fallback
  }
}

/**
 * Why the rest of a share is missing (discovery coverage: the uncovered
 * assets by cause), each cause opening its own list. Drawn with the shared
 * bars, ordinal (the server's precedence order).
 */
function RatioCauses({ value }: { value: WidgetValue | undefined }): ReactNode {
  const { t } = useTranslation()
  const causes = value?.ratio?.causes
  if (!causes || causes.length === 0) return null
  const result: CategoryResult = {
    shape: 'category',
    rows: causes.map((c) => ({
      key: c.key,
      label_key: `dashboards.coverage.cause.${c.key.replace(/[^a-zA-Z0-9_]/g, '_')}`,
      label: c.key,
      value: c.value,
    })),
    total: causes.reduce((s, c) => s + c.value, 0),
    ordinal: true,
  }
  return (
    <div className="mt-3 flex flex-col gap-1.5">
      <p className="text-xs font-medium text-muted-foreground">
        {t('dashboards.coverage.causesTitle', 'Why assets are not covered')}
      </p>
      <BarViz
        result={result}
        drill={({ key }) => safeInternalHref(causes.find((c) => c.key === key)?.drill)}
      />
    </div>
  )
}

function Viz({
  model,
  value,
  viz,
  scope,
  filters,
}: {
  model: WidgetModel
  value: WidgetValue | undefined
  viz: VizType | undefined
  scope?: 'organization' | 'personal'
  /** The list's filters as words (the findings table's chip row). */
  filters?: string[]
}): ReactNode {
  const r: WidgetResult | undefined = model.result
  if (!r) return null
  const unit = unitOf(value)
  const polarity = kitPolarity(value?.polarity)
  const drill = drillFor(value, model.drill)
  const href = safeInternalHref(model.drill) ?? undefined
  switch (r.shape) {
    case 'scalar':
    case 'duration':
      return <StatViz result={r} unit={unit} polarity={polarity} href={href} />
    case 'ratio':
      return (
        <>
          {viz === 'stat' ? (
            <StatViz result={r} polarity={polarity} href={href} />
          ) : (
            <ProgressViz result={r} polarity={polarity} href={href} />
          )}
          <RatioCauses value={value} />
        </>
      )
    case 'category':
      if (viz === 'table') return <CategoryTable result={r} unit={unit} drill={drill} />
      // Part-to-whole ("donut" in the catalog) is drawn as one stacked bar: no radial encodings.
      return <BarViz result={r} unit={unit} drill={drill} stacked={viz === 'donut'} />
    case 'time_series':
      if (viz === 'table') return <TimeSeriesTable result={r} unit={unit} drill={drill} />
      if (viz === 'diverging') return <DivergingViz result={r} drill={drill} polarity={polarity} />
      if (viz === 'column')
        return <ColumnViz result={r} unit={unit} drill={drill} polarity={polarity} />
      return (
        <AreaLineViz
          result={r}
          unit={unit}
          drill={drill}
          polarity={polarity}
          mode={viz === 'line' ? 'line' : 'area'}
        />
      )
    case 'matrix':
      if (viz === 'table') return <MatrixTable result={r} drill={drill} />
      return <HeatmapViz result={r} drill={drill} />
    case 'items':
      if (viz === 'table')
        return <ItemsTable result={r} viewAllHref={model.drill} filters={filters} />
      return <ItemsViz result={r} viewAllHref={model.drill} />
    case 'stages':
      return viz === 'table' ? <StagesTable result={r} /> : <LoopViz result={r} />
    case 'paths':
      return viz === 'table' ? <PathsTable result={r} /> : <PathsViz result={r} href={href} />
    case 'flow':
      return <ExposureFlowViz result={r} scope={scope} />
    case 'intake':
      return <IntakeViz result={r} />
    case 'levers':
      return <LeversViz result={r} />
    case 'brief':
      return <BriefViz result={r} />
    case 'kpis':
      return <KpiStripViz result={r} />
    default:
      return null
  }
}

export interface WidgetViewProps {
  widget: { widget_type: string; config?: Record<string, unknown> }
  value: WidgetValue | undefined
  /** When the dashboard's figures were computed. */
  asOf?: string
  /** The dashboard's own time; a widget shows its time only when stale or different. */
  pageAsOf?: string
  stale?: boolean
  loading?: boolean
  onRetry?: () => void
  actions?: ReactNode
  className?: string
  /** Draws only the visualisation, without the bordered frame (for a host that already is a card). */
  bare?: boolean
  /** Whose numbers the dashboard shows (the exposure flow names it). */
  scope?: 'organization' | 'personal'
}

export function WidgetView({
  widget,
  value,
  asOf,
  pageAsOf,
  stale = false,
  loading = false,
  onRetry,
  actions,
  className,
  bare = false,
  scope,
}: WidgetViewProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissionsSafe()
  const spec: WidgetSpec | undefined = specOf(widget)
  const metric = spec?.data.metric ?? value?.metric
  const title =
    spec?.title?.trim() ||
    (spec?.data.kind === 'note'
      ? t('dashboards.widget.note', 'Note')
      : metric
        ? (defaultWidgetTitle(spec, t) ?? t(metricNameKey(metric), metric))
        : t('dashboards.widget.legacy', 'Earlier tile'))

  if (spec?.data.kind === 'note') {
    return (
      <WidgetFrame title={title} state="ready" actions={actions} className={className}>
        <MarkdownPreview content={spec.data.text ?? ''} className="text-sm" />
      </WidgetFrame>
    )
  }

  const model: WidgetModel = loading ? { state: 'loading' } : widgetModel(value, spec, stale)
  const reason = model.reasonKey ? t(model.reasonKey) : undefined
  // Only a truly empty figure (nothing in the period, or nothing has come
  // in yet) gets a next step; "still building" has none.
  const next =
    model.state === 'no_data_yet' && model.reasonKey !== reasonKeyOf('facts_building')
      ? metricEmptyAction(metric)
      : undefined
  const emptyAction =
    next && next.needs.every((p) => hasPermission(p))
      ? { label: t(next.labelKey, next.fallback), href: openFormHref(next.path, next.form) }
      : undefined
  // The filters the findings table's list carries (Fix next opens open P0 to P2).
  const filters =
    metric === 'fix.next'
      ? [
          t('dashboards.table.filterOpen', 'Open'),
          t('dashboards.table.filterPriority', 'Priority P0–P2'),
        ]
      : undefined
  const count =
    model.state === 'ready' && model.viz === 'table' && model.result?.shape === 'items'
      ? model.result.total
      : undefined
  if (bare)
    return <Viz model={model} value={value} viz={model.viz} scope={scope} filters={filters} />
  return (
    <WidgetFrame
      title={title}
      definition={metric ? t(metricDefinitionKey(metric), '') || undefined : undefined}
      asOf={model.state === 'loading' ? null : asOf}
      pageAsOf={pageAsOf}
      state={model.state}
      skeleton={skeletonFor(value?.shape)}
      notMeasuredReason={reason}
      emptyMessage={reason}
      emptyAction={emptyAction}
      count={count}
      onRetry={model.state === 'error' ? onRetry : undefined}
      actions={actions}
      className={className}
    >
      <Viz model={model} value={value} viz={model.viz} scope={scope} filters={filters} />
    </WidgetFrame>
  )
}
