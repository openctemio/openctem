'use client'

/**
 * One typed widget: its frame (title, definition, freshness, state) and the
 * visualization the spec chose, drawn from the widget's stored result.
 */

import type { ReactNode } from 'react'
import {
  AreaLineViz,
  BarViz,
  CategoryTable,
  ColumnViz,
  DivergingViz,
  HeatmapViz,
  ItemsViz,
  LoopViz,
  MatrixTable,
  PathsTable,
  PathsViz,
  ProgressViz,
  StagesTable,
  StatViz,
  TimeSeriesTable,
  WidgetFrame,
  type DrillFn,
  type WidgetResult,
} from '@/components/dashboard-kit'
import { MarkdownPreview } from '@/components/ui/markdown-editor'
import { useTranslation } from '@/context/i18n-provider'
import { safeInternalHref } from '@/lib/safe-href'
import type { WidgetValue } from '../api/widget-data'
import type { VizType, WidgetSpec } from '../api/widget-spec'
import { specOf, unitOf, widgetModel, type WidgetModel } from '../api/widget-adapter'
import { kitPolarity, metricDefinitionKey, metricNameKey, skeletonFor } from '../metrics'

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

function Viz({
  model,
  value,
  viz,
}: {
  model: WidgetModel
  value: WidgetValue | undefined
  viz: VizType | undefined
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
      return viz === 'stat' ? (
        <StatViz result={r} polarity={polarity} href={href} />
      ) : (
        <ProgressViz result={r} polarity={polarity} href={href} />
      )
    case 'category':
      if (viz === 'table') return <CategoryTable result={r} unit={unit} drill={drill} />
      return <BarViz result={r} unit={unit} drill={drill} />
    case 'time_series':
      if (viz === 'table') return <TimeSeriesTable result={r} unit={unit} drill={drill} />
      if (viz === 'diverging') return <DivergingViz result={r} drill={drill} />
      if (viz === 'column') return <ColumnViz result={r} unit={unit} drill={drill} />
      return (
        <AreaLineViz result={r} unit={unit} drill={drill} mode={viz === 'line' ? 'line' : 'area'} />
      )
    case 'matrix':
      if (viz === 'table') return <MatrixTable result={r} drill={drill} />
      return <HeatmapViz result={r} drill={drill} />
    case 'items':
      return <ItemsViz result={r} viewAllHref={model.drill} />
    case 'stages':
      return viz === 'table' ? <StagesTable result={r} /> : <LoopViz result={r} />
    case 'paths':
      return viz === 'table' ? <PathsTable result={r} /> : <PathsViz result={r} href={href} />
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
}: WidgetViewProps) {
  const { t } = useTranslation()
  const spec: WidgetSpec | undefined = specOf(widget)
  const metric = spec?.data.metric ?? value?.metric
  const title =
    spec?.title?.trim() ||
    (spec?.data.kind === 'note'
      ? t('dashboards.widget.note', 'Note')
      : metric
        ? t(metricNameKey(metric), metric)
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
  if (bare) return <Viz model={model} value={value} viz={model.viz} />
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
      onRetry={model.state === 'error' ? onRetry : undefined}
      actions={actions}
      className={className}
    >
      <Viz model={model} value={value} viz={model.viz} />
    </WidgetFrame>
  )
}
