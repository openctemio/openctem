'use client'

/**
 * The one dashboard renderer: every widget of a layout, laid out in the
 * dashboard's columns, drawn from the dashboard's stored snapshot. Each
 * widget has its own error boundary, so one bad result never blanks the page.
 */

import { WidgetErrorBoundary, WidgetFrame } from '@/components/dashboard-kit'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { Dashboard, DashboardWidget } from '../api/dashboards.types'
import type { DashboardData, WidgetValue } from '../api/widget-data'
import {
  ROW_HEIGHT,
  colSpanFor,
  columnsClass,
  gridColumnSpan,
  phoneSpan,
  widgetSpanClass,
  normalizeColumns,
  widgetRowSpan,
} from '../layout'
import { specOf, widgetModel } from '../api/widget-adapter'
import { WidgetView } from './widget-view'

export interface DashboardViewProps {
  dashboard: Pick<Dashboard, 'layout' | 'columns'>
  data: DashboardData | undefined
  loading: boolean
  /** The data request failed (every widget shows the error with Retry). */
  failed?: boolean
  onRetry?: () => void
}

/** The result of the widget at `index` of the layout. */
function valueAt(data: DashboardData | undefined, index: number): WidgetValue | undefined {
  return data?.widgets.find((w) => w.index === index)
}

export function DashboardView({ dashboard, data, loading, failed, onRetry }: DashboardViewProps) {
  const { t } = useTranslation()
  const cols = normalizeColumns(dashboard.columns)
  const layout: DashboardWidget[] = dashboard.layout ?? []
  if (layout.length === 0) {
    return (
      <div className="rounded-lg border border-dashed py-12 text-center text-sm text-muted-foreground">
        {t(
          'dashboards.view.empty',
          'This dashboard has no widgets yet. Choose Customize to add some.'
        )}
      </div>
    )
  }
  return (
    <div
      // Rows keep their stored height from 640px; on a phone every widget is
      // as tall as its content, so a two-row figure leaves no empty space.
      className={cn(
        'grid gap-3 sm:gap-4 sm:[grid-auto-rows:minmax(var(--row),auto)]',
        columnsClass(cols)
      )}
      style={{ '--row': `${ROW_HEIGHT}px` } as React.CSSProperties}
      data-columns={cols}
    >
      {layout.map((w, i) => {
        const spec = w.config as { id?: string } | undefined
        const title = t('dashboards.widget.failed', 'This widget could not be shown')
        const value = failed
          ? { id: '', index: i, widget_type: w.widget_type, state: 'error' as const }
          : valueAt(data, i)
        // A widget with nothing to show yet takes one row: the compact empty
        // state never holds a tall card of blank space.
        const compact = !!value && widgetModel(value, specOf(w), false).state === 'no_data_yet'
        const rows = compact ? 1 : w.h
        return (
          <div
            key={spec?.id ?? `${w.widget_type}-${i}`}
            style={
              {
                '--span': gridColumnSpan(colSpanFor(w.w, cols)),
                '--span-sm': gridColumnSpan(Math.min(2, colSpanFor(w.w, cols))),
                '--span-xs': phoneSpan(w.w, rows, cols),
                '--row-span': widgetRowSpan(rows),
              } as React.CSSProperties
            }
            className={cn(
              'flex min-w-0 flex-col sm:[grid-row:var(--row-span)]',
              widgetSpanClass(cols)
            )}
            data-widget-index={i}
            data-compact={compact || undefined}
          >
            <WidgetErrorBoundary
              fallback={(reset) => (
                <WidgetFrame title={title} state="error" onRetry={reset} className="flex-1" />
              )}
            >
              <WidgetView
                widget={w}
                value={value}
                asOf={data?.computed_at}
                pageAsOf={data?.computed_at}
                stale={data?.stale}
                loading={loading && !data && !failed}
                onRetry={onRetry}
                scope={data?.scope}
                className="flex-1"
              />
            </WidgetErrorBoundary>
          </div>
        )
      })}
    </div>
  )
}
