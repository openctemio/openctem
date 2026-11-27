'use client'

/**
 * The one dashboard renderer: every widget of a layout, laid out in the
 * dashboard's columns, drawn from the dashboard's stored snapshot. Each
 * widget has its own error boundary, so one bad result never blanks the page.
 */

import { useId, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { WidgetErrorBoundary, WidgetFrame } from '@/components/dashboard-kit'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { Dashboard, DashboardWidget } from '../api/dashboards.types'
import type { DashboardData, WidgetValue } from '../api/widget-data'
import {
  colSpanFor,
  columnsClass,
  gridColumnSpan,
  phoneSpan,
  widgetSpanClass,
  normalizeColumns,
  widgetRowSpan,
  widePackSpans,
  WIDE_GRID_CLASS,
  WIDE_WIDGET_CLASS,
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

/**
 * A widget of a module that is off for the organization, or of a metric the
 * viewer may not read, carries no figure and is not shown at all: an empty
 * card would read as "nothing to see", and a lock card on a shared dashboard
 * only says what someone else can see. The editor still lists them, so a
 * person who may edit the dashboard can remove them.
 */
export function hiddenOnView(value: WidgetValue | undefined): boolean {
  return (
    value?.state === 'unsupported' &&
    (value.reason === 'module_off' || value.reason === 'forbidden')
  )
}

/**
 * On a phone the first widgets are the page; the rest wait behind one
 * "More widgets" button, so the home is one short column (board M-Home).
 * From 640px every widget shows.
 */
export const PHONE_VISIBLE_WIDGETS = 5

/** The result of the widget at `index` of the layout. */
function valueAt(data: DashboardData | undefined, index: number): WidgetValue | undefined {
  return data?.widgets.find((w) => w.index === index)
}

/**
 * The rows a widget spans beside its neighbours, on the dashboard and in its
 * editor alike (the editor's previews stand as they will on the page). A
 * full-width widget with no figure (nothing yet, or not measured) takes one
 * row; a narrower one keeps its rows, so the widgets placed beside it do not
 * move. The key figures strip is always one row of tiles (older layouts
 * stored it taller).
 */
export function rowsOnView(
  w: DashboardWidget,
  value: WidgetValue | undefined,
  columns: number | undefined
): number {
  return value?.shape === 'kpis' || isCompact(w, value, columns) ? 1 : w.h || 1
}

/** A full-width widget with no figure: one row, whatever it stored. */
function isCompact(
  w: DashboardWidget,
  value: WidgetValue | undefined,
  columns: number | undefined
): boolean {
  const cols = normalizeColumns(columns)
  const state = value ? widgetModel(value, specOf(w), false).state : undefined
  return (state === 'no_data_yet' || state === 'not_measured') && colSpanFor(w.w, cols) === cols
}

export function DashboardView({ dashboard, data, loading, failed, onRetry }: DashboardViewProps) {
  const { t } = useTranslation()
  const [allOnPhone, setAllOnPhone] = useState(false)
  const moreId = useId()
  const cols = normalizeColumns(dashboard.columns)
  const layout: DashboardWidget[] = dashboard.layout ?? []
  const shown = layout
    .map((w, i) => ({ w, i }))
    .filter(({ i }) => failed || !hiddenOnView(valueAt(data, i)))
  const folded = Math.max(0, shown.length - PHONE_VISIBLE_WIDGETS)
  if (layout.length > 0 && shown.length === 0) {
    return (
      <div className="rounded-lg border border-dashed py-12 text-center text-sm text-muted-foreground">
        {t(
          'dashboards.view.nothingVisible',
          'Nothing on this dashboard is available to you. The widgets need a permission or a module you do not have.'
        )}
      </div>
    )
  }
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
  // On a wide screen runs of side-by-side widgets sit three, then four, to a row.
  const wide3 = widePackSpans(
    shown.map(({ w }) => w),
    cols,
    3
  )
  const wide4 = widePackSpans(
    shown.map(({ w }) => w),
    cols,
    4
  )
  return (
    <div className="@container flex flex-col gap-4">
      <div
        id={moreId}
        // Rows are as tall as their content at every width. A widget's stored
        // height only places it (it spans that many rows beside its
        // neighbours); it never sets a floor. Every figure has its own height
        // (the plots are 180/220 px), so a 128 px row floor only left an empty
        // card: the CTEM loop stored two rows tall stood 120 px above its
        // tiles. Widgets of one row share its height. One 16px gap.
        className={cn('grid gap-4', columnsClass(cols), cols > 1 && WIDE_GRID_CLASS)}
        data-columns={cols}
      >
        {shown.map(({ w, i }, pos) => {
          const spec = w.config as { id?: string } | undefined
          const title = t('dashboards.widget.failed', 'This widget could not be shown')
          const value = failed
            ? { id: '', index: i, widget_type: w.widget_type, state: 'error' as const }
            : valueAt(data, i)
          const rows = rowsOnView(w, value, cols)
          const compact = isCompact(w, value, cols)
          return (
            <div
              key={spec?.id ?? `${w.widget_type}-${i}`}
              style={
                {
                  '--span': gridColumnSpan(colSpanFor(w.w, cols)),
                  '--span-sm': gridColumnSpan(Math.min(2, colSpanFor(w.w, cols))),
                  '--span-xs': phoneSpan(w.w, rows, cols),
                  '--row-span': widgetRowSpan(rows),
                  '--span-wide': wide3[pos].column,
                  '--span-wider': wide4[pos].column,
                  '--row-span-wide': wide3[pos].packed ? 'auto' : widgetRowSpan(rows),
                  '--row-span-wider': wide4[pos].packed ? 'auto' : widgetRowSpan(rows),
                } as React.CSSProperties
              }
              className={cn(
                'flex min-w-0 flex-col sm:[grid-row:var(--row-span)]',
                widgetSpanClass(cols),
                cols > 1 && WIDE_WIDGET_CLASS,
                !allOnPhone && pos >= PHONE_VISIBLE_WIDGETS && 'max-sm:hidden'
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
      {folded > 0 && (
        <Button
          type="button"
          variant="outline"
          className="w-full justify-between sm:hidden"
          aria-expanded={allOnPhone}
          aria-controls={moreId}
          onClick={() => setAllOnPhone((v) => !v)}
        >
          {allOnPhone
            ? t('dashboards.view.fewerWidgets', 'Show fewer widgets')
            : t('dashboards.view.moreWidgets', 'More widgets on this dashboard ({n})', {
                n: folded,
              })}
          <ChevronDown
            className={cn('h-4 w-4 transition-transform', allOnPhone && 'rotate-180')}
            aria-hidden
          />
        </Button>
      )}
    </div>
  )
}
