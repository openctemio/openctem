'use client'

import { Card, CardContent } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import type { Dashboard, DashboardWidget } from '../api/dashboards.types'
import { WIDGET_REGISTRY } from '../widgets/registry'
import { WidgetBoundary } from '@/features/dashboard/components/widget-boundary'
import {
  ROW_HEIGHT,
  colSpanFor,
  columnsClass,
  gridColumnSpan,
  normalizeColumns,
  widgetRowSpan,
} from '../layout'

/** Re-exported for callers that used to import it from here. */
export { widgetColSpan } from '../layout'

/**
 * Read-only render of a saved dashboard laid out in `columns` equal columns
 * (1..4) on a fixed-row grid. Shared by the main dashboard shell (as a
 * switchable view) and the /dashboards gallery. Each widget renders its own live
 * data from WIDGET_REGISTRY — an unknown type is shown as a small notice, never a
 * crash. Row height is fixed so a short stat widget occupies exactly its `h` rows
 * instead of stretching to fill the container.
 */
export function DashboardCanvas({
  layout,
  columns,
}: {
  layout: DashboardWidget[]
  columns?: Dashboard['columns']
}) {
  const { t } = useTranslation()
  const cols = normalizeColumns(columns)
  if (layout.length === 0) {
    return (
      <div className="rounded-lg border border-dashed py-12 text-center text-sm text-muted-foreground">
        {t('dashboardMetrics.canvas.empty')}
      </div>
    )
  }
  return (
    <div
      className={cn('grid gap-4', columnsClass(cols))}
      style={{ gridAutoRows: `${ROW_HEIGHT}px` }}
      data-columns={cols}
    >
      {layout.map((wg, i) => {
        const def = WIDGET_REGISTRY[wg.widget_type]
        return (
          <div
            key={`${wg.widget_type}-${i}`}
            style={{
              gridColumn: gridColumnSpan(colSpanFor(wg.w, cols)),
              gridRow: widgetRowSpan(wg.h),
            }}
            className="min-w-0"
          >
            {def ? (
              // One widget that throws shows its own error; the others render.
              <WidgetBoundary>
                <def.component />
              </WidgetBoundary>
            ) : (
              <Card className="h-full">
                <CardContent className="p-5 text-sm text-muted-foreground">
                  {t('dashboardMetrics.widget.unknown', undefined, { type: wg.widget_type })}
                </CardContent>
              </Card>
            )}
          </div>
        )
      })}
    </div>
  )
}
