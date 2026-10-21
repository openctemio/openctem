'use client'

/**
 * Bars for a category result: one labelled horizontal bar per key, or one
 * stacked bar for proportion. Drawn with CSS (no chart library): values are
 * printed next to every bar, ordinal keys (severity, priority, age band) keep
 * their order, and past eight keys the rest folds into "Other".
 */

import { useTranslation } from '@/context/i18n-provider'
import { CATEGORICAL_SLOTS, seriesVar } from '@/lib/chart-palette'
import { formatMetric, formatPercent, type MetricUnit } from '@/lib/format-metric'
import { CategoryTable } from './table-viz'
import { ChartOrTable, DrillLink, foldOther, useLabel } from './viz-parts'
import type { CategoryResult, CategoryRow, DrillFn } from './types'

export interface BarVizProps {
  result: CategoryResult
  unit?: MetricUnit
  /** One stacked bar showing the share of each key, with a legend. */
  stacked?: boolean
  drill?: DrillFn
}

/** The rows to draw: ordinal results keep every key; others fold past the slot count. */
export function barRows(result: CategoryResult, otherLabel: string): CategoryRow[] {
  if (result.ordinal) return result.rows
  return foldOther(result.rows, CATEGORICAL_SLOTS, (value) => ({
    key: 'other',
    label: otherLabel,
    value,
  }))
}

export function BarViz({ result, unit = 'count', stacked = false, drill }: BarVizProps) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  const rows = barRows(result, t('dashboardKit.other', 'Other'))
  const max = Math.max(1, ...rows.map((r) => r.value))
  const sum = rows.reduce((s, r) => s + r.value, 0)

  const chart = stacked ? (
    <div className="flex flex-col gap-2">
      <div className="flex h-4 w-full gap-0.5 overflow-hidden rounded-full bg-muted">
        {rows
          .filter((r) => r.value > 0)
          .map((r) => {
            const i = rows.indexOf(r)
            const text = `${label(r)}: ${formatMetric(r.value, unit, locale)}`
            return (
              <DrillLink
                key={r.key}
                to={drill?.({ key: r.key })}
                label={text}
                title={text}
                className="h-full"
                style={{
                  width: `${(r.value / (sum || 1)) * 100}%`,
                  background: seriesVar(r.key, i),
                }}
              />
            )
          })}
      </div>
      <ul className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
        {rows.map((r, i) => (
          <li key={r.key} className="inline-flex items-center gap-1.5">
            <span
              className="size-2.5 rounded-sm"
              style={{ background: seriesVar(r.key, i) }}
              aria-hidden
            />
            <span className="text-muted-foreground">{label(r)}</span>
            <span className="tabular-nums">{formatMetric(r.value, unit, locale)}</span>
            <span className="text-muted-foreground tabular-nums">
              ({formatPercent(sum ? (r.value / sum) * 100 : 0, locale)})
            </span>
          </li>
        ))}
      </ul>
    </div>
  ) : (
    <ul className="flex flex-col gap-1.5">
      {rows.map((r, i) => {
        const text = `${label(r)}: ${formatMetric(r.value, unit, locale)}`
        return (
          <li key={r.key}>
            <DrillLink to={drill?.({ key: r.key })} label={text} className="block">
              <div className="grid grid-cols-[minmax(5rem,9rem)_1fr_auto] items-center gap-2 text-sm hover:bg-accent/40">
                <span className="truncate text-muted-foreground">{label(r)}</span>
                <span className="h-3 rounded-e-sm bg-muted/60">
                  <span
                    className="block h-full rounded-e-sm"
                    style={{
                      width: `${(r.value / max) * 100}%`,
                      minWidth: r.value > 0 ? 2 : 0,
                      background: seriesVar(r.key, i),
                    }}
                  />
                </span>
                <span className="tabular-nums">{formatMetric(r.value, unit, locale)}</span>
              </div>
            </DrillLink>
          </li>
        )
      })}
    </ul>
  )

  return (
    <ChartOrTable
      chart={chart}
      table={<CategoryTable result={{ ...result, rows }} unit={unit} drill={drill} />}
    />
  )
}
