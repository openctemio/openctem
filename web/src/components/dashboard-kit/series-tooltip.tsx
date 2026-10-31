'use client'

/**
 * The one hover/focus/tap tooltip of every dashboard-kit time-series chart
 * (columns, area, line, diverging flow). It reads the bucket from the chart's
 * own rows, so the order and the comparison never depend on what the chart
 * library happens to pass:
 *
 *   Week of Oct 20 – 26                 vs previous
 *   ● P0                       3          +1
 *   ● P1                      12          −2
 *   2 more at 0
 *   Total                     15          −1
 *
 * - header: the span the bucket covers (formatBucketRange);
 * - one row per series with a value, in the order the marks are drawn (top of
 *   a stack first), each with its swatch (the series colour from the shared
 *   palette: severity, priority, flow or categorical), its value in the
 *   chart's unit and its change against the previous bucket;
 * - series at zero fold into one line (from three series); a series with no point in the bucket is
 *   absent, never shown as 0;
 * - a Total row for stacks of two or more, a Net change row for a flow pair.
 */

import type { ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { formatBucketRange, formatDelta, formatMetric, type MetricUnit } from '@/lib/format-metric'
import { deltaTone } from './compare'
import type { Polarity } from './types'
import { TONE_CLASS, useToneVerdict } from './viz-parts'

type Row = Record<string, number | string>

/** How the series of a chart combine: stacked marks, independent lines, or a flow pair. */
export type SeriesTooltipMode = 'stack' | 'lines' | 'flow'

export interface SeriesTooltipMeta {
  key: string
  label: string
  /** CSS background of the series swatch (a colour, or the hatch for "none"). */
  swatch: string
}

export interface SeriesTooltipRow extends SeriesTooltipMeta {
  value: number
  /** Change against the previous bucket; null when that bucket has no point. */
  delta: number | null
}

export interface SeriesTooltipModel {
  t: string
  rows: SeriesTooltipRow[]
  /** Series with a point of 0 in this bucket (folded into one line). */
  zero: number
  /** Sum of the stack (two or more series), with its change. */
  total: { value: number; delta: number | null } | null
  /** Opened minus fixed, for a flow pair. */
  net: number | null
  /** Whether any change against a previous bucket is shown. */
  hasPrevious: boolean
}

/** Charts with at least this many series fold their zero rows into one line. */
export const FOLD_ZEROS_FROM = 3

function pointOf(row: Row | undefined, key: string): number | null {
  const v = row?.[key]
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

/**
 * The tooltip's content for the bucket starting at `t`. Pure, so the wording
 * rules are unit-tested without rendering a chart. Flow values arrive signed
 * (fixed drawn downwards) and are shown as magnitudes.
 */
export function buildSeriesTooltip(
  rows: Row[],
  t: string,
  meta: SeriesTooltipMeta[],
  mode: SeriesTooltipMode
): SeriesTooltipModel | null {
  const index = rows.findIndex((r) => String(r.t) === t)
  if (index < 0) return null
  const row = rows[index]
  const prev = index > 0 ? rows[index - 1] : undefined
  const read = (r: Row | undefined, key: string) => {
    const v = pointOf(r, key)
    return v == null ? null : mode === 'flow' ? Math.abs(v) : v
  }
  const ordered = mode === 'stack' ? [...meta].reverse() : meta
  const shown: SeriesTooltipRow[] = []
  let zero = 0
  let present = 0
  let sum = 0
  let prevSum = 0
  let prevAny = false
  for (const m of ordered) {
    const v = read(row, m.key)
    const p = read(prev, m.key)
    if (p != null) {
      prevAny = true
      prevSum += p
    }
    if (v == null) continue
    present++
    sum += v
    // Fold zeros only where a chart has enough series for them to crowd the
    // rows; "Fixed 0" next to "New 26" is the point of a two-series chart.
    if (v === 0 && meta.length >= FOLD_ZEROS_FROM) {
      zero++
      continue
    }
    shown.push({ ...m, value: v, delta: p == null ? null : v - p })
  }
  if (present === 0) return null
  const total =
    mode === 'stack' && meta.length > 1
      ? { value: sum, delta: prevAny ? sum - prevSum : null }
      : null
  const net = mode === 'flow' ? (read(row, 'opened') ?? 0) - (read(row, 'fixed') ?? 0) : null
  return {
    t,
    rows: shown,
    zero,
    total,
    net,
    hasPrevious: shown.some((r) => r.delta != null) || total?.delta != null,
  }
}

interface SeriesTooltipProps {
  /** Injected by the chart: whether a bucket is hovered, focused or tapped. */
  active?: boolean
  /** Injected by the chart: the hovered bucket's `t`. */
  label?: string | number
  rows: Row[]
  meta: SeriesTooltipMeta[]
  mode: SeriesTooltipMode
  bucket: 'day' | 'week' | 'month'
  unit?: MetricUnit
  /**
   * Which way is good for the figure. A change is coloured by it (shared tone
   * logic of DeltaText); omitted or neutral, changes stay muted. In a flow the
   * polarity is the open count's: "opened" follows it, "fixed" is its opposite.
   */
  polarity?: Polarity
}

const OPPOSITE: Record<Polarity, Polarity> = {
  down_good: 'up_good',
  up_good: 'down_good',
  neutral: 'neutral',
}

/** The polarity of one series' change: in a flow, fixed runs against opened. */
export function seriesPolarity(mode: SeriesTooltipMode, key: string, polarity: Polarity): Polarity {
  return mode === 'flow' && key === 'fixed' ? OPPOSITE[polarity] : polarity
}

function Line({
  swatch,
  label,
  value,
  delta,
  deltaClass,
  verdict,
  toneOnValue,
  strong,
}: {
  swatch?: string
  label: ReactNode
  value: string
  delta?: string
  /** The tone class of the delta (value for the net row), muted when absent. */
  deltaClass?: string
  /** Screen-reader words that say what the colour says. */
  verdict?: string | null
  /** Colour the value cell instead of the delta cell (the Net change row has no delta). */
  toneOnValue?: boolean
  strong?: boolean
}) {
  return (
    <tr className={strong ? 'font-medium' : undefined}>
      <td className="w-2 py-0.5 pe-2 align-middle">
        {swatch && (
          <span aria-hidden className="block size-2 rounded-full" style={{ background: swatch }} />
        )}
      </td>
      <td
        className={
          strong
            ? 'max-w-40 truncate py-0.5 pe-3'
            : 'max-w-40 truncate py-0.5 pe-3 text-muted-foreground'
        }
      >
        {label}
      </td>
      <td className={cn('py-0.5 text-end font-medium tabular-nums', toneOnValue && deltaClass)}>
        {value}
        {toneOnValue && verdict && <span className="sr-only"> ({verdict})</span>}
      </td>
      <td
        className={cn(
          'min-w-10 py-0.5 ps-3 text-end tabular-nums',
          toneOnValue ? 'text-muted-foreground' : (deltaClass ?? 'text-muted-foreground')
        )}
      >
        {delta ?? ''}
        {!toneOnValue && delta != null && verdict && <span className="sr-only"> ({verdict})</span>}
      </td>
    </tr>
  )
}

/** The rendered tooltip; pass it as the chart Tooltip's `content`. */
export function SeriesTooltip({
  active,
  label,
  rows,
  meta,
  mode,
  bucket,
  unit = 'count',
  polarity = 'neutral',
}: SeriesTooltipProps) {
  const { t, locale } = useTranslation()
  const verdictOf = useToneVerdict()
  if (!active || label == null) return null
  const model = buildSeriesTooltip(rows, String(label), meta, mode)
  if (!model) return null
  const range = formatBucketRange(model.t, bucket, locale)
  const header =
    range.kind === 'week'
      ? t('dashboardKit.tooltip.week', 'Week of {range}', { range: range.text })
      : range.text
  const delta = (d: number | null) => (d == null ? undefined : formatDelta(d, unit, locale))
  const tone = (d: number | null, p: Polarity) => {
    const k = deltaTone(d, p)
    return { deltaClass: TONE_CLASS[k], verdict: verdictOf(k) }
  }
  const value = (v: number) => formatMetric(v, unit, locale)
  return (
    <div
      data-testid="series-tooltip"
      className="min-w-48 max-w-72 rounded-md border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-md"
    >
      <div className="mb-1 flex items-baseline justify-between gap-4">
        <span className="font-medium">{header}</span>
        {model.hasPrevious && (
          <span className="text-muted-foreground">
            {t('dashboardKit.tooltip.vsPrevious', 'vs previous')}
          </span>
        )}
      </div>
      <table className="w-full border-collapse">
        <tbody>
          {model.rows.map((r) => (
            <Line
              key={r.key}
              swatch={r.swatch}
              label={r.label}
              value={value(r.value)}
              delta={delta(r.delta)}
              {...tone(r.delta, seriesPolarity(mode, r.key, polarity))}
            />
          ))}
        </tbody>
        {(model.total || model.net != null) && (
          <tfoot className="border-t">
            {model.total && (
              <Line
                label={t('dashboardKit.tooltip.total', 'Total')}
                value={value(model.total.value)}
                delta={delta(model.total.delta)}
                {...tone(model.total.delta, polarity)}
                strong
              />
            )}
            {model.net != null && (
              <Line
                label={t('dashboardKit.tooltip.net', 'Net change')}
                value={formatDelta(model.net, unit, locale)}
                toneOnValue
                {...tone(model.net, polarity)}
                strong
              />
            )}
          </tfoot>
        )}
      </table>
      {model.zero > 0 && (
        <p className="mt-1 text-muted-foreground">
          {model.rows.length === 0
            ? t('dashboardKit.tooltip.allZero', 'All at 0')
            : t('dashboardKit.tooltip.moreAtZero', '{n} more at 0', { n: model.zero })}
        </p>
      )}
    </div>
  )
}
