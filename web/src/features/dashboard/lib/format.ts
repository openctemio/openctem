/**
 * Number and period formatting shared by the executive summary, program health
 * and the reports page, so one figure reads the same wherever it appears.
 */

export type Period = '30' | '90' | '365'

/** The reporting windows every insight page offers (one list, one set of labels). */
export const PERIOD_OPTIONS: readonly { value: Period; labelKey: string; fallback: string }[] = [
  { value: '30', labelKey: 'insights.period.d30', fallback: 'Last 30 days' },
  { value: '90', labelKey: 'insights.period.d90', fallback: 'Last 90 days' },
  { value: '365', labelKey: 'insights.period.d365', fallback: 'Last year' },
]

/** A rate over fewer items than this is noise, so it is not shown as a percentage. */
export const MIN_RATE_SAMPLE = 5

/**
 * A 0-100 rate as the dashboards show it: whole percent, "<1%" for a non-zero
 * value that would round to zero, and "—" when it is not measured or rests on
 * fewer than MIN_RATE_SAMPLE items (`n`, when the caller knows it).
 */
export function formatPct(
  value: number | null | undefined,
  opts: { n?: number | null; locale?: string } = {}
): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  if (opts.n !== null && opts.n !== undefined && opts.n < MIN_RATE_SAMPLE) return '—'
  if (value > 0 && value < 1) return '<1%'
  return `${new Intl.NumberFormat(opts.locale, { maximumFractionDigits: 0 }).format(Math.round(value))}%`
}

/** A count in the app locale (thousands separators follow the language). */
export function formatCount(value: number, locale?: string): string {
  return new Intl.NumberFormat(locale).format(value)
}

/** A date tick for a chart axis, in the app locale. */
export function formatTickDate(iso: string, locale?: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString(locale, { month: 'short', day: 'numeric' })
}
