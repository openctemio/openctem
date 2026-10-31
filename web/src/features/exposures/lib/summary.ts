/**
 * The one-line description of an exposure in the viewer's language. The API
 * returns the English sentence plus the sentence form (variant) and its
 * values; the catalog key is `exposures.summary.<event_type>[.<variant>]`, so
 * a translated sentence uses exactly the values the API chose. Values are
 * scan output: they are only ever interpolated into text, never markup.
 */
import type { ExposureEvent } from '@/lib/api/exposure-types'

type Translate = (key: string, fallback: string, vars?: Record<string, string | number>) => string

/** The catalog key of a summary, or null when the API fell back to the title. */
export function summaryKey(e: Pick<ExposureEvent, 'event_type' | 'summary'>): string | null {
  const s = e.summary
  if (!s || !s.text || s.variant === 'title') return null
  return s.variant
    ? `exposures.summary.${e.event_type}.${s.variant}`
    : `exposures.summary.${e.event_type}`
}

/** The summary to show, translated when the catalog has it; "" when none. */
export function exposureSummaryText(
  e: Pick<ExposureEvent, 'event_type' | 'summary'>,
  t: Translate
): string {
  const key = summaryKey(e)
  if (!key || !e.summary) return ''
  return t(key, e.summary.text, e.summary.args ?? {})
}
