'use client'

/**
 * The confirmation New scan asks before a scan with a range wider than a /16
 * is created: the address count, the /16 chunks the platform dispatches and
 * a rough duration of the host discovery pass, which always runs first.
 * Display and consent only: scope, exclusions, zones and the per-tenant
 * range limit are the API's answer. Design:
 * api/docs/rfcs/RFC-151-large-range-targets.md.
 */

import { useId } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { useTranslation } from '@/context/i18n-provider'
import {
  durationParts,
  ESTIMATE_ADDRESSES_PER_SECOND,
  largeRangeKey,
  type LargeRangeSummary,
} from '../../lib/large-range'

/** How many ranges are named one by one; the rest are counted. */
const LISTED_RANGES = 3

export function LargeRangeConfirm({
  summary,
  confirmed,
  onConfirm,
}: {
  summary: LargeRangeSummary
  /** The key the person confirmed (ScanTargets.largeRangeConfirmed). */
  confirmed?: string
  onConfirm: (key: string | undefined) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const key = largeRangeKey(summary)
  const addresses = summary.addresses.toLocaleString()
  const { hours, minutes } = durationParts(summary.seconds)
  const listed = summary.ranges.slice(0, LISTED_RANGES).join(', ')
  const more = summary.ranges.length - LISTED_RANGES
  return (
    <div
      className="space-y-2 rounded-md border bg-muted/40 p-3 text-sm"
      data-testid="large-range-confirm"
    >
      <p className="font-medium">
        {more > 0
          ? t('scans.largeRange.titleMore', undefined, { ranges: listed, count: more })
          : t('scans.largeRange.title', undefined, { ranges: listed })}
      </p>
      <p className="text-muted-foreground">
        {t('scans.largeRange.summary', undefined, {
          addresses,
          chunks: summary.chunks.toLocaleString(),
        })}
      </p>
      <p className="text-muted-foreground">
        {t('scans.largeRange.estimate', undefined, {
          hours,
          minutes,
          rate: ESTIMATE_ADDRESSES_PER_SECOND.toLocaleString(),
        })}
      </p>
      <p className="text-muted-foreground">{t('scans.largeRange.scope')}</p>
      <div className="flex items-start gap-2 pt-1">
        <Checkbox
          id={id}
          checked={confirmed === key}
          onCheckedChange={(v) => onConfirm(v === true ? key : undefined)}
          className="mt-0.5"
        />
        <label htmlFor={id} className="cursor-pointer">
          {t('scans.largeRange.confirm', undefined, { addresses })}
        </label>
      </div>
    </div>
  )
}
