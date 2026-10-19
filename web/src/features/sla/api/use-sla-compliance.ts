'use client'

import { useFindingStatsApi } from '@/features/findings/api/use-findings-api'
import type { AgingBucketKey, ComplianceTile } from '../lib/compliance'

// One toast per failure is the page's inline error, not one per request.
const QUIET = { onError: () => undefined }

const AGE_FIELD: Record<AgingBucketKey, 'up_to_7' | 'd8_to_30' | 'd31_to_90' | 'over_90'> = {
  upTo7: 'up_to_7',
  d8to30: 'd8_to_30',
  d31to90: 'd31_to_90',
  over90: 'over_90',
}

/**
 * Every number of the SLA compliance page from one server-side stats read
 * over the open findings (the tiles, the past-due age buckets and the severity
 * split), so the page costs one request however many buckets it shows.
 */
export function useSlaCompliance() {
  const q = useFindingStatsApi({ state: 'open', sla_breakdown: true }, QUIET)
  const sla = q.data?.sla

  // A failed or pending read is undefined, shown as "—", never a 0.
  const tiles: Record<ComplianceTile, number | undefined> = {
    pastDue: sla?.past_due,
    dueSoon: sla?.due_soon,
    onTrack: sla?.on_track,
    open: q.data?.total,
  }
  const aging = Object.fromEntries(
    (Object.keys(AGE_FIELD) as AgingBucketKey[]).map((k) => [
      k,
      sla?.past_due_by_age[AGE_FIELD[k]],
    ])
  ) as Record<AgingBucketKey, number | undefined>

  return {
    tiles,
    aging,
    /** Past-due findings by severity. */
    bySeverity: sla?.past_due_by_severity,
    error: q.error,
    isLoading: q.isLoading && !q.data,
    retry: () => void q.mutate(),
  }
}
