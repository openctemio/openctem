'use client'

import { useFindingStatsApi } from '@/features/findings/api/use-findings-api'
import {
  AGING_BUCKET_KEYS,
  agingFilter,
  tileFilter,
  type AgingBucketKey,
  type ComplianceTile,
} from '../lib/compliance'

// One toast per failure is the page's inline error, not one per request.
const QUIET = { onError: () => undefined }

const TILES: ComplianceTile[] = ['pastDue', 'dueSoon', 'onTrack', 'open']

/** Every number of the SLA compliance page: server-side stats reads, no client counting. */
export function useSlaCompliance() {
  const pastDue = useFindingStatsApi(tileFilter('pastDue'), QUIET)
  const dueSoon = useFindingStatsApi(tileFilter('dueSoon'), QUIET)
  const onTrack = useFindingStatsApi(tileFilter('onTrack'), QUIET)
  const open = useFindingStatsApi(tileFilter('open'), QUIET)
  const upTo7 = useFindingStatsApi(agingFilter('upTo7'), QUIET)
  const d8to30 = useFindingStatsApi(agingFilter('d8to30'), QUIET)
  const d31to90 = useFindingStatsApi(agingFilter('d31to90'), QUIET)
  const over90 = useFindingStatsApi(agingFilter('over90'), QUIET)

  const tiles: Record<ComplianceTile, typeof pastDue> = { pastDue, dueSoon, onTrack, open }
  const aging: Record<AgingBucketKey, typeof pastDue> = { upTo7, d8to30, d31to90, over90 }
  const all = [...TILES.map((k) => tiles[k]), ...AGING_BUCKET_KEYS.map((k) => aging[k])]

  const error = all.find((r) => r.error)?.error
  const isLoading = all.some((r) => r.isLoading && !r.data)
  const retry = () => {
    for (const r of all) void r.mutate()
  }

  return {
    tiles,
    aging,
    /** Past-due findings by severity (the same read as the Past due tile). */
    bySeverity: pastDue.data?.by_severity,
    error,
    isLoading,
    retry,
  }
}
