/**
 * EPSS trend helpers (api/docs/architecture/vulnerability-page.md, "EPSS
 * trend"): the API sends daily scores 0..1; charts draw percent.
 */

import type { SeriesPoint } from '@/components/dashboard-kit'
import type { EpssPoint } from '../types/list'

/** The trend as dashboard-kit series points, in percent (0..100). */
export function epssSeries(points: EpssPoint[] | undefined): SeriesPoint[] {
  return (points ?? [])
    .filter((p) => Number.isFinite(p.score))
    .map((p) => ({ t: p.date, v: Math.round(p.score * 100000) / 1000 }))
}

/**
 * The change over the trend in percentage points (last minus first), or null
 * with fewer than two points.
 */
export function epssChange(points: EpssPoint[] | undefined): number | null {
  const s = epssSeries(points)
  if (s.length < 2) return null
  return Math.round((s[s.length - 1].v - s[0].v) * 1000) / 1000
}
