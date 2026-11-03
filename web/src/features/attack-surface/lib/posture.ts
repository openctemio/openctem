/**
 * The attack surface posture read (GET /api/v1/attack-surface/posture) and
 * its helpers. Formula: api/docs/architecture/easm-posture.md.
 */

import type { PostureCategoryRow } from '@/components/dashboard-kit'

export const POSTURE_URL = '/api/v1/attack-surface/posture'
export const POSTURE_REFRESH_URL = `${POSTURE_URL}/refresh`
export const POSTURE_SCHEDULE_URL = `${POSTURE_URL}/schedule`

export const POSTURE_SCHEDULES = ['manual', '1h', '6h', '24h'] as const
export type PostureSchedule = (typeof POSTURE_SCHEDULES)[number]

export interface PostureState {
  refresh_every: PostureSchedule
  computed_at?: string
  next_refresh_at?: string
  building: boolean
  last_error?: string
  stale: boolean
}

export interface PosturePlanStep {
  asset_id?: string
  asset_name?: string
  category: string
  points: number
  issues: number
  score_after: number
  grade_after: string
}

export interface PostureReduction {
  criticality: 'critical' | 'high' | 'medium' | 'low'
  assets: number
  issues: number
  points: number
  share: number
  gain: number
}

export interface PostureRoot {
  root_domain: string
  score: number
  grade?: string
  assets: number
  issues: number
  top_category?: string
}

export interface PostureResponse {
  state: PostureState
  scoped: boolean
  filtered: boolean
  score: {
    measured: boolean
    score: number
    grade?: string
    assets: number
    categories: PostureCategoryRow[]
  }
  previous_score?: number
  previous_grade?: string
  plan: { target?: string; floor?: number; reached: boolean; steps: PosturePlanStep[] }
  reductions: PostureReduction[]
  roots: PostureRoot[]
  roots_total: number
}

/** The read URL, optionally for one root domain. */
export function postureUrl(rootDomain?: string): string {
  if (!rootDomain) return POSTURE_URL
  return `${POSTURE_URL}?${new URLSearchParams({ root_domain: rootDomain }).toString()}`
}

/** The categories that take points away, largest first (at most n). */
export function topDeductions(categories: PostureCategoryRow[], n = 3): PostureCategoryRow[] {
  return [...categories]
    .filter((c) => c.deduction > 0)
    .sort((a, b) => b.deduction - a.deduction || a.category.localeCompare(b.category))
    .slice(0, n)
}

/** The score change since the previous computation, or null. */
export function scoreDelta(p: Pick<PostureResponse, 'score' | 'previous_score'>): number | null {
  if (!p.score.measured || p.previous_score == null) return null
  return p.score.score - p.previous_score
}

/** The rows of the CSV export of the root domains. */
export function rootsCsv(roots: PostureRoot[], header: string[]): string {
  const esc = (v: string | number) => {
    const s = String(v)
    // Neutralise spreadsheet formulas and quote every cell.
    const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s
    return `"${safe.replace(/"/g, '""')}"`
  }
  const lines = [header.map(esc).join(',')]
  for (const r of roots) {
    lines.push(
      [r.root_domain, r.grade ?? '', r.score, r.assets, r.issues, r.top_category ?? '']
        .map(esc)
        .join(',')
    )
  }
  return lines.join('\n')
}
