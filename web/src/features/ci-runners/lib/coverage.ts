/**
 * Repository coverage (api RFC-051 §10.6): which repositories are not being
 * looked at, per capability, and since when. A capability is fresh while the
 * pipeline that reported it runs within its cadence (30 days for a daemon
 * scan), stale up to 90 days, never after.
 */

import type { PillTone } from '@/features/shared/components/tone-pill'
import type { CICapability, CICoverageFilter, CICoverageState } from '../types'

export const CAPABILITIES: CICapability[] = ['sast', 'sca', 'secrets', 'iac']

export const CAPABILITY_LABEL: Record<CICapability, string> = {
  sast: 'SAST',
  sca: 'SCA',
  secrets: 'Secrets',
  iac: 'IaC',
}

export const COVERAGE_STATE_META: Record<
  CICoverageState,
  { label: string; tone: PillTone; description: string }
> = {
  fresh: { label: 'Fresh', tone: 'success', description: 'Looked at within its cadence.' },
  stale: {
    label: 'Stale',
    tone: 'warning',
    description: 'Last looked at more than its cadence ago, within 90 days.',
  },
  never: { label: 'Never', tone: 'muted', description: 'Not looked at in the last 90 days.' },
}

export function isCoverageState(s: string | undefined): s is CICoverageState {
  return s === 'fresh' || s === 'stale' || s === 'never'
}

export function isCoverageFilter(s: string | undefined): s is CICoverageFilter {
  return s === '' || s === 'gap' || s === 'uncovered' || s === 'covered'
}

export const SOURCE_KIND_LABEL: Record<string, string> = {
  ci_pipeline: 'CI pipeline',
  scan: 'Daemon scan',
}

export interface CoverageFilters {
  filter?: CICoverageFilter
  expected?: boolean
  search?: string
  page?: number
  perPage?: number
}

/** GET /api/v1/ci/coverage with its filters; exported for tests. */
export function coverageURL(base: string, f: CoverageFilters = {}): string {
  const q = new URLSearchParams()
  if (f.filter) q.set('filter', f.filter)
  if (f.expected) q.set('expected', 'true')
  if (f.search) q.set('search', f.search)
  q.set('page', String(f.page ?? 1))
  q.set('per_page', String(f.perPage ?? 25))
  return `${base}/coverage?${q.toString()}`
}

/** A retirement reason the API accepts (10 to 2,000 characters). */
export function validRetireReason(reason: string): boolean {
  const n = [...reason.trim()].length
  return n >= 10 && n <= 2000
}
