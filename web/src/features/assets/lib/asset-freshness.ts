/**
 * Asset data freshness (RFC-075): when each enrichable attribute class of an
 * asset was last observed, and whether it is live, stale, dead or never
 * observed. Mirrors GET /api/v1/assets/{id}/freshness.
 */

export type FreshnessState = 'live' | 'stale' | 'dead' | 'never'

export type FreshnessClass = 'dns' | 'registration' | 'network_owner' | 'http' | 'tls' | 'ports'

export interface FreshnessClassView {
  class: FreshnessClass
  state: FreshnessState
  observed_at?: string
  source?: string
  ttl_seconds: number
  passive: boolean
  due_at?: string
}

export interface EnrichmentRequest {
  reason: 'new_asset' | 'stale' | 'change' | 'manual'
  requested_at: string
  dispatched_at?: string
  outcome?: string
  last_run_id?: string
}

/** Whether a host name resolves (GET /assets/{id}/freshness, `resolution`). */
export interface AssetResolution {
  state: 'resolving' | 'not_resolving'
  resolved_at?: string
  checked_at: string
  failures: number
  source?: string
}

export interface AssetFreshness {
  resolution?: AssetResolution
  state: FreshnessState
  classes: FreshnessClassView[]
  next_due_at?: string
  enrichment?: EnrichmentRequest
}

/** Badge variant per state. */
export const FRESHNESS_BADGE: Record<
  FreshnessState,
  'default' | 'secondary' | 'destructive' | 'outline'
> = {
  live: 'default',
  stale: 'secondary',
  dead: 'destructive',
  never: 'outline',
}

/** A TTL in seconds as hours or days, for the i18n templates. */
export function ttlParts(seconds: number): { key: 'hours' | 'days'; n: number } {
  const hours = Math.round(seconds / 3600)
  if (hours < 48) return { key: 'hours', n: hours }
  return { key: 'days', n: Math.round(hours / 24) }
}

/** The enrichment line key: queued, dispatched (with a run), or another outcome. */
export function enrichmentStatus(e: EnrichmentRequest): string {
  if (!e.dispatched_at) return 'queued'
  return e.outcome || 'claimed'
}
