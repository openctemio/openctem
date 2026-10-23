import type { AssetSearchFilters } from '@/features/assets'
import type { RiskLevelThresholds } from '@/features/shared/types'

/** Risk bands of the external surface filter, from the tenant's thresholds. */
export type RiskBand = 'critical' | 'high' | 'medium' | 'low'

/**
 * Risk-score range for a band, using the tenant's risk-level thresholds (the
 * same ones RiskScoreBadge colours by), so "Critical" in the filter and the
 * badge in the row always agree.
 */
export function riskRange(
  band: RiskBand,
  t: RiskLevelThresholds
): Pick<AssetSearchFilters, 'minRiskScore' | 'maxRiskScore'> {
  switch (band) {
    case 'critical':
      return { minRiskScore: t.critical_min }
    case 'high':
      return { minRiskScore: t.high_min, maxRiskScore: t.critical_min - 1 }
    case 'medium':
      return { minRiskScore: t.medium_min, maxRiskScore: t.high_min - 1 }
    case 'low':
      return { maxRiskScore: t.medium_min - 1 }
  }
}

/** The attribution population the attack-surface stats count. */
export const STATS_ATTRIBUTION = 'attributed'

export interface ExternalSurfaceView {
  search?: string
  type?: string // 'all' or an asset type
  risk?: RiskBand | 'all'
  withFindings?: boolean
}

/**
 * Server filters for the external attack surface: every internet-facing
 * asset (exposure public or reported reachable, the API's one definition).
 * This is the same population, with the same attribution, as the overview's
 * "Internet-facing assets" tile and exposed list, so the numbers and the
 * lists they open agree.
 */
export function externalSurfaceFilters(
  view: ExternalSurfaceView,
  t: RiskLevelThresholds
): AssetSearchFilters {
  // Attributed assets only (research/22 P0-12): a name a person rejected, or
  // one still waiting for review, is not part of the organization's surface.
  // This is the population the attack-surface stats count.
  const f: AssetSearchFilters = { isInternetFacing: true, attribution: [STATS_ATTRIBUTION] }
  if (view.search) f.search = view.search
  if (view.type && view.type !== 'all') f.types = [view.type as never]
  if (view.risk && view.risk !== 'all') Object.assign(f, riskRange(view.risk, t))
  if (view.withFindings) f.hasFindings = true
  return f
}
