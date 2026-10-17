'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'

/** One severity tier of the findings score. */
export interface AssetRiskTier {
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
  exploitable: number
  effective: number
  score: number
}

/** GET /api/v1/assets/{id}/risk (docs/architecture/asset-risk-score.md). */
export interface AssetRiskExplanation {
  asset_id: string
  score: number
  level: 'critical' | 'high' | 'medium' | 'low' | 'minimal' | 'none'
  scored_at?: string
  pending: boolean
  breakdown: {
    model: string
    score: number
    findings_score: number
    tiers: AssetRiskTier[]
    exposure: string
    exposure_factor: number
    criticality: string
    effective_criticality: string
    crown_jewel: boolean
    criticality_factor: number
    control_reduction: number
  }
  contributors: Array<{
    finding_id: string
    title: string
    severity: string
    epss_score?: number
    in_kev: boolean
    exploit_available: boolean
  }>
  risk_levels: { critical_min: number; high_min: number; medium_min: number; low_min: number }
}

/** The explanation of an asset's risk score; fetched only when enabled. */
export function useAssetRisk(assetId: string | null, enabled = true) {
  const { can } = usePermissions()
  const key =
    enabled && assetId && can(Permission.AssetsRead) ? `/api/v1/assets/${assetId}/risk` : null
  const { data, error, isLoading, mutate } = useSWR<AssetRiskExplanation>(key, get, {
    revalidateOnFocus: false,
  })
  return { data, error, isLoading, mutate }
}
