'use client'

import useSWR from 'swr'
import { useTenant } from '@/context/tenant-provider'
import { get } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'

// ============================================
// API Response Types (snake_case from backend)
// ============================================

interface AssetTypeBreakdownResponse {
  type: string
  total: number
  exposed: number
}

interface ExposedServiceResponse {
  id: string
  name: string
  type: string
  port?: number
  exposure: string
  criticality: string
  finding_count: number
  last_seen: string
}

interface AssetChangeResponse {
  type: string
  asset_name: string
  asset_type: string
  timestamp: string
}

interface AttackSurfaceStatsResponse {
  total_assets: number
  internet_facing_assets: number
  critical_internet_facing_assets: number
  risk_score: number
  total_assets_change: number
  newly_exposed: number
  trend_window_days?: number
  asset_breakdown: AssetTypeBreakdownResponse[]
  exposed_services_list: ExposedServiceResponse[]
  recent_changes: AssetChangeResponse[]
}

// ============================================
// Frontend Types (camelCase)
// ============================================

export interface AssetTypeBreakdown {
  type: string
  total: number
  exposed: number
}

export interface ExposedService {
  id: string
  name: string
  type: string
  port?: number
  exposure: string
  criticality: string
  findingCount: number
  lastSeen: string
}

export interface AssetChange {
  type: 'added' | 'removed' | 'changed'
  assetName: string
  assetType: string
  timestamp: string
}

export interface AttackSurfaceStats {
  totalAssets: number
  /** Internet-facing assets (exposure public or reported reachable). */
  internetFacingAssets: number
  /** The same, limited to critical/high criticality. A population, not a problem count. */
  criticalInternetFacingAssets: number
  riskScore: number
  /** Assets added in the last `trendWindowDays` days (never negative). */
  totalAssetsChange: number
  /** "Became internet-facing" changes in the window: the same number as
   * Assets > What changed > Newly exposed. */
  newlyExposed: number
  trendWindowDays: number
  assetBreakdown: AssetTypeBreakdown[]
  exposedServicesList: ExposedService[]
  recentChanges: AssetChange[]
}

// ============================================
// Transform API response to frontend format
// ============================================

function transformResponse(data: AttackSurfaceStatsResponse): AttackSurfaceStats {
  return {
    totalAssets: data.total_assets,
    internetFacingAssets: data.internet_facing_assets,
    criticalInternetFacingAssets: data.critical_internet_facing_assets,
    riskScore: data.risk_score,
    totalAssetsChange: data.total_assets_change,
    newlyExposed: data.newly_exposed,
    trendWindowDays: data.trend_window_days ?? 7,
    assetBreakdown:
      data.asset_breakdown?.map((item) => ({
        type: item.type,
        total: item.total,
        exposed: item.exposed,
      })) || [],
    exposedServicesList:
      data.exposed_services_list?.map((item) => ({
        id: item.id,
        name: item.name,
        type: item.type,
        port: item.port,
        exposure: item.exposure,
        criticality: item.criticality,
        findingCount: item.finding_count,
        lastSeen: item.last_seen,
      })) || [],
    recentChanges:
      data.recent_changes?.map((item) => ({
        type: item.type as 'added' | 'removed' | 'changed',
        assetName: item.asset_name,
        assetType: item.asset_type,
        timestamp: item.timestamp,
      })) || [],
  }
}

// ============================================
// SWR Fetcher
// ============================================

async function fetchAttackSurfaceStats(url: string): Promise<AttackSurfaceStats> {
  const data = await get<AttackSurfaceStatsResponse>(url)
  return transformResponse(data)
}

// ============================================
// Hook
// ============================================

export function useAttackSurfaceStats() {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const canReadAssets = can(Permission.AssetsRead)

  // Only fetch if user has permission
  const shouldFetch = currentTenant && canReadAssets

  const key = shouldFetch ? '/api/v1/attack-surface/stats' : null

  const { data, error, isLoading, mutate } = useSWR<AttackSurfaceStats>(
    key,
    fetchAttackSurfaceStats,
    {
      revalidateOnFocus: false,
      revalidateIfStale: true,
      dedupingInterval: 30000, // Cache for 30 seconds
    }
  )

  return {
    stats: data,
    error,
    isLoading: shouldFetch ? isLoading : false,
    mutate,
  }
}
