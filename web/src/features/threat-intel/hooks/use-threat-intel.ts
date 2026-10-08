'use client'

import useSWR from 'swr'
import { get, post, patch } from '@/lib/api/client'
import { threatIntelEndpoints } from '@/lib/api/endpoints'
import { usePermissions, Permission } from '@/lib/permissions'
import type {
  SyncStatus,
  EPSSScore,
  EPSSStats,
  KEVEntry,
  KEVStats,
  CVEEnrichment,
  ThreatIntelSource,
  SetSyncEnabledRequest,
  ThreatIntelStats,
} from '@/lib/api/threatintel-types'

// ============================================
// UNIFIED STATS HOOK (RECOMMENDED)
// ============================================

/**
 * Hook to fetch unified threat intel stats (EPSS + KEV + sync status)
 * This is the recommended hook - single API call for all data
 * Only fetches if user has vulnerabilities:read permission
 */
export function useThreatIntelStats(tenantId: string | null) {
  const { can } = usePermissions()
  const canReadVulns = can(Permission.VulnerabilitiesRead)

  // Only fetch if user has permission
  const shouldFetch = tenantId && canReadVulns

  const { data, error, isLoading, mutate } = useSWR<ThreatIntelStats>(
    // The endpoint URL: shared with every other reader (the dashboard).
    shouldFetch ? threatIntelEndpoints.stats() : null,
    (url: string) => get<ThreatIntelStats>(url),
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000,
    }
  )

  const emptyEPSS: EPSSStats = {
    total_scores: 0,
    high_risk_count: 0,
    critical_risk_count: 0,
  }

  const emptyKEV: KEVStats = {
    total_entries: 0,
    past_due_count: 0,
    recently_added_last_30_days: 0,
    ransomware_related_count: 0,
  }

  return {
    stats: data || null,
    epssStats: data?.epss || emptyEPSS,
    kevStats: data?.kev || emptyKEV,
    syncStatuses: data?.sync_statuses || [],
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}

// ============================================
// SYNC STATUS HOOKS
// ============================================

/**
 * Hook to fetch all sync statuses
 * Only fetches if user has vulnerabilities:read permission
 */
export function useSyncStatuses(tenantId: string | null) {
  const { can } = usePermissions()
  const canReadVulns = can(Permission.VulnerabilitiesRead)

  // Only fetch if user has permission
  const shouldFetch = tenantId && canReadVulns

  const { data, error, isLoading, mutate } = useSWR<SyncStatus[]>(
    shouldFetch ? threatIntelEndpoints.syncStatuses() : null,
    async (url: string) => {
      try {
        return await get<SyncStatus[]>(url)
      } catch (err: unknown) {
        // 404 means no sync status exists yet - return empty array
        if (
          err &&
          typeof err === 'object' &&
          'statusCode' in err &&
          (err as { statusCode: number }).statusCode === 404
        ) {
          return []
        }
        throw err
      }
    },
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000,
    }
  )

  return {
    statuses: data || [],
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}

/**
 * Hook to fetch sync status for a specific source
 * Only fetches if user has vulnerabilities:read permission
 */
export function useSyncStatus(tenantId: string | null, source: ThreatIntelSource) {
  const { can } = usePermissions()
  const canReadVulns = can(Permission.VulnerabilitiesRead)

  // Only fetch if user has permission
  const shouldFetch = tenantId && canReadVulns

  const { data, error, isLoading, mutate } = useSWR<SyncStatus>(
    shouldFetch ? threatIntelEndpoints.syncStatus(source) : null,
    (url: string) => get<SyncStatus>(url),
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000,
    }
  )

  return {
    status: data || null,
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}

/**
 * Trigger sync for a source
 */
export async function triggerSync(source: ThreatIntelSource): Promise<SyncStatus> {
  // Source travels in the body; the API is POST /sync (no per-source path).
  return post<SyncStatus>(threatIntelEndpoints.triggerSync(), { source })
}

/**
 * Enable/disable sync for a source
 */
export async function setSyncEnabled(
  source: ThreatIntelSource,
  enabled: boolean
): Promise<SyncStatus> {
  return patch<SyncStatus>(threatIntelEndpoints.setSyncEnabled(source), {
    enabled,
  } as SetSyncEnabledRequest)
}

// ============================================
// EPSS HOOKS
// ============================================

/**
 * Hook to fetch EPSS score for a CVE
 * Only fetches if user has vulnerabilities:read permission
 */
export function useEPSSScore(tenantId: string | null, cveId: string | null) {
  const { can } = usePermissions()
  const canReadVulns = can(Permission.VulnerabilitiesRead)

  // Only fetch if user has permission
  const shouldFetch = tenantId && cveId && canReadVulns

  const { data, error, isLoading, mutate } = useSWR<EPSSScore>(
    shouldFetch ? threatIntelEndpoints.epssScore(cveId!) : null,
    (url: string) => get<EPSSScore>(url),
    {
      revalidateOnFocus: false,
    }
  )

  return {
    epss: data || null,
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}

/**
 * Hook to fetch EPSS statistics
 * Only fetches if user has vulnerabilities:read permission
 */
export function useEPSSStats(tenantId: string | null) {
  const { can } = usePermissions()
  const canReadVulns = can(Permission.VulnerabilitiesRead)

  // Only fetch if user has permission
  const shouldFetch = tenantId && canReadVulns

  const { data, error, isLoading, mutate } = useSWR<EPSSStats>(
    shouldFetch ? threatIntelEndpoints.epssStats() : null,
    (url: string) => get<EPSSStats>(url),
    {
      revalidateOnFocus: false,
      dedupingInterval: 60000,
    }
  )

  const emptyStats: EPSSStats = {
    total_scores: 0,
    high_risk_count: 0,
    critical_risk_count: 0,
  }

  return {
    stats: data || emptyStats,
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}

// ============================================
// KEV HOOKS
// ============================================

/**
 * Hook to fetch KEV entry for a CVE
 * Only fetches if user has vulnerabilities:read permission
 */
export function useKEVEntry(tenantId: string | null, cveId: string | null) {
  const { can } = usePermissions()
  const canReadVulns = can(Permission.VulnerabilitiesRead)

  // Only fetch if user has permission
  const shouldFetch = tenantId && cveId && canReadVulns

  const { data, error, isLoading, mutate } = useSWR<KEVEntry>(
    shouldFetch ? threatIntelEndpoints.kevEntry(cveId!) : null,
    (url: string) => get<KEVEntry>(url),
    {
      revalidateOnFocus: false,
    }
  )

  return {
    kev: data || null,
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}

/**
 * Hook to fetch KEV statistics
 * Only fetches if user has vulnerabilities:read permission
 */
export function useKEVStats(tenantId: string | null) {
  const { can } = usePermissions()
  const canReadVulns = can(Permission.VulnerabilitiesRead)

  // Only fetch if user has permission
  const shouldFetch = tenantId && canReadVulns

  const { data, error, isLoading, mutate } = useSWR<KEVStats>(
    shouldFetch ? threatIntelEndpoints.kevStats() : null,
    (url: string) => get<KEVStats>(url),
    {
      revalidateOnFocus: false,
      dedupingInterval: 60000,
    }
  )

  const emptyStats: KEVStats = {
    total_entries: 0,
    past_due_count: 0,
    recently_added_last_30_days: 0,
    ransomware_related_count: 0,
  }

  return {
    stats: data || emptyStats,
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}

// ============================================
// ENRICHMENT FUNCTIONS
// ============================================

/**
 * Enrich a single CVE with threat intel
 */
export async function enrichCVE(cveId: string): Promise<CVEEnrichment> {
  return get<CVEEnrichment>(threatIntelEndpoints.enrichCVE(cveId))
}

// ============================================
// COMBINED HOOKS
// ============================================

/**
 * Hook to fetch CVE enrichment data (EPSS + KEV)
 * Only fetches if user has vulnerabilities:read permission
 */
export function useCVEEnrichment(tenantId: string | null, cveId: string | null) {
  const { can } = usePermissions()
  const canReadVulns = can(Permission.VulnerabilitiesRead)

  // Only fetch if user has permission
  const shouldFetch = tenantId && cveId && canReadVulns

  const { data, error, isLoading, mutate } = useSWR<CVEEnrichment>(
    shouldFetch ? threatIntelEndpoints.enrichCVE(cveId!) : null,
    (url: string) => get<CVEEnrichment>(url),
    {
      revalidateOnFocus: false,
    }
  )

  return {
    enrichment: data || null,
    epss: data?.epss || null,
    kev: data?.kev || null,
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}
