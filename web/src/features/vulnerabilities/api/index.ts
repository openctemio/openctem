'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { get } from '@/lib/api/client'
import { handleApiError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import type { Vulnerability, VulnerabilityListFilters, VulnerabilityListResponse } from '../types'

const VULNERABILITIES_BASE = '/api/v1/vulnerabilities'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  shouldRetryOnError: (error) => {
    if (error?.statusCode >= 400 && error?.statusCode < 500) return false
    return true
  },
  errorRetryCount: 3,
  errorRetryInterval: 1000,
  dedupingInterval: 2000,
  onError: (error) => {
    handleApiError(error, { showToast: true, logError: true })
  },
}

function buildListEndpoint(filters?: VulnerabilityListFilters): string {
  if (!filters) return VULNERABILITIES_BASE

  const params = new URLSearchParams()

  if (filters.cve_ids?.length) params.set('cve_ids', filters.cve_ids.join(','))
  if (filters.severities?.length) params.set('severities', filters.severities.join(','))
  if (filters.statuses?.length) params.set('statuses', filters.statuses.join(','))
  if (filters.min_cvss !== undefined) params.set('min_cvss', String(filters.min_cvss))
  if (filters.max_cvss !== undefined) params.set('max_cvss', String(filters.max_cvss))
  if (filters.min_epss !== undefined) params.set('min_epss', String(filters.min_epss))
  if (filters.exploit_available !== undefined) {
    params.set('exploit_available', String(filters.exploit_available))
  }
  if (filters.cisa_kev_only !== undefined) {
    params.set('cisa_kev_only', String(filters.cisa_kev_only))
  }
  if (filters.page) params.set('page', String(filters.page))
  if (filters.per_page) params.set('per_page', String(filters.per_page))

  const qs = params.toString()
  return qs ? `${VULNERABILITIES_BASE}?${qs}` : VULNERABILITIES_BASE
}

async function fetchList(url: string): Promise<VulnerabilityListResponse> {
  return get<VulnerabilityListResponse>(url)
}

async function fetchOne(url: string): Promise<Vulnerability> {
  return get<Vulnerability>(url)
}

/**
 * Fetch the global CVE catalog. Not tenant-scoped.
 */
export function useVulnerabilities(filters?: VulnerabilityListFilters, config?: SWRConfiguration) {
  const { can } = usePermissions()
  const canRead = can(Permission.VulnerabilitiesRead)

  const key = canRead ? buildListEndpoint(filters) : null

  return useSWR<VulnerabilityListResponse>(key, fetchList, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Fetch a single vulnerability by its internal UUID.
 */
export function useVulnerability(id: string | null, config?: SWRConfiguration) {
  const { can } = usePermissions()
  const canRead = can(Permission.VulnerabilitiesRead)

  const key = canRead && id ? `${VULNERABILITIES_BASE}/${id}` : null

  return useSWR<Vulnerability>(key, fetchOne, { ...defaultConfig, ...config })
}

/**
 * Fetch a single vulnerability by CVE ID (e.g. "CVE-2024-1234").
 */
export function useVulnerabilityByCVE(cveId: string | null, config?: SWRConfiguration) {
  const { can } = usePermissions()
  const canRead = can(Permission.VulnerabilitiesRead)

  const key = canRead && cveId ? `${VULNERABILITIES_BASE}/cve/${cveId}` : null

  return useSWR<Vulnerability>(key, fetchOne, { ...defaultConfig, ...config })
}

// =============================================================================
// Affected assets reverse lookup (blast-radius)
// =============================================================================

export interface VulnerabilityAffectedAsset {
  asset_id: string
  asset_name: string
  asset_type: string
  criticality: string
  asset_status: string
  exposure: string
  risk_score: number
  is_internet_accessible: boolean

  finding_count: number
  open_finding_count: number
  highest_severity: string
  worst_sla_status?: string
  first_detected_at: string
  last_seen_at: string
  sample_finding_id: string
  sample_finding_status: string
}

export interface AffectedAssetsResponse {
  data: VulnerabilityAffectedAsset[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/**
 * List the assets in the current tenant affected by a CVE
 * (blast-radius reverse lookup). Backed by
 * GET /api/v1/vulnerabilities/{id}/affected-assets.
 *
 * Pass `null` for vulnId to skip fetching (e.g. sheet not yet on this tab).
 *
 * SWR cache key includes tenant.id to prevent cross-tenant cache leaks
 * (vulnerability IDs are global so the URL alone would collide).
 */
export function useAffectedAssets(
  vulnId: string | null,
  options?: { includeResolved?: boolean; page?: number; perPage?: number },
  config?: SWRConfiguration
) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const canRead = can(Permission.VulnerabilitiesRead)

  const params = new URLSearchParams()
  if (options?.includeResolved) params.set('include_resolved', 'true')
  if (options?.page) params.set('page', String(options.page))
  if (options?.perPage) params.set('per_page', String(options.perPage))
  const qs = params.toString()

  const url =
    canRead && vulnId && currentTenant
      ? `${VULNERABILITIES_BASE}/${vulnId}/affected-assets${qs ? `?${qs}` : ''}`
      : null
  // Keyed by the URL alone: a tenant switch drops every cached answer
  // (tenant-provider), so one key per endpoint cannot leak across tenants.
  const key = url

  return useSWR<AffectedAssetsResponse>(key, (u: string) => get<AffectedAssetsResponse>(u), {
    ...defaultConfig,
    ...config,
  })
}
