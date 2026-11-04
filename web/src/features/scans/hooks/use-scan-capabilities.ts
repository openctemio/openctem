'use client'

/**
 * What the organization may scan (GET /api/v1/scans/capabilities,
 * scans:read; the organization comes from the credential). The wizard offers
 * only passive intensity, and so only passive tools and workflows, to a
 * passive-only organization. Advice only: the API refuses a scan above
 * passive for such an organization whatever the console sends. While the
 * answer is unknown (loading, error, no access) nothing is hidden.
 */

import useSWR from 'swr'
import { fetcher } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { ScanCapabilitiesResponse } from '@/lib/api/generated'

export const SCAN_CAPABILITIES_URL = '/api/v1/scans/capabilities'

export function useScanCapabilities(enabled = true) {
  const { currentTenant } = useTenant()
  const { data } = useSWR<ScanCapabilitiesResponse>(
    enabled && currentTenant ? [SCAN_CAPABILITIES_URL, currentTenant.id] : null,
    ([url]: [string, string]) => fetcher<ScanCapabilitiesResponse>(url),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
  return { passiveOnly: data?.active_scanning === false }
}
