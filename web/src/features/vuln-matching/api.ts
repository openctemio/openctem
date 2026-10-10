'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { get, put } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type { AssetSoftwareListResponse } from '@/lib/api/generated'
import type { VulnMatchingSettings } from './types'

export const VULN_MATCHING_SETTINGS_ENDPOINT = '/api/v1/organization/settings/vuln-matching'

export function assetSoftwareEndpoint(assetId: string): string {
  return `/api/v1/assets/${encodeURIComponent(assetId)}/software`
}

const quietConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

/**
 * The software an asset runs with the CVEs its versions fall in. The API
 * answers 404 for an asset outside the caller's data scope.
 */
export function useAssetSoftware(assetId: string | null | undefined, config?: SWRConfiguration) {
  return useSWR<AssetSoftwareListResponse>(
    assetId ? assetSoftwareEndpoint(assetId) : null,
    (url: string) => get<AssetSoftwareListResponse>(url),
    { ...quietConfig, ...config }
  )
}

/** The organization's vulnerability matching policy (owners and admins). */
export function useVulnMatchingSettings(config?: SWRConfiguration) {
  const { can } = usePermissions()
  const key = can(Permission.TeamUpdate) ? VULN_MATCHING_SETTINGS_ENDPOINT : null
  return useSWR<VulnMatchingSettings>(key, (url: string) => get<VulnMatchingSettings>(url), {
    ...quietConfig,
    ...config,
  })
}

/**
 * Saves the policy. etag is the section's tag from the organization
 * settings read; with it the API refuses (409 SETTINGS_CONFLICT) a save over
 * a change someone else made since.
 */
export async function updateVulnMatchingSettings(
  payload: VulnMatchingSettings,
  etag?: string
): Promise<VulnMatchingSettings> {
  return put<VulnMatchingSettings>(VULN_MATCHING_SETTINGS_ENDPOINT, payload, {
    headers: etag ? { 'If-Match': etag } : undefined,
  })
}
