/**
 * Finding identity explanation hook
 *
 * Read-only SWR hook for
 *   GET /api/v1/findings/{id}/identity
 *
 * Why a finding is one finding: the recipe of its key, the NAMES of the
 * fields the key was built from, the tools that reported it and the
 * duplicates merged into it that the caller may see. The response never
 * carries a key, fingerprint or field value. A 403/404 means "not shown"
 * (no retry, no toast).
 *
 * Response shape mirrors `handler.FindingIdentityResponse`.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { get } from '@/lib/api/client'
import { handleApiError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'

export interface FindingIdentitySource {
  tool: string
  last_seen_at?: string
}

export interface FindingIdentityMerged {
  id: string
  tool_name: string
  merged_at: string
  /** manual, asset_merge, refingerprint, dast_identity_repair, … ("" when unknown). */
  reason: string
}

export interface FindingIdentity {
  /** "v2/sca", "v1/ingest", "manual/v1", "pentest/v1"; "" when unknown. */
  algo: string
  version: number
  /** Field names in recipe order. */
  fields: string[]
  /** Read from the stored identity tuple (keyed before recipes were recorded). */
  derived: boolean
  /** A version-1 key with no recorded recipe. */
  legacy: boolean
  sources: FindingIdentitySource[]
  merged: FindingIdentityMerged[]
}

const config: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
  dedupingInterval: 5000,
  onError: (error) => {
    handleApiError(error, { showToast: false, logError: true })
  },
}

export function useFindingIdentity(
  findingId: string | null | undefined,
  swrConfig?: SWRConfiguration
) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? `/api/v1/findings/${findingId}/identity` : null
  const { data, error, isLoading, mutate } = useSWR<FindingIdentity>(
    key,
    (url: string) => get<FindingIdentity>(url),
    { ...config, ...swrConfig }
  )
  return { identity: data ?? null, isLoading, error, mutate }
}
