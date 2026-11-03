'use client'

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  DISCOVERY_URL,
  stageRunUrl,
  type DiscoveryAbortResult,
  type DiscoveryOverview,
  type DiscoveryRunResult,
  type DiscoveryStage,
} from '../lib/discovery'

const swrConfig = {
  revalidateOnFocus: true,
  shouldRetryOnError: (error: { statusCode?: number }) =>
    !((error?.statusCode ?? 0) >= 400 && (error?.statusCode ?? 0) < 500),
}

/**
 * GET /api/v1/attack-surface/discovery: the coverage work by stage.
 * Fetched only with scans:read; the API also refuses (403) a caller whose
 * data scope is restricted.
 */
export function useEASMDiscovery() {
  const { can } = usePermissions()
  const enabled = can(Permission.ScansRead)
  const { data, error, isLoading, isValidating, mutate } = useSWR<DiscoveryOverview>(
    enabled ? DISCOVERY_URL : null,
    (u: string) => get<DiscoveryOverview>(u),
    swrConfig
  )
  return { overview: data, error, isLoading, isValidating, mutate, enabled }
}

/** POST .../stages/{stage}/run (scans:write + scans:execute; 429 within a minute). */
export function runDiscoveryStage(stage: DiscoveryStage) {
  return post<DiscoveryRunResult>(stageRunUrl(stage), {})
}

/** POST .../run: every stage; stages run within the minute are skipped. */
export function runAllDiscovery() {
  return post<DiscoveryRunResult>(`${DISCOVERY_URL}/run`, {})
}

/** POST .../cancel (scans:write): cancels the organization's coverage runs. */
export function abortAllDiscovery() {
  return post<DiscoveryAbortResult>(`${DISCOVERY_URL}/cancel`, {})
}
