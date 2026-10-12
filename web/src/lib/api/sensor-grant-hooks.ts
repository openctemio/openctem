/**
 * Per-sensor grants (api docs/rfcs/RFC-052 §5): what one sensor may do,
 * enforced by the platform on every poll, claim and unsolicited result.
 *
 * A null list means "no limit from the grant" on that dimension; an empty
 * list means "nothing". The UI keeps that difference: null shows as "Any",
 * [] as "None".
 *
 * Reads need sensors:read. A change needs sensors:grant:narrow when every
 * dimension stays equal or narrower and sensors:grant:widen otherwise; the
 * server decides which and answers 403 with its reason. Writes carry the
 * version read; a stale one answers 409.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'

import { get, put } from './client'

export type TrustLevel = 'new' | 'trusted'
export type TargetNetwork = 'any' | 'public' | 'none'

export interface SensorGrantEffective {
  tier_ceiling: number
  allow_credentials: boolean
  allow_push_ingest: boolean
}

export interface SensorGrant {
  sensor_id: string
  profile: string
  legacy_broad: boolean
  trust_level: TrustLevel | (string & {})
  job_types: string[] | null
  zone_ids: string[] | null
  tools: string[] | null
  capabilities: string[] | null
  tier_ceiling: number
  target_network: TargetNetwork | (string & {})
  target_cidrs: string[] | null
  target_domains: string[] | null
  allow_credentials: boolean
  allow_push_ingest: boolean
  remote_actions: string[] | null
  version: number
  updated_at?: string
  /** What applies now, after the trust level (New: T0, no credentials, no push). */
  effective?: SensorGrantEffective
}

export interface SensorGrantProfile {
  name: string
  job_types: string[] | null
  tier_ceiling: number
  target_network: string
  allow_credentials: boolean
  allow_push_ingest: boolean
  default: boolean
  /** collector:<integration> */
  parameterised: boolean
}

export interface SensorGrantSummary {
  sensor_id: string
  profile: string
  trust_level: string
  legacy_broad: boolean
}

/** Full replacement of a grant (with the version read). */
export interface UpdateSensorGrantRequest {
  version: number
  trust_level?: TrustLevel
  job_types: string[] | null
  zone_ids: string[] | null
  tools: string[] | null
  capabilities: string[] | null
  tier_ceiling: number
  target_network: TargetNetwork
  target_cidrs: string[] | null
  target_domains: string[] | null
  allow_credentials: boolean
  allow_push_ingest: boolean
  remote_actions: string[] | null
}

/** Rebuild a grant from a profile (zone_ids: the zones a zone-bound profile keeps to). */
export interface ApplyProfileRequest {
  version: number
  profile: string
  trust_level?: TrustLevel
  zone_ids?: string[] | null
}

export const SENSOR_GRANT_PROFILES_PATH = '/api/v1/sensors/grant-profiles'
export const SENSOR_GRANT_SUMMARIES_PATH = '/api/v1/sensors/grant-summaries'
export const sensorGrantPath = (id: string) => `/api/v1/sensors/${encodeURIComponent(id)}/grant`

const config: SWRConfiguration = { revalidateOnFocus: false, shouldRetryOnError: false }

export function useSensorGrant(sensorId: string | null, enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<SensorGrant>(
    currentTenant && sensorId && enabled ? sensorGrantPath(sensorId) : null,
    (url: string) => get<SensorGrant>(url),
    config
  )
}

export function useSensorGrantProfiles(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<{ profiles: SensorGrantProfile[] }>(
    currentTenant && enabled ? SENSOR_GRANT_PROFILES_PATH : null,
    (url: string) => get<{ profiles: SensorGrantProfile[] }>(url),
    { ...config, dedupingInterval: 60_000 }
  )
}

export function useSensorGrantSummaries(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<{ data: SensorGrantSummary[] }>(
    currentTenant && enabled ? SENSOR_GRANT_SUMMARIES_PATH : null,
    (url: string) => get<{ data: SensorGrantSummary[] }>(url),
    config
  )
}

export function updateSensorGrant(
  sensorId: string,
  body: UpdateSensorGrantRequest | ApplyProfileRequest
): Promise<SensorGrant> {
  return put<SensorGrant>(sensorGrantPath(sensorId), body)
}

/** The request that replaces `g` with itself plus `changes` (full replacement). */
export function grantUpdateRequest(
  g: SensorGrant,
  changes: Partial<UpdateSensorGrantRequest> = {}
): UpdateSensorGrantRequest {
  return {
    version: g.version,
    trust_level: g.trust_level === 'trusted' ? 'trusted' : 'new',
    job_types: g.job_types,
    zone_ids: g.zone_ids,
    tools: g.tools,
    capabilities: g.capabilities,
    tier_ceiling: g.tier_ceiling,
    target_network: (['any', 'public', 'none'].includes(g.target_network)
      ? g.target_network
      : 'any') as TargetNetwork,
    target_cidrs: g.target_cidrs,
    target_domains: g.target_domains,
    allow_credentials: g.allow_credentials,
    allow_push_ingest: g.allow_push_ingest,
    remote_actions: g.remote_actions,
    ...changes,
  }
}
