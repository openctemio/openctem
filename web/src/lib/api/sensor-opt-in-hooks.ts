/**
 * Sensor opt-ins (api research/25 D3): the organization's switches for
 * out-of-band callbacks (interactsh) and custom templates in sensor jobs,
 * off unless an owner enabled them, and the scans affected while they are
 * off. Backed by GET /api/v1/scans/sensor-opt-in-impact (scans:read).
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'

import { get } from './client'

export interface SensorOptIns {
  allow_interactsh: boolean
  allow_custom_templates: boolean
}

export interface SensorOptInImpactScan {
  id: string
  name: string
  status: string
  uses_interactsh: boolean
  uses_custom_templates: boolean
}

export interface SensorOptInImpact {
  opt_ins: SensorOptIns
  scans: SensorOptInImpactScan[]
  truncated: boolean
}

export const SENSOR_OPT_IN_IMPACT_PATH = '/api/v1/scans/sensor-opt-in-impact'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  // Advisory data: one attempt, then hide quietly.
  shouldRetryOnError: false,
  keepPreviousData: true,
}

/** The opt-ins and the scans they affect, for the current organization. */
export function useSensorOptInImpact(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  return useSWR<SensorOptInImpact>(
    currentTenant ? SENSOR_OPT_IN_IMPACT_PATH : null,
    (url: string) => get<SensorOptInImpact>(url),
    { ...defaultConfig, ...config }
  )
}

/**
 * The scans a banner must name: those that ask for an opt-in that is off.
 * A scan that asks only for enabled opt-ins is not affected.
 */
export function affectedScans(impact?: SensorOptInImpact | null): SensorOptInImpactScan[] {
  if (!impact) return []
  const { allow_interactsh: interactsh, allow_custom_templates: templates } = impact.opt_ins
  return impact.scans.filter(
    (s) => (s.uses_interactsh && !interactsh) || (s.uses_custom_templates && !templates)
  )
}
