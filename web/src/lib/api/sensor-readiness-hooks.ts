/**
 * The readiness checklist of a sensor (GET /api/v1/sensors/{id}/readiness,
 * sensors:read): what still stops it from scanning, in fix order, each item
 * with the action that fixes it and whether the viewer may take it. Reads
 * only. The API decides everything; the console only shows it.
 */

'use client'

import useSWR from 'swr'

import { useTenant } from '@/context/tenant-provider'

import { get } from './client'

export type ReadinessKey =
  'online' | 'trusted' | 'private_targets' | 'kill_switch' | 'networks' | 'scope' | 'sandbox'

export type ReadinessState = 'ok' | 'blocked' | 'waiting' | 'unknown' | 'not_applicable'

export type ReadinessAction =
  | 'show_install'
  | 'promote'
  | 'enable_private'
  | 'kill_switch_off'
  | 'add_zone'
  | 'add_scope'
  | 'sandbox_docs'

export interface ReadinessFix {
  action: ReadinessAction
  permission?: string
  allowed: boolean
  patterns?: string[]
  host_line?: string
  docs?: string
}

export interface ReadinessItem {
  key: ReadinessKey
  state: ReadinessState
  count?: number
  fix?: ReadinessFix
}

export interface SensorReadiness {
  sensor_id: string
  ready: boolean
  items: ReadinessItem[]
}

/** How often an open checklist refreshes while something is not ready. */
export const READINESS_POLL_MS = 10_000

/** Module scope: SWR restarts its timer when the interval changes identity. */
function readinessInterval(latest?: SensorReadiness): number {
  return latest?.ready ? 0 : READINESS_POLL_MS
}

export function sensorReadinessPath(sensorId: string): string {
  return `/api/v1/sensors/${encodeURIComponent(sensorId)}/readiness`
}

export function useSensorReadiness(sensorId: string | null) {
  const { currentTenant } = useTenant()
  return useSWR<SensorReadiness>(
    currentTenant && sensorId ? sensorReadinessPath(sensorId) : null,
    (url: string) => get<SensorReadiness>(url),
    { revalidateOnFocus: true, shouldRetryOnError: false, refreshInterval: readinessInterval }
  )
}
