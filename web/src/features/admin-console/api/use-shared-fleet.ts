'use client'

/**
 * Console > System > Shared sensors (api docs/rfcs/RFC-100-shared-sensors.md
 * §12): the instance sensors, queue aggregates, job metadata, the audited job
 * view and the remote actions. Job rows carry metadata only; a job's targets
 * and logs come from viewSharedJob, which the API audits with the reason.
 */

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'

export interface SharedFleetSensor {
  id: string
  name: string
  region: string
  status: string
  health: string
  version: string
  tools: string[]
  current_jobs: number
  max_jobs: number
  last_seen_at?: string
  created_at: string
}

export interface SharedQueueLane {
  tool: string
  queued: number
  running: number
}

export interface SharedOrgUsage {
  tenant_id: string
  /** Super and operations administrators only. */
  tenant_name?: string
  queued: number
  running: number
  completed_24h: number
  failed_24h: number
}

export interface SharedQueue {
  lanes: SharedQueueLane[]
  organizations: SharedOrgUsage[]
}

export interface SharedJob {
  id: string
  tenant_id: string
  /** Super and operations administrators only. */
  tenant_name?: string
  type: string
  tool: string
  status: string
  sensor_id?: string
  sensor_name?: string
  created_at: string
  started_at?: string
  completed_at?: string
}

export interface SharedJobPage {
  data: SharedJob[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface SharedJobDetail {
  job: SharedJob
  targets: string[]
  logs: { ts: string; level: string; msg: string; source?: string }[]
  logs_truncated: boolean
}

export type SharedSensorAction = 'pause' | 'resume' | 'retire'

/** The fleet (any administrator). */
export function useSharedFleet() {
  return useSWR<{ sensors: SharedFleetSensor[] }>('/shared-sensors', adminFetcher, {
    refreshInterval: 30_000,
  })
}

/** Queue aggregates (any administrator). */
export function useSharedQueue() {
  return useSWR<SharedQueue>('/shared-sensors/queue', adminFetcher, { refreshInterval: 30_000 })
}

/** Job metadata, newest first (any administrator). */
export function useSharedJobs(page: number, status: string) {
  const q = new URLSearchParams({ page: String(page), per_page: '20' })
  if (status) q.set('status', status)
  return useSWR<SharedJobPage>(`/shared-sensors/jobs?${q.toString()}`, adminFetcher)
}

/** A job's targets and logs (super or ops admin, reason; audited). */
export function viewSharedJob(id: string, reason: string) {
  return adminFetch<SharedJobDetail>(`/shared-sensors/jobs/${encodeURIComponent(id)}/view`, {
    method: 'POST',
    body: { reason },
  })
}

/** Pause, resume or retire a shared sensor (super admin, reason, fresh code). */
export function actOnSharedSensor(
  id: string,
  action: SharedSensorAction,
  proof: { reason: string; totp_code?: string }
) {
  return adminFetch<void>(`/shared-sensors/${encodeURIComponent(id)}/${action}`, {
    method: 'POST',
    body: proof,
  })
}
