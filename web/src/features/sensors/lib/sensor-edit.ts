/**
 * The edit-sensor form: what an administrator can change on a sensor and the
 * PUT /api/v1/sensors/{id} body it becomes. The update API accepts name,
 * description, status, capabilities and max_concurrent_jobs. Capabilities
 * and the job count are limits that narrow what the sensor reports (api
 * RFC-029 §4.3.1). The tools are the ones the sensor reports; the sensor
 * grant narrows them. Execution mode is not accepted by the update API; it
 * is fixed when the sensor is created.
 */

import type { Sensor, UpdateSensorRequest } from '@/lib/api/sensor-types'

export interface SensorEditDraft {
  name: string
  description: string
  /** Active (true) or disabled (false). Revoking is a separate action. */
  enabled: boolean
  /** The concurrency limit as typed. */
  maxJobs: string
  /** The scan zones the sensor belongs to (sorted). */
  zoneIds: string[]
}

export const MAX_JOBS_LIMIT = 100

/** The installed tools the sensor reports, sorted; null before its first report. */
export function reportedToolNames(sensor: Pick<Sensor, 'reported'>): string[] | null {
  const tools = sensor.reported?.tools
  if (!Array.isArray(tools)) return null
  return [...new Set(tools.filter((t) => t.installed).map((t) => t.name))].sort()
}

/** The form's starting values for a sensor and the zones it is in. */
export function sensorEditDraft(
  sensor: Pick<Sensor, 'name' | 'description' | 'status' | 'max_concurrent_jobs'>,
  zoneIds: string[] = []
): SensorEditDraft {
  return {
    name: sensor.name,
    description: sensor.description ?? '',
    enabled: sensor.status === 'active',
    maxJobs: sensor.max_concurrent_jobs ? String(sensor.max_concurrent_jobs) : '',
    zoneIds: [...zoneIds].sort(),
  }
}

const sameList = (a: string[], b: string[]) =>
  a.length === b.length && [...a].sort().every((v, i) => v === [...b].sort()[i])

export interface SensorEditErrors {
  name?: string
  description?: string
  maxJobs?: string
}

export function validateSensorEdit(draft: SensorEditDraft, initial: SensorEditDraft) {
  const errors: SensorEditErrors = {}
  const name = draft.name.trim()
  if (!name) errors.name = 'Enter a name.'
  else if (name.length > 255) errors.name = 'Use 255 characters or fewer.'
  if (draft.description.length > 1000) errors.description = 'Use 1000 characters or fewer.'
  if (draft.maxJobs !== initial.maxJobs) {
    const n = Number(draft.maxJobs)
    if (!/^\d+$/.test(draft.maxJobs.trim()) || n < 1 || n > MAX_JOBS_LIMIT) {
      errors.maxJobs = `Enter a whole number from 1 to ${MAX_JOBS_LIMIT}.`
    }
  }
  return errors
}

export function isSensorEditDirty(draft: SensorEditDraft, initial: SensorEditDraft): boolean {
  return (
    draft.name !== initial.name ||
    draft.description !== initial.description ||
    draft.enabled !== initial.enabled ||
    draft.maxJobs !== initial.maxJobs ||
    !sameList(draft.zoneIds, initial.zoneIds)
  )
}

/** The PUT body: only what changed. */
export function sensorUpdateBody(
  draft: SensorEditDraft,
  initial: SensorEditDraft
): UpdateSensorRequest {
  const body: UpdateSensorRequest = {}
  const name = draft.name.trim()
  if (name !== initial.name) body.name = name
  if (draft.description !== initial.description) body.description = draft.description.trim()
  if (draft.enabled !== initial.enabled) body.status = draft.enabled ? 'active' : 'disabled'
  if (draft.maxJobs !== initial.maxJobs) body.max_concurrent_jobs = Number(draft.maxJobs)
  return body
}

/** Zone membership changes: zones to join and zones to leave. */
export function zoneChanges(draft: SensorEditDraft, initial: SensorEditDraft) {
  return {
    join: draft.zoneIds.filter((z) => !initial.zoneIds.includes(z)),
    leave: initial.zoneIds.filter((z) => !draft.zoneIds.includes(z)),
  }
}
