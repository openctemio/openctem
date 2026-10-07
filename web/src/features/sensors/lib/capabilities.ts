/**
 * Sensor-reported capabilities (api RFC-029 §4.3.1). A sensor reports the
 * tools it really has (with versions), what it serves and how many jobs it
 * runs at once. Dispatch uses every installed tool the sensor reports (the
 * sensor grant narrows them); the capabilities and max_concurrent_jobs set
 * on the sensor are limits that can only narrow that report. These helpers
 * read the API's `reported` / `effective` blocks.
 */

import type { Sensor } from '@/lib/api/sensor-types'

/** How one tool stands on a sensor. */
export type SensorToolStatus =
  /** Installed, and dispatch may use it. */
  | 'ready'
  /** The sensor reports it, but not installed. */
  | 'not_installed'

export interface SensorToolRow {
  name: string
  version?: string
  status: SensorToolStatus
  /** What the tool serves besides its name, as the sensor reported. */
  capabilities?: string[]
  /**
   * Installed, but the sensor may not run it: its grant or its local policy
   * refuses a scan with it (from the tool availability view).
   */
  excluded?: { reason: 'grant' | 'local_policy'; detail?: string }
}

type ToolSource = Pick<Sensor, 'reported' | 'effective'>

/** Whether the sensor reported its tool inventory. */
export function hasReportedTools(sensor: Pick<Sensor, 'reported'>): boolean {
  return Array.isArray(sensor.reported?.tools)
}

/** The tools dispatch may send the sensor work for. */
export function dispatchTools(sensor: ToolSource): string[] {
  return sensor.effective?.tools ?? []
}

/**
 * Every tool the sensor reports, with versions: ready tools first, then the
 * ones it reports not installed; alphabetical within each. Empty before the
 * sensor's first report.
 */
export function sensorToolRows(
  sensor: ToolSource,
  exclusions?: Map<string, NonNullable<SensorToolRow['excluded']>>
): SensorToolRow[] {
  const rows = new Map<string, SensorToolRow>()
  for (const t of sensor.reported?.tools ?? []) {
    const caps = t.capabilities?.filter(Boolean) ?? []
    const excluded = t.installed ? exclusions?.get(t.name) : undefined
    rows.set(t.name, {
      name: t.name,
      version: t.version || undefined,
      status: t.installed ? 'ready' : 'not_installed',
      ...(caps.length > 0 ? { capabilities: caps } : {}),
      ...(excluded ? { excluded } : {}),
    })
  }
  const order: Record<SensorToolStatus, number> = { ready: 0, not_installed: 1 }
  return [...rows.values()].sort(
    (a, b) => order[a.status] - order[b.status] || a.name.localeCompare(b.name)
  )
}

/**
 * A sensor's capacity (api RFC-033, Kubernetes' capacity vs allocatable):
 * what it can run now (its slots, sized from CPU and memory), the ceiling its
 * operator set, and the limit set here. Dispatch uses the smallest of them.
 */
export interface SensorCapacity {
  /** The concurrent jobs dispatch allows. */
  effective: number
  /** The sensor operator's ceiling; null when it reported none. */
  reported: number | null
  /** The jobs the sensor can run at once now; null when it reported none. */
  slots: number | null
  /** The limit set on the sensor. */
  limit: number
}

type CapacitySource = Pick<Sensor, 'max_concurrent_jobs' | 'reported' | 'effective' | 'load'>

/** The sensor's capacity: effective, its slots, its ceiling and the limit. */
export function sensorCapacity(sensor: CapacitySource): SensorCapacity {
  const limit = sensor.max_concurrent_jobs ?? 0
  const reported = sensor.reported?.max_concurrent_jobs ?? null
  const rawSlots = sensor.load?.capacity?.slots_total
  const slots = rawSlots != null && rawSlots > 0 ? rawSlots : null
  let effective = sensor.effective?.max_concurrent_jobs
  if (effective == null) {
    const set = [limit, reported ?? 0, slots ?? 0].filter((n) => n > 0)
    effective = set.length > 0 ? Math.min(...set) : limit
  }
  return { effective, reported, slots, limit }
}

/**
 * "Runs 4 at once now · operator cap 64 · your limit 5": each number that is
 * known; "your limit 5" alone when the sensor reports neither.
 */
export function capacityLabel(sensor: CapacitySource): string {
  const c = sensorCapacity(sensor)
  const parts: string[] = []
  if (c.slots != null) parts.push(`Runs ${c.slots} at once now`)
  if (c.reported != null) parts.push(`operator cap ${c.reported}`)
  parts.push(`your limit ${c.limit}`)
  return parts.join(' · ')
}
