import type { AdminOperations } from '../types'

/** Compares two versions like v0.9.2 / 0.10.0-rc.1 by their numeric core. */
export function compareVersions(a: string, b: string): number {
  const core = (v: string) =>
    v
      .replace(/^v/, '')
      .split(/[-+]/)[0]
      .split('.')
      .map((n) => Number.parseInt(n, 10) || 0)
  const x = core(a)
  const y = core(b)
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  return 0
}

export interface SensorFleetSummary {
  platform: { total: number; online: number; unhealthy: number }
  customer: { total: number; online: number; unhealthy: number }
  /** SDK versions in the field, newest first, with whether each is below the minimum. */
  versions: { version: string; count: number; belowMin: boolean }[]
}

const UNHEALTHY = new Set(['offline', 'stale', 'error'])

/** Active sensors grouped for the Operations page (counts only). */
export function summarizeSensors(o: AdminOperations): SensorFleetSummary {
  const out: SensorFleetSummary = {
    platform: { total: 0, online: 0, unhealthy: 0 },
    customer: { total: 0, online: 0, unhealthy: 0 },
    versions: [],
  }
  const versions = new Map<string, number>()
  for (const s of o.sensors) {
    const g = s.platform ? out.platform : out.customer
    g.total += s.count
    if (s.health === 'online') g.online += s.count
    if (UNHEALTHY.has(s.health)) g.unhealthy += s.count
    const v = s.sdk_version || 'unknown'
    versions.set(v, (versions.get(v) ?? 0) + s.count)
  }
  out.versions = [...versions.entries()]
    .map(([version, count]) => ({
      version,
      count,
      belowMin:
        !!o.sdk_min_version &&
        version !== 'unknown' &&
        compareVersions(version, o.sdk_min_version) < 0,
    }))
    .sort((a, b) =>
      a.version === 'unknown'
        ? 1
        : b.version === 'unknown'
          ? -1
          : compareVersions(b.version, a.version)
    )
  return out
}

export type SchemaState = 'ok' | 'behind' | 'ahead' | 'dirty' | 'unknown'

export function schemaState(o: AdminOperations): SchemaState {
  if (!o.schema.known) return 'unknown'
  if (o.schema.dirty) return 'dirty'
  if (o.schema.shipped > 0 && o.schema.applied < o.schema.shipped) return 'behind'
  if (o.schema.shipped > 0 && o.schema.applied > o.schema.shipped) return 'ahead'
  return 'ok'
}
