import { isOneShotSensor } from '@/features/sensors/lib/sensor-state'
import type { Sensor } from '@/lib/api/sensor-types'

import type { ProxyAssignment, ProxyPool } from '../types'
import { pathValue, pathWarning, type PathWarning } from './path-warning'

/** One sensor a proxy change would hold back, and why. */
export interface SensorImpact {
  id: string
  name: string
  warning: Exclude<PathWarning, 'pool-disabled'>
}

/**
 * The sensors that would stop getting jobs if the organization default pool
 * were on, from what they report (api internal/app/command/egress.go): a
 * sensor on the default path (no assignment) that does not report proxy
 * support gets no scan jobs, and one that does not send validation probes
 * through the pool gets no validation jobs. Sensors with their own path,
 * disabled or revoked sensors and one-shot runners are not affected here.
 * The same rules as the sensor drawer (pathWarning), applied to the fleet.
 */
export function defaultPoolImpacts(
  sensors: Pick<Sensor, 'id' | 'name' | 'status' | 'type' | 'execution_mode' | 'reported'>[],
  assignments: ProxyAssignment[],
  pools: Pick<ProxyPool, 'id' | 'enabled' | 'is_default'>[]
): SensorImpact[] {
  // The default pool as it would be: on.
  const hypothetical = pools.some((p) => p.is_default)
    ? pools.map((p) => (p.is_default ? { ...p, enabled: true } : p))
    : [...pools, { id: '', enabled: true, is_default: true }]
  const out: SensorImpact[] = []
  for (const s of sensors) {
    if (s.status !== 'active' || isOneShotSensor(s)) continue
    const row = assignments.find((a) => a.sensor_id === s.id)
    if (row && row.mode !== 'inherit') continue
    const w = pathWarning(
      pathValue(row?.mode, row?.pool_id),
      hypothetical,
      s.reported?.capabilities ?? null
    )
    if (w === 'unsupported' || w === 'validate-waits')
      out.push({ id: s.id, name: s.name, warning: w })
  }
  return out.sort((a, b) => a.name.localeCompare(b.name))
}

/** The impacts of one warning kind. */
export function impactsOf(impacts: SensorImpact[], warning: SensorImpact['warning']) {
  return impacts.filter((i) => i.warning === warning)
}
