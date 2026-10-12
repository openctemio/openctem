import type { Sensor } from '@/lib/api/sensor-types'

/**
 * A sensor the router can pin jobs to: active and heartbeating, online or
 * late (past its heartbeat deadline but not yet stale; api RFC-035 §5.6).
 * The API also requires an unexpired key and a daemon/worker mode, and is
 * the authority on routing.
 */
export function isSensorHealthy(sensor: Pick<Sensor, 'status' | 'health'>): boolean {
  return sensor.status === 'active' && (sensor.health === 'online' || sensor.health === 'late')
}

export type SensorHealthLabel =
  'Online' | 'Late' | 'Stale' | 'Offline' | 'Error' | 'Disabled' | 'Revoked'

export function sensorHealthLabel(sensor: Pick<Sensor, 'status' | 'health'>): SensorHealthLabel {
  if (sensor.status === 'disabled') return 'Disabled'
  if (sensor.status === 'revoked') return 'Revoked'
  if (sensor.health === 'error') return 'Error'
  if (sensor.health === 'online') return 'Online'
  if (sensor.health === 'late') return 'Late'
  if (sensor.health === 'stale') return 'Stale'
  return 'Offline'
}
