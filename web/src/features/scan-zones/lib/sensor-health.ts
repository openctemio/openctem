import type { Sensor } from '@/lib/api/sensor-types'
import type { Tr } from '@/features/sensors/lib/format'
import {
  SENSOR_STATE_META,
  sensorState,
  stateLabel,
  type SensorStateTone,
} from '@/features/sensors/lib/sensor-state'

/**
 * A sensor the router can pin jobs to: active and heartbeating, online or
 * late (past its heartbeat deadline but not yet stale; api RFC-035 §5.6).
 * The API also requires an unexpired key and a daemon/worker mode, and is
 * the authority on routing.
 */
export function isSensorHealthy(sensor: Pick<Sensor, 'status' | 'health'>): boolean {
  return sensor.status === 'active' && (sensor.health === 'online' || sensor.health === 'late')
}

/** The fields the shared state ladder reads; callers that lack some leave them out. */
export type ZoneSensorStateInput = Pick<Sensor, 'status' | 'health'> &
  Partial<
    Pick<
      Sensor,
      'last_seen_at' | 'state' | 'type' | 'execution_mode' | 'health_reasons' | 'outbox_warning'
    >
  >

/** The sensor's state word, the same one the Sensors tab shows. */
export function sensorStateLabel(sensor: ZoneSensorStateInput, tr: Tr): string {
  return stateLabel(sensorState(sensor as Parameters<typeof sensorState>[0]), tr)
}

/** The tone of the sensor's state, for the dot colour. */
export function sensorStateTone(sensor: ZoneSensorStateInput): SensorStateTone {
  return SENSOR_STATE_META[sensorState(sensor as Parameters<typeof sensorState>[0])].tone
}
