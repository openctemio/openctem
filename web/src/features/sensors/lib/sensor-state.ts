import type { Sensor, SensorState } from '@/lib/api/sensor-types'

/**
 * The thresholds of the state ladder. The API returns its own in
 * GET /sensors/stats (online_window_seconds, offline_after_seconds); these are
 * its defaults, used until the stats arrive or against an older API.
 */
export interface FleetThresholds {
  onlineWindowSeconds: number
  offlineAfterSeconds: number
}

export const DEFAULT_FLEET_THRESHOLDS: FleetThresholds = {
  onlineWindowSeconds: 90,
  offlineAfterSeconds: 300,
}

type StateInput = Pick<
  Sensor,
  | 'status'
  | 'health'
  | 'last_seen_at'
  | 'type'
  | 'execution_mode'
  | 'state'
  | 'health_reasons'
  | 'outbox_warning'
>

/** A one-shot (CI) sensor connects only while it runs. */
export function isOneShotSensor(sensor: Pick<Sensor, 'type' | 'execution_mode'>): boolean {
  return sensor.execution_mode === 'standalone'
}

/**
 * The sensor's operational state. The API computes it (`state`) and is the
 * authority: each sensor is judged against its own heartbeat deadline, online
 * -> late -> stale -> offline (api RFC-035 §5.6). Against an older API, which
 * sends no state, this computes that API's ladder: revoked, disabled, never
 * connected, online (heartbeat within the online window), degraded (online
 * with a problem), idle (a CI sensor between runs), stale (past the window,
 * within the heartbeat timeout), offline.
 */
export function sensorState(
  sensor: StateInput,
  now: number = Date.now(),
  thresholds: FleetThresholds = DEFAULT_FLEET_THRESHOLDS
): SensorState {
  if (sensor.state) return sensor.state
  if (sensor.status === 'revoked') return 'revoked'
  if (sensor.status === 'disabled') return 'disabled'
  if (!sensor.last_seen_at) return 'never_connected'
  const seen = new Date(sensor.last_seen_at).getTime()
  if (Number.isNaN(seen)) return 'never_connected'
  const ageSeconds = (now - seen) / 1000
  if (ageSeconds <= thresholds.onlineWindowSeconds) {
    const problems =
      (sensor.health_reasons?.length ?? 0) > 0 ||
      !!sensor.outbox_warning ||
      sensor.health === 'error'
    return problems ? 'degraded' : 'online'
  }
  if (isOneShotSensor(sensor)) return 'idle'
  if (ageSeconds <= thresholds.offlineAfterSeconds && sensor.health !== 'offline') return 'stale'
  return 'offline'
}

/**
 * States the platform dispatches new work to: online, degraded, and late (past
 * its heartbeat deadline but not yet stale). Stale and offline sensors get none.
 */
export function stateTakesJobs(state: SensorState): boolean {
  return state === 'online' || state === 'degraded' || state === 'late'
}

/** States of a sensor that is still heartbeating (late and stale included). */
export function stateIsHeartbeating(state: SensorState): boolean {
  return stateTakesJobs(state) || state === 'stale'
}

/** Enabled, long-running and heartbeating: the platform can dispatch to it. */
export function canTakeJobs(
  sensor: StateInput,
  now: number = Date.now(),
  thresholds: FleetThresholds = DEFAULT_FLEET_THRESHOLDS
): boolean {
  if (isOneShotSensor(sensor)) return false
  return stateTakesJobs(sensorState(sensor, now, thresholds))
}

export type SensorStateTone = 'success' | 'warning' | 'destructive' | 'info' | 'muted'

export const SENSOR_STATE_META: Record<
  SensorState,
  { label: string; tone: SensorStateTone; description: string }
> = {
  online: { label: 'Online', tone: 'success', description: 'Heartbeating, nothing wrong.' },
  degraded: {
    label: 'Degraded',
    tone: 'warning',
    description: 'Heartbeating, but something needs attention.',
  },
  late: {
    label: 'Late',
    tone: 'warning',
    description: 'Its heartbeat is past due. It still takes work; nobody is notified yet.',
  },
  stale: {
    label: 'Stale',
    tone: 'warning',
    description:
      'Its heartbeat is well past due. It takes no new work and its queued work goes to other sensors; it is not offline yet.',
  },
  offline: { label: 'Offline', tone: 'destructive', description: 'No heartbeat in time.' },
  idle: {
    label: 'Idle (CI)',
    tone: 'info',
    description: 'A CI sensor between runs. It connects only while it runs.',
  },
  never_connected: {
    label: 'Never connected',
    tone: 'muted',
    description: 'No heartbeat yet. Install the sensor with its key.',
  },
  disabled: { label: 'Disabled', tone: 'muted', description: 'Disabled by an admin.' },
  revoked: { label: 'Revoked', tone: 'muted', description: 'Access revoked for good.' },
}

/** The ladder order, for sorting and breakdowns. */
export const SENSOR_STATES: SensorState[] = [
  'online',
  'degraded',
  'late',
  'stale',
  'offline',
  'idle',
  'never_connected',
  'disabled',
  'revoked',
]
