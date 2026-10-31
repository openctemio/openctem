import type { Sensor } from '@/lib/api/sensor-types'

/**
 * What the viewer holds. Mirrors the API gates in
 * api/internal/infra/http/routes/scanning.go: update, rotate, activate and
 * deactivate need sensors:write, revoke needs sensors:write OR sensors:revoke
 * (revoking only narrows access), delete needs sensors:delete.
 */
export interface SensorActionPerms {
  write: boolean
  revoke: boolean
  delete: boolean
  /**
   * Whether the organization still allows bearer API keys (GET
   * /sensors/identity-policy). Rotating mints a bearer key, so the API refuses
   * it when they are not allowed. Unknown (undefined) counts as allowed.
   */
  bearerKeys?: boolean
}

export interface SensorActions {
  view: boolean
  edit: boolean
  rotate: boolean
  enable: boolean
  disable: boolean
  revoke: boolean
  delete: boolean
}

/**
 * The lifecycle actions one sensor offers to one viewer. One place for the
 * row menu, the detail drawer and the edit dialog so they cannot drift from
 * the API state machine: a revoked sensor is terminal (cannot be edited,
 * rotated or re-enabled), Enable only applies to a disabled sensor, and only
 * a sensor with a bearer key in an organization that allows them can rotate.
 */
export function sensorActions(
  sensor: Pick<Sensor, 'status' | 'auth_kind'>,
  perms: SensorActionPerms
): SensorActions {
  const revoked = sensor.status === 'revoked'
  return {
    view: true,
    edit: perms.write && !revoked,
    // "Rotate key" issues a new bearer API key. A key-bound sensor has no API
    // key (it pairs again instead), and an organization that allows no bearer
    // keys refuses every new one (sensor service RegenerateAPIKey).
    rotate:
      perms.write && !revoked && sensor.auth_kind !== 'key_bound' && perms.bearerKeys !== false,
    enable: perms.write && sensor.status === 'disabled',
    disable: perms.write && sensor.status === 'active',
    revoke: (perms.write || perms.revoke) && !revoked,
    delete: perms.delete,
  }
}
