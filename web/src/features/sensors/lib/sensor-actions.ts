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
 * rotated or re-enabled), Enable only applies to a disabled sensor.
 */
export function sensorActions(
  sensor: Pick<Sensor, 'status'>,
  perms: SensorActionPerms
): SensorActions {
  const revoked = sensor.status === 'revoked'
  return {
    view: true,
    edit: perms.write && !revoked,
    rotate: perms.write && !revoked,
    enable: perms.write && sensor.status === 'disabled',
    disable: perms.write && sensor.status === 'active',
    revoke: (perms.write || perms.revoke) && !revoked,
    delete: perms.delete,
  }
}
