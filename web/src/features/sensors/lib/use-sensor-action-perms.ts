'use client'

import { useMemo } from 'react'

import { useSensorIdentityPolicy } from '@/lib/api/sensor-pairing-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import type { SensorActionPerms } from './sensor-actions'

/**
 * What the viewer may do to a sensor, for sensorActions(): the permissions
 * the API gates check and whether the organization allows bearer keys.
 */
export function useSensorActionPerms(): SensorActionPerms {
  const write = useHasPermission(Permission.SensorsWrite)
  const revoke = useHasPermission(Permission.SensorsRevoke)
  const del = useHasPermission(Permission.SensorsDelete)
  const { data: identityPolicy } = useSensorIdentityPolicy()
  const bearerKeys = identityPolicy?.bearer_keys_allowed
  return useMemo(
    () => ({ write, revoke, delete: del, bearerKeys }),
    [write, revoke, del, bearerKeys]
  )
}
