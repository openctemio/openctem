'use client'

import { useState } from 'react'
import { toast } from 'sonner'

import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { setSensorIdentityPolicy, useSensorIdentityPolicy } from '@/lib/api/sensor-pairing-hooks'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'

const ID = 'tenant-sensor-require-key-bound'

/**
 * "Require key-bound identity" (api docs/rfcs/RFC-052 D-4). On: new sensors
 * join only by pairing (they make their own key); no bearer API key can be
 * created. Turning it on narrows (sensors:grant:narrow); turning it off
 * widens (sensors:grant:widen). Saved at once and audited; the API checks
 * the same permissions.
 */
export function SensorIdentityPolicySwitch() {
  const canRead = useHasPermission(Permission.SensorsRead)
  const canNarrow = useHasPermission(Permission.SensorsGrantNarrow)
  const canWiden = useHasPermission(Permission.SensorsGrantWiden)
  const { data, mutate, isLoading } = useSensorIdentityPolicy(canRead)
  const [saving, setSaving] = useState(false)

  if (!canRead) return null
  const required = data ? !data.bearer_keys_allowed : false
  // The direction decides the permission: requiring narrows, allowing widens.
  const canChange = required ? canWiden : canNarrow

  const onChange = async (requireNow: boolean) => {
    setSaving(true)
    try {
      const next = await setSensorIdentityPolicy({ bearer_keys_allowed: !requireNow })
      await mutate(next, { revalidate: false })
      toast.success(
        requireNow ? 'New sensors now join only by pairing' : 'Sensor API keys are allowed again'
      )
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not change the sensor identity policy'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex items-center justify-between gap-4" data-testid="sensor-identity-policy">
      <div className="space-y-0.5">
        <Label htmlFor={ID}>Require key-bound sensor identity</Label>
        <p className="text-sm text-muted-foreground" id={`${ID}-desc`}>
          On: new sensors join only by pairing, with a key they make themselves; no sensor API key
          can be created. Sensors that already have an API key keep working. Turning it off needs
          the permission to widen sensor grants and is audited.
        </p>
      </div>
      <Switch
        id={ID}
        aria-describedby={`${ID}-desc`}
        checked={required}
        onCheckedChange={(c) => void onChange(c)}
        disabled={!data || isLoading || saving || !canChange}
      />
    </div>
  )
}
