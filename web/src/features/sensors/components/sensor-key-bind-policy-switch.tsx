'use client'

import { useState } from 'react'
import { toast } from 'sonner'

import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { setSensorIdentityPolicy, useSensorIdentityPolicy } from '@/lib/api/sensor-pairing-hooks'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'

const ID = 'tenant-sensor-key-bind-approval'

/**
 * "Require approval of sensor keys" (api docs/rfcs/RFC-052 §4.8). Off: a
 * bearer-key sensor binds its own signing key once (audited) and its API key
 * stops working. On: it keeps its API key until an administrator re-pairs
 * it. Turning it on narrows (sensors:grant:narrow); turning it off widens
 * (sensors:grant:widen, with a recent sign-in). The API checks the same.
 */
export function SensorKeyBindPolicySwitch() {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.SensorsRead)
  const canNarrow = useHasPermission(Permission.SensorsGrantNarrow)
  const canWiden = useHasPermission(Permission.SensorsGrantWiden)
  const { data, mutate, isLoading } = useSensorIdentityPolicy(canRead)
  const [saving, setSaving] = useState(false)

  if (!canRead) return null
  const required = data?.key_bind_requires_approval ?? false
  // Requiring approval narrows; allowing self-binding again widens.
  const canChange = required ? canWiden : canNarrow

  const onChange = async (requireNow: boolean) => {
    setSaving(true)
    try {
      const next = await setSensorIdentityPolicy({ key_bind_requires_approval: requireNow })
      await mutate(next, { revalidate: false })
      toast.success(
        requireNow
          ? t('sensors.keyBindPolicy.requiredToast')
          : t('sensors.keyBindPolicy.allowedToast')
      )
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.keyBindPolicy.error')))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex items-center justify-between gap-4" data-testid="sensor-key-bind-policy">
      <div className="space-y-0.5">
        <Label htmlFor={ID}>{t('sensors.keyBindPolicy.label')}</Label>
        <p className="text-sm text-muted-foreground" id={`${ID}-desc`}>
          {t('sensors.keyBindPolicy.description')}
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
