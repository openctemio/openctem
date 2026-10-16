'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { toast } from 'sonner'

import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { get, put } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/lib/permissions'

const ID = 'tenant-shared-sensors-opt-out'
export const SHARED_SENSORS_SETTINGS_ENDPOINT = '/api/v1/organization/settings/shared-sensors'

/** The organization's shared sensor choice (api docs/rfcs/RFC-100 §5). */
export interface SharedSensorsSettings {
  /** Never send this organization's scans to shared sensors. */
  opt_out: boolean
}

/**
 * "Never use shared sensors": the organization owner's opt-out (data
 * residency, allowlists, policy). Default off: scans use shared sensors when
 * the instance offers them. Owners and administrators see it; only the owner
 * changes it. The API checks the same.
 */
export function SharedSensorsOptOutSwitch() {
  const { t } = useTranslation()
  const { isOwner, isAdmin } = usePermissions()
  const canRead = isAdmin()
  const { data, mutate, isLoading } = useSWR<SharedSensorsSettings>(
    canRead ? SHARED_SENSORS_SETTINGS_ENDPOINT : null,
    (url: string) => get<SharedSensorsSettings>(url),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
  const [saving, setSaving] = useState(false)

  if (!canRead) return null

  const onChange = async (optOut: boolean) => {
    setSaving(true)
    try {
      const next = await put<SharedSensorsSettings>(SHARED_SENSORS_SETTINGS_ENDPOINT, {
        opt_out: optOut,
      })
      await mutate(next, { revalidate: false })
      toast.success(
        optOut ? t('sensors.sharedOptOut.optedOutToast') : t('sensors.sharedOptOut.optedInToast')
      )
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.sharedOptOut.error')))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex items-center justify-between gap-4" data-testid="shared-sensors-opt-out">
      <div className="space-y-0.5">
        <Label htmlFor={ID}>{t('sensors.sharedOptOut.label')}</Label>
        <p className="text-sm text-muted-foreground" id={`${ID}-desc`}>
          {isOwner() ? t('sensors.sharedOptOut.description') : t('sensors.sharedOptOut.ownerOnly')}
        </p>
      </div>
      <Switch
        id={ID}
        aria-describedby={`${ID}-desc`}
        checked={data?.opt_out ?? false}
        onCheckedChange={(c) => void onChange(c)}
        disabled={!data || isLoading || saving || !isOwner()}
      />
    </div>
  )
}
