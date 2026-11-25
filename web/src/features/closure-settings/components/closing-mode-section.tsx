'use client'

import { useCallback, useState } from 'react'

import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, SettingsSaveBar, SettingsSection } from '@/features/shared'
import { useTenantSettings } from '@/features/organization/api/use-tenant-settings'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

import { useClosureSettings } from '../api'
import { ClosingModeForm, type ClosingModeFormStatus } from './closing-mode-form'

const FORM_ID = 'closing-mode-form'

/**
 * Settings > Finding lifecycle > Closing findings: the organization's closing
 * mode. Owners and administrators only (the API refuses anyone else); others
 * see nothing of it.
 */
export function ClosingModeSection() {
  const { t } = useTranslation()
  const { can, isOwner } = usePermissions()
  const canManage = can(Permission.TeamUpdate)
  const { currentTenant } = useTenant()
  const { data, error, isLoading, mutate } = useClosureSettings()
  const { settings, mutate: mutateSettings } = useTenantSettings(
    canManage ? currentTenant?.id : undefined
  )
  const [status, setStatus] = useState<ClosingModeFormStatus>({ dirty: false, submitting: false })
  const [resetKey, setResetKey] = useState(0)
  const onStatusChange = useCallback((s: ClosingModeFormStatus) => setStatus(s), [])
  const onSaved = useCallback(() => {
    void mutate()
    void mutateSettings()
  }, [mutate, mutateSettings])

  if (!canManage) return null

  return (
    <SettingsSection
      id="closing-mode"
      title={t('settings.closing.title', 'Closing findings')}
      description={t(
        'settings.closing.description',
        'When the platform may close a finding that a later scan no longer finds.'
      )}
    >
      {error ? (
        <ErrorState
          title={t('settings.closing.errorName', 'closing mode')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : isLoading || !data ? (
        <Skeleton className="h-64 w-full rounded-xl" />
      ) : (
        <ClosingModeForm
          key={`${JSON.stringify(data)}:${resetKey}`}
          initial={data}
          etag={settings?.etags?.closure}
          isOwner={isOwner()}
          onSaved={onSaved}
          formId={FORM_ID}
          onStatusChange={onStatusChange}
        />
      )}
      {data && !error && (
        <SettingsSaveBar
          dirty={status.dirty}
          saving={status.submitting}
          form={FORM_ID}
          onDiscard={() => {
            // A fresh form shows the saved values again.
            setResetKey((k) => k + 1)
            setStatus({ dirty: false, submitting: false })
          }}
        />
      )}
    </SettingsSection>
  )
}
