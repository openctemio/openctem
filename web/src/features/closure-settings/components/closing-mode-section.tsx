'use client'

import { useCallback, useState } from 'react'
import { Loader2, Save } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, SettingsSection } from '@/features/shared'
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
      actions={
        data && !error ? (
          <Button
            type="submit"
            form={FORM_ID}
            size="sm"
            disabled={!status.dirty || status.submitting}
          >
            {status.submitting ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            {t('settings.closing.save', 'Save changes')}
          </Button>
        ) : undefined
      }
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
          key={JSON.stringify(data)}
          initial={data}
          etag={settings?.etags?.closure}
          isOwner={isOwner()}
          onSaved={onSaved}
          formId={FORM_ID}
          onStatusChange={onStatusChange}
        />
      )}
    </SettingsSection>
  )
}
