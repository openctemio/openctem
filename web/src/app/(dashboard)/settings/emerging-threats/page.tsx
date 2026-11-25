'use client'

import { NoAccessState, SettingsPage } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenantSettings } from '@/features/organization/api/use-tenant-settings'
import {
  EmergingThreatsSettingsForm,
  useEmergingThreatsSettings,
} from '@/features/emerging-threats'

const FORM_ID = 'emerging-threats-form'

export default function EmergingThreatsSettingsPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canManage = can(Permission.TeamUpdate)
  const { currentTenant } = useTenant()
  const { data, error, isLoading, mutate } = useEmergingThreatsSettings()
  // Hours are read in the organization time zone.
  const { settings } = useTenantSettings(currentTenant?.id)
  const timezone = settings?.general?.timezone || 'UTC'

  return (
    <SettingsPage
      title={t('emergingThreats.settings.title')}
      description={t('emergingThreats.settings.description')}
      state={!canManage ? 'ready' : error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
    >
      {!canManage ? (
        <NoAccessState
          title={t('emergingThreats.settings.loadError')}
          permission={Permission.TeamUpdate}
        />
      ) : (
        data && (
          <EmergingThreatsSettingsForm
            key={JSON.stringify(data)}
            initial={data}
            timezone={timezone}
            formId={FORM_ID}
            onSaved={() => void mutate()}
          />
        )
      )}
    </SettingsPage>
  )
}
