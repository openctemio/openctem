'use client'

import { AlertCircle } from 'lucide-react'
import { Main } from '@/components/layout'
import { ErrorState, PageHeader } from '@/features/shared'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
    <Main>
      <PageHeader
        title={t('emergingThreats.settings.title')}
        description={t('emergingThreats.settings.description')}
      />
      <div className="mt-5">
        {!canManage ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>{t('emergingThreats.settings.noPermissionTitle')}</AlertTitle>
            <AlertDescription>{t('emergingThreats.settings.noPermission')}</AlertDescription>
          </Alert>
        ) : error ? (
          <ErrorState
            title={t('emergingThreats.settings.loadError')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full rounded-xl" />
        ) : (
          <EmergingThreatsSettingsForm
            key={JSON.stringify(data)}
            initial={data}
            timezone={timezone}
            formId={FORM_ID}
            onSaved={() => void mutate()}
          />
        )}
      </div>
    </Main>
  )
}
