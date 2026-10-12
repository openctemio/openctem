'use client'

import { AlertCircle } from 'lucide-react'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import {
  AssetSourcesSettingsForm,
  previewReconciliationSettings,
  saveReconciliationSettings,
  useReconciliationSettings,
} from '@/features/assets'
import { usePermissions, Permission } from '@/lib/permissions'

export default function AssetSourcesSettingsPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.TeamUpdate)
  const { data, error, isLoading, mutate } = useReconciliationSettings(canRead)

  return (
    <Main>
      <PageHeader
        title={t('assetSources.title', 'Asset sources')}
        description={t(
          'assetSources.description',
          'Assets hear from scans, imports, connectors, feeds and people. Choose which source decides each kind of value.'
        )}
      />
      <div className="mt-5">
        {!canRead ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>{t('assetSources.noAccessTitle', 'Insufficient permissions')}</AlertTitle>
            <AlertDescription>
              {t(
                'assetSources.noAccess',
                'Only owners and administrators view or change asset source settings.'
              )}
            </AlertDescription>
          </Alert>
        ) : error ? (
          <ErrorState
            title={t('assetSources.errorTitle', 'asset source settings')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full rounded-xl" />
        ) : (
          <AssetSourcesSettingsForm
            settings={data}
            canEdit={canRead}
            onSave={async (p) => {
              const saved = await saveReconciliationSettings(p)
              await mutate(saved, { revalidate: false })
            }}
            onPreview={previewReconciliationSettings}
          />
        )}
      </div>
    </Main>
  )
}
