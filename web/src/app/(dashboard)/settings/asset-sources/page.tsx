'use client'

import { AlertCircle } from 'lucide-react'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader } from '@/features/shared'
import {
  AssetSourcesSettingsForm,
  saveReconciliationSettings,
  useReconciliationSettings,
} from '@/features/assets'
import { usePermissions, Permission } from '@/lib/permissions'

export default function AssetSourcesSettingsPage() {
  const { can } = usePermissions()
  const canRead = can(Permission.TeamUpdate)
  const { data, error, isLoading, mutate } = useReconciliationSettings(canRead)

  return (
    <Main>
      <PageHeader
        title="Asset sources"
        description="Assets hear from scans, imports, integrations and people. Choose which source decides each value."
      />
      <div className="mt-5">
        {!canRead ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Insufficient permissions</AlertTitle>
            <AlertDescription>
              Only owners and administrators view or change asset source settings.
            </AlertDescription>
          </Alert>
        ) : error ? (
          <ErrorState title="asset source settings" error={error} onRetry={() => mutate()} />
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
          />
        )}
      </div>
    </Main>
  )
}
