'use client'

import { useCallback, useState } from 'react'
import { AlertCircle, Loader2, PlayCircle, Save } from 'lucide-react'
import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  LifecycleSettingsForm,
  useAssetLifecycleSettings,
  DEFAULT_LIFECYCLE_SETTINGS,
  type LifecycleFormStatus,
} from '@/features/asset-lifecycle'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

const FORM_ID = 'asset-lifecycle-form'

export default function AssetLifecycleSettingsPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.TeamUpdate)
  const { currentTenant } = useTenant()
  const { data, error, isLoading, mutate } = useAssetLifecycleSettings()
  const [status, setStatus] = useState<LifecycleFormStatus>({ dirty: false, submitting: false })
  const [dryRunOpen, setDryRunOpen] = useState(false)
  const onStatusChange = useCallback((s: LifecycleFormStatus) => setStatus(s), [])

  const formReady = canRead && !error && !isLoading

  return (
    <Main>
      <PageHeader
        title={t('settings.assetLifecycle.title', 'Asset lifecycle')}
        description={t(
          'settings.assetLifecycle.description',
          'Mark assets as stale when no scan or integration has seen them for a while.'
        )}
      >
        {formReady && (
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setDryRunOpen(true)}
              disabled={status.submitting || !currentTenant}
            >
              <PlayCircle className="h-4 w-4" />
              {t('settings.assetLifecycle.runDryRun', 'Run dry run')}
            </Button>
            <Button
              type="submit"
              form={FORM_ID}
              size="sm"
              disabled={!status.dirty || status.submitting || !currentTenant}
            >
              {status.submitting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {t('settings.assetLifecycle.save', 'Save changes')}
            </Button>
          </>
        )}
      </PageHeader>

      <div className="mt-5">
        {!canRead ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>{t('settings.noPermissionTitle', 'Insufficient permissions')}</AlertTitle>
            <AlertDescription>
              {t(
                'settings.assetLifecycle.noPermission',
                'You do not have permission to view or change asset lifecycle settings.'
              )}
            </AlertDescription>
          </Alert>
        ) : error ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>{t('settings.loadFailed', 'Failed to load settings')}</AlertTitle>
            <AlertDescription>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                {t('common.retry', 'Retry')}
              </Button>
            </AlertDescription>
          </Alert>
        ) : isLoading ? (
          <Skeleton className="h-96 w-full rounded-xl" />
        ) : (
          <LifecycleSettingsForm
            initial={data ?? DEFAULT_LIFECYCLE_SETTINGS}
            formId={FORM_ID}
            onStatusChange={onStatusChange}
            dryRunOpen={dryRunOpen}
            onDryRunOpenChange={setDryRunOpen}
          />
        )}
      </div>
    </Main>
  )
}
