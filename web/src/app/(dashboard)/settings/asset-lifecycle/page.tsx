'use client'

import { useCallback, useState } from 'react'
import { PlayCircle } from 'lucide-react'
import { Main } from '@/components/layout'
import {
  ErrorState,
  NoAccessState,
  PageHeader,
  PageStack,
  SettingsSaveBar,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
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
  // Discard remounts the form on the saved settings.
  const [resets, setResets] = useState(0)
  const onStatusChange = useCallback((s: LifecycleFormStatus) => setStatus(s), [])

  const formReady = canRead && !error && !isLoading

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('settings.assetLifecycle.title', 'Asset lifecycle')}
          description={t(
            'settings.assetLifecycle.description',
            'Mark assets as stale when no scan or integration has seen them for a while.'
          )}
        >
          {formReady && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setDryRunOpen(true)}
              disabled={status.submitting || !currentTenant}
            >
              <PlayCircle className="h-4 w-4" />
              {t('settings.assetLifecycle.runDryRun', 'Run dry run')}
            </Button>
          )}
        </PageHeader>

        {!canRead ? (
          <NoAccessState
            title={t('settings.assetLifecycle.errorName', 'asset lifecycle settings')}
          />
        ) : error ? (
          <ErrorState
            title={t('settings.assetLifecycle.errorName', 'asset lifecycle settings')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <Skeleton className="h-96 w-full rounded-xl" />
        ) : (
          <LifecycleSettingsForm
            key={resets}
            initial={data ?? DEFAULT_LIFECYCLE_SETTINGS}
            formId={FORM_ID}
            onStatusChange={onStatusChange}
            dryRunOpen={dryRunOpen}
            onDryRunOpenChange={setDryRunOpen}
          />
        )}
        {formReady && (
          <SettingsSaveBar
            dirty={status.dirty}
            saving={status.submitting}
            form={FORM_ID}
            saveDisabled={!currentTenant}
            onDiscard={() => setResets((n) => n + 1)}
          />
        )}
      </PageStack>
    </Main>
  )
}
