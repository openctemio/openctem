'use client'

import { useCallback, useState } from 'react'
import { Main } from '@/components/layout'
import { ErrorState, PageHeader, PageStack, SettingsSaveBar } from '@/features/shared'
import { Skeleton } from '@/components/ui/skeleton'
import {
  LicensePolicyForm,
  useLicensePolicy,
  type LicensePolicyFormStatus,
} from '@/features/license-policy'
import { useTenantSettings } from '@/features/organization/api/use-tenant-settings'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { useCanMutate } from '@/lib/permissions'

const FORM_ID = 'license-policy-form'

export default function LicensePolicySettingsPage() {
  const { t } = useTranslation()
  const canEdit = useCanMutate('PUT /api/v1/organization/settings/license-policy')
  const { currentTenant } = useTenant()
  const { data, error, isLoading, mutate } = useLicensePolicy()
  // The section's ETag rides on the organization settings read.
  const { settings, mutate: mutateSettings } = useTenantSettings(currentTenant?.id)
  const [status, setStatus] = useState<LicensePolicyFormStatus>({ dirty: false, submitting: false })
  const onStatusChange = useCallback((s: LicensePolicyFormStatus) => setStatus(s), [])
  // Discard remounts the form on the saved policy.
  const [resets, setResets] = useState(0)
  const onSaved = useCallback(() => {
    void mutate()
    void mutateSettings()
  }, [mutate, mutateSettings])

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('settings.item.license-policy', 'License policy')}
          description={t(
            'licensePolicy.pageDescription',
            'Allow, review or deny the licenses your open-source packages declare. Denied licenses open findings.'
          )}
        />
        {error ? (
          <ErrorState
            title={t('licensePolicy.loadTitle', 'license policy')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full rounded-xl" />
        ) : (
          <LicensePolicyForm
            key={`${JSON.stringify(data.policy)}:${resets}`}
            initial={data.policy}
            etag={(settings?.etags as Record<string, string> | undefined)?.license_policy}
            formId={FORM_ID}
            canEdit={canEdit}
            onSaved={onSaved}
            onStatusChange={onStatusChange}
          />
        )}
        {canEdit && data && (
          <SettingsSaveBar
            dirty={status.dirty}
            saving={status.submitting}
            form={FORM_ID}
            onDiscard={() => setResets((n) => n + 1)}
          />
        )}
      </PageStack>
    </Main>
  )
}
