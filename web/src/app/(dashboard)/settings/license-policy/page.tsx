'use client'

import { useCallback, useState } from 'react'
import { Loader2, Save } from 'lucide-react'
import { Main } from '@/components/layout'
import { ErrorState, PageHeader } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  LicensePolicyForm,
  useLicensePolicy,
  type LicensePolicyFormStatus,
} from '@/features/license-policy'
import { useTenantSettings } from '@/features/organization/api/use-tenant-settings'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions, Permission } from '@/lib/permissions'

const FORM_ID = 'license-policy-form'

export default function LicensePolicySettingsPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canEdit = can(Permission.SettingsWrite)
  const { currentTenant } = useTenant()
  const { data, error, isLoading, mutate } = useLicensePolicy()
  // The section's ETag rides on the organization settings read.
  const { settings, mutate: mutateSettings } = useTenantSettings(currentTenant?.id)
  const [status, setStatus] = useState<LicensePolicyFormStatus>({ dirty: false, submitting: false })
  const onStatusChange = useCallback((s: LicensePolicyFormStatus) => setStatus(s), [])
  const onSaved = useCallback(() => {
    void mutate()
    void mutateSettings()
  }, [mutate, mutateSettings])

  return (
    <Main>
      <PageHeader
        title={t('settings.item.license-policy', 'License policy')}
        description={t(
          'licensePolicy.pageDescription',
          'Allow, review or deny the licenses your open-source packages declare. Denied licenses open findings.'
        )}
      >
        {canEdit && data && (
          <Button
            type="submit"
            form={FORM_ID}
            size="sm"
            disabled={!status.dirty || status.submitting}
          >
            {status.submitting ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <Save className="h-4 w-4" aria-hidden />
            )}
            {t('licensePolicy.save', 'Save changes')}
          </Button>
        )}
      </PageHeader>
      <div className="mt-5">
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
            key={JSON.stringify(data.policy)}
            initial={data.policy}
            etag={(settings?.etags as Record<string, string> | undefined)?.license_policy}
            formId={FORM_ID}
            canEdit={canEdit}
            onSaved={onSaved}
            onStatusChange={onStatusChange}
          />
        )}
      </div>
    </Main>
  )
}
