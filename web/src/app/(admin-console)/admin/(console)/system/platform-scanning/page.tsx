'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import {
  savePlatformSensorProof,
  usePlatformSensorProof,
} from '@/features/admin-console/api/use-scan-policy'
import { PlatformSensorProofForm } from '@/features/admin-console/components/platform-sensor-proof-form'
import { adminCan } from '@/features/admin-console/types'

/**
 * System -> Platform scanning: whether platform sensors need a verified
 * domain before they scan a target (RFC-054 §8.1). Any administrator sees
 * it; super admins change it.
 */
export default function PlatformScanningPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = usePlatformSensorProof()

  return (
    <Main>
      <PageHeader title={t('admin.proof.pageTitle')} description={t('admin.proof.pageDesc')} />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('admin.proof.errorTitle')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-56 w-full" />
        ) : (
          <PlatformSensorProofForm
            required={data.required}
            canEdit={adminCan(me.role, 'super_admin')}
            onSave={async (required, reason, code) => {
              await savePlatformSensorProof({
                required,
                version: data.version ?? 0,
                reason,
                totp_code: code,
              })
              await mutate()
            }}
          />
        )}
      </div>
    </Main>
  )
}
