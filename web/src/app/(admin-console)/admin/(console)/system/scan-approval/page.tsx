'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import {
  saveScanPolicyDefault,
  useScanPolicyDefault,
} from '@/features/admin-console/api/use-scan-policy'
import { ScanPolicyForm } from '@/features/admin-console/components/scan-policy-form'
import { adminCan } from '@/features/admin-console/types'

/**
 * System -> Scan approval: the platform default for scan approval
 * (RFC-073 §5). An organization may have its own override on its Scope
 * tab. Any administrator sees it; super admins change it.
 */
export default function ScanApprovalPolicyPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useScanPolicyDefault()

  return (
    <Main>
      <PageHeader
        title={t('admin.scanPolicy.pageTitle', 'Scan approval')}
        description={t(
          'admin.scanPolicy.pageDesc',
          'Whether organizations choose their own scan approval, or the platform sets it.'
        )}
      />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('admin.scanPolicy.errorTitle', 'the scan approval policy')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-72 w-full" />
        ) : (
          <ScanPolicyForm
            title={t('admin.scanPolicy.defaultTitle', 'Platform default')}
            description={t(
              'admin.scanPolicy.defaultDesc',
              'Applies to every organization without its own setting.'
            )}
            value={data.policy}
            canEdit={adminCan(me.role, 'super_admin')}
            onSave={async (policy, reason, code) => {
              await saveScanPolicyDefault({
                policy: policy ?? 'tenant_controlled',
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
