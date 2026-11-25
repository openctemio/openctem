'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import {
  saveScanPolicyDefault,
  useScanPolicyDefault,
} from '@console/features/admin-console/api/use-scan-policy'
import { ScanPolicyForm } from '@console/features/admin-console/components/scan-policy-form'
import { adminHas } from '@console/features/admin-console/types'

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
    <SettingsPage
      title={t('admin.scanPolicy.pageTitle', 'Scan approval')}
      description={t(
        'admin.scanPolicy.pageDesc',
        'Whether organizations choose their own scan approval, or the platform sets it.'
      )}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
    >
      {data && (
        <ScanPolicyForm
          title={t('admin.scanPolicy.defaultTitle', 'Platform default')}
          description={t(
            'admin.scanPolicy.defaultDesc',
            'Applies to every organization without its own setting.'
          )}
          value={data.policy}
          canEdit={adminHas(me, 'platform.sensors.manage')}
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
    </SettingsPage>
  )
}
