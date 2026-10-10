'use client'

import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { saveScanPolicyOrganization, useScanPolicyOrganization } from '../api/use-scan-policy'
import { ScanPolicyForm, useScanPolicyText } from './scan-policy-form'

/**
 * An organization's Scope tab: its scan approval policy (RFC-073 §5), an
 * override of the platform default, and the scan approval in force.
 */
export function OrganizationScanPolicyPanel({
  tenantId,
  canEdit,
}: {
  tenantId: string
  canEdit: boolean
}) {
  const { t } = useTranslation()
  const text = useScanPolicyText()
  const { data, error, isLoading, mutate } = useScanPolicyOrganization(tenantId)
  if (error) {
    return (
      <ErrorState
        title={t('admin.scanPolicy.errorTitle', 'the scan approval policy')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-72 w-full" />
  return (
    <ScanPolicyForm
      title={t('admin.scanPolicy.orgTitle', 'Scan approval')}
      description={t(
        'admin.scanPolicy.orgDesc',
        'In force: {mode} (policy: {policy}, {source}). The organization’s administrators are told when it changes.',
        {
          mode: text.mode(data.effective_mode),
          policy: text.policy(data.policy).label,
          source:
            data.source === 'organization_override'
              ? t('admin.scanPolicy.sourceOrg', 'set for this organization')
              : t('admin.scanPolicy.sourceDefault', 'platform default'),
        }
      )}
      value={data.override}
      platformDefault={data.platform_default}
      canEdit={canEdit}
      onSave={async (policy, reason, code) => {
        await saveScanPolicyOrganization(tenantId, { policy, reason, totp_code: code })
        await mutate()
      }}
    />
  )
}
