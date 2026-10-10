'use client'

import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState } from '@/features/shared'
import { saveScopePolicyOrganization, useScopePolicyOrganization } from '../api/use-scope-policy'
import { ScopePolicyForm, SCOPE_POLICY_TEXT } from './scope-policy-form'

/**
 * An organization's Scope tab: its scope-widening approval policy
 * (RFC-054 §12.6), an override of the platform default.
 */
export function OrganizationScopePolicyPanel({
  tenantId,
  canEdit,
}: {
  tenantId: string
  canEdit: boolean
}) {
  const { data, error, isLoading, mutate } = useScopePolicyOrganization(tenantId)
  if (error) {
    return (
      <ErrorState title="the scope approval policy" error={error} onRetry={() => void mutate()} />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-72 w-full" />
  return (
    <ScopePolicyForm
      title="Scope approvals"
      description={`In effect: ${SCOPE_POLICY_TEXT[data.effective].label} (${
        data.source === 'organization_override' ? 'set for this organization' : 'platform default'
      }). The organization's administrators are told when it changes.`}
      value={data.override}
      platformDefault={data.platform_default}
      canEdit={canEdit}
      onSave={async (mode, reason, code) => {
        await saveScopePolicyOrganization(tenantId, { mode, reason, totp_code: code })
        await mutate()
      }}
    />
  )
}
