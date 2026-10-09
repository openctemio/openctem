'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import {
  saveScopePolicyDefault,
  useScopePolicyDefault,
} from '@/features/admin-console/api/use-scope-policy'
import { ScopePolicyForm } from '@/features/admin-console/components/scope-policy-form'
import { adminCan } from '@/features/admin-console/types'

/**
 * System -> Scope approvals: the platform default for scope-widening
 * approvals (RFC-054 §12.6). An organization may have its own override on
 * its Scope tab. Any administrator sees it; super admins change it.
 */
export default function ScopeApprovalsPage() {
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useScopePolicyDefault()

  return (
    <Main>
      <PageHeader
        title="Scope approvals"
        description="Whether widening an organization's scope waits for a second person."
      />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title="the scope approval policy"
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-72 w-full" />
        ) : (
          <ScopePolicyForm
            title="Platform default"
            description="Applies to every organization without its own setting."
            value={data.mode}
            canEdit={adminCan(me.role, 'super_admin')}
            onSave={async (mode, reason, code) => {
              await saveScopePolicyDefault({
                mode: mode ?? 'required',
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
