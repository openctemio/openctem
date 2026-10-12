'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { useSignupPolicy } from '@/features/admin-console/api/use-signup-policy'
import { SignupPolicyForm } from '@/features/admin-console/components/signup-policy-form'
import { adminCan } from '@/features/admin-console/types'

/**
 * System -> Sign-up: who may create an organization on this deployment. Any
 * administrator sees it; super admins change it.
 */
export default function SignupPolicyPage() {
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useSignupPolicy()

  return (
    <Main>
      <PageHeader
        title="Sign-up"
        description="Who may create an organization on this deployment."
      />
      <div className="mt-5">
        {error ? (
          <ErrorState title="the sign-up policy" error={error} onRetry={() => void mutate()} />
        ) : isLoading || !data ? (
          <Skeleton className="h-72 w-full" />
        ) : (
          <SignupPolicyForm
            policy={data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSaved={() => void mutate()}
          />
        )}
      </div>
    </Main>
  )
}
