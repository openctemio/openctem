'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { usePlanDefaults, usePlanModules } from '@/features/admin-console/api/use-plans'
import { PlanDefaultsForm } from '@/features/admin-console/components/plan-defaults-form'
import { PlanModulesForm } from '@/features/admin-console/components/plan-modules-form'
import { adminCan } from '@/features/admin-console/types'

/**
 * System -> Plans: the limits and the modules of the Free, Pro and Enterprise
 * plans. Any administrator sees them; super admins change them.
 */
export default function PlanDefaultsPage() {
  const me = useAdmin()
  const { data, error, isLoading, mutate } = usePlanDefaults()
  const modules = usePlanModules()

  return (
    <Main>
      <PageHeader
        title="Plans"
        description="What organizations on each plan may add, and which modules they may use."
      />
      <div className="mt-5 space-y-5">
        {error ? (
          <ErrorState title="the plan limits" error={error} onRetry={() => void mutate()} />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <PlanDefaultsForm
            defaults={data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSaved={() => void mutate()}
          />
        )}
        {modules.error ? (
          <ErrorState
            title="the plan modules"
            error={modules.error}
            onRetry={() => void modules.mutate()}
          />
        ) : modules.isLoading || !modules.data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <PlanModulesForm
            data={modules.data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSaved={() => void modules.mutate()}
          />
        )}
      </div>
    </Main>
  )
}
