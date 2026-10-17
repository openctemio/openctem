'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { fetcher } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import { ErrorState, ReadOnlyNotice, SettingsSection } from '@/features/shared'
import { ORGANIZATION_PLAN_URL } from '@/features/plans/api/use-organization-plan'
import { useLifecycleSubStatuses } from '../../api/use-finding-lifecycles'
import { planLimit, type PlanLimitRow } from '../../lib/lifecycle'
import { LifecycleSchemes } from './lifecycle-schemes'
import { SubStatusLanes } from './sub-status-lanes'

/**
 * Settings > Finding lifecycle: the sub-status catalog (a lane per canonical
 * status) and the lifecycles with their drafts and versions. Everyone with
 * findings:read may look; findings:lifecycles:write may change. The API is
 * the authority for both and for the plan limits shown here.
 */
export function FindingLifecycleSettings() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.FindingsLifecyclesWrite)
  const [showArchived, setShowArchived] = useState(false)
  const subs = useLifecycleSubStatuses({ archived: showArchived })
  // Plan usage is readable by administrators; only those who may change the
  // lifecycle need it.
  const plan = useSWR<{ limits?: PlanLimitRow[] }>(
    canWrite ? ORGANIZATION_PLAN_URL : null,
    fetcher,
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    }
  )
  const subLimit = planLimit(plan.data?.limits, 'lifecycle_sub_statuses')
  const schemeLimit = planLimit(plan.data?.limits, 'lifecycle_schemes')

  if (subs.error) {
    return (
      <ErrorState
        title={t('findingLifecycle.subStatus.loadTitle', 'finding sub-statuses')}
        error={subs.error}
        onRetry={() => void subs.mutate()}
      />
    )
  }
  if (subs.isLoading || !subs.data) return <Skeleton className="h-64 w-full rounded-xl" />

  const catalog = subs.data.data ?? []

  return (
    <div className="space-y-5">
      {!canWrite && (
        <ReadOnlyNotice
          reason={t(
            'findingLifecycle.readOnlyNotice',
            'You can see the lifecycle. Changing it needs the Manage Finding Lifecycles permission.'
          )}
        />
      )}
      <Tabs defaultValue="sub-statuses">
        <TabsList>
          <TabsTrigger value="sub-statuses">
            {t('findingLifecycle.tabs.subStatuses', 'Sub-statuses')}
          </TabsTrigger>
          <TabsTrigger value="lifecycles">
            {t('findingLifecycle.tabs.lifecycles', 'Lifecycles')}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="sub-statuses" className="mt-4">
          <SettingsSection
            title={t('findingLifecycle.subStatus.title', 'Sub-statuses')}
            description={
              subLimit
                ? t('findingLifecycle.plan.usage', '{used} of {limit} on your plan', {
                    used: subLimit.used,
                    limit: subLimit.limit,
                  })
                : t(
                    'findingLifecycle.subStatus.hint',
                    'Labels inside each status. A label never changes what a metric counts.'
                  )
            }
            actions={
              <div className="flex items-center gap-2">
                <Switch
                  id="lifecycle-show-archived"
                  checked={showArchived}
                  onCheckedChange={setShowArchived}
                />
                <Label htmlFor="lifecycle-show-archived" className="text-sm font-normal">
                  {t('findingLifecycle.subStatus.showArchived', 'Show archived')}
                </Label>
              </div>
            }
          >
            {subLimit?.reached && canWrite && (
              <p role="status" className="text-sm text-warning">
                {t(
                  'findingLifecycle.plan.subStatusesReached',
                  'Your plan allows no more sub-statuses. Archive one, or ask your administrator for more.'
                )}
              </p>
            )}
            <SubStatusLanes
              subStatuses={catalog}
              colors={subs.data.colors ?? []}
              canWrite={canWrite}
              limitReached={subLimit?.reached ?? false}
              onChanged={() => void subs.mutate()}
            />
          </SettingsSection>
        </TabsContent>
        <TabsContent value="lifecycles" className="mt-4">
          <LifecycleSchemes catalog={catalog} canWrite={canWrite} limit={schemeLimit} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
