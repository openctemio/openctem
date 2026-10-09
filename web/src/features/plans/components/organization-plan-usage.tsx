'use client'

import { useMemo } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { useOrganizationPlan } from '../api/use-organization-plan'
import { isPlanName, PLAN_KEY_LABEL, PLAN_LABEL, type PlanKey } from '../lib/plan-keys'
import { PlanUsageTable, type PlanUsageTableText } from './plan-usage-table'

/**
 * Settings > Plan & usage: the organization's plan and, per limit, what it
 * uses. Read-only: a platform administrator changes the plan and the limits.
 */
export function OrganizationPlanUsage() {
  const { t, locale } = useTranslation()
  const { data, error, isLoading, mutate } = useOrganizationPlan()

  const text = useMemo<PlanUsageTableText>(
    () => ({
      limit: t('plan.col.item', 'Limit'),
      limitColumn: t('plan.col.limit', 'Allowed'),
      usedColumn: t('plan.col.used', 'Used'),
      unlimited: t('plan.unlimited', 'Unlimited'),
      notCounted: t('plan.notCounted', 'Counted while a limit is set'),
      overLimit: t('plan.overLimit', 'Over limit'),
      override: t('plan.override', 'Set for this organization'),
      until: (date) =>
        t('plan.until', 'until {date}', {
          date: new Date(date).toLocaleDateString(locale),
        }),
      keyLabel: (key: PlanKey) => t(`plan.key.${key}`, PLAN_KEY_LABEL[key]),
    }),
    [t, locale]
  )

  if (error) {
    return (
      <ErrorState
        title={t('plan.loadError', 'the plan')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) {
    return <Skeleton className="h-80 w-full" />
  }

  const plan = data.plan && isPlanName(data.plan) ? data.plan : undefined
  const planLabel = plan ? t(`plan.name.${plan}`, PLAN_LABEL[plan]) : (data.plan ?? '')

  return (
    <div className="space-y-5">
      {data.over_limit && (
        <Alert variant="destructive">
          <AlertTriangle className="size-4" />
          <AlertTitle>{t('plan.overLimitTitle', 'Over your plan')}</AlertTitle>
          <AlertDescription>
            {t(
              'plan.overLimitNotice',
              'Nothing was removed. New additions of the items marked over limit are refused until you remove some or your plan allows more.'
            )}
          </AlertDescription>
        </Alert>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            {t('plan.current', 'Current plan')}
            <Badge variant="secondary">{planLabel}</Badge>
          </CardTitle>
          <CardDescription>
            {t(
              'plan.description',
              'What this organization may add. To change the plan or a limit, contact your platform administrator.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <PlanUsageTable limits={data.limits ?? []} text={text} />
        </CardContent>
      </Card>
    </div>
  )
}
