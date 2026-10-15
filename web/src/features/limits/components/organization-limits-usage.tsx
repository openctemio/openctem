'use client'

import { AlertTriangle, Gauge } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState } from '@/features/shared'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'
import { useOrganizationLimits } from '../api/use-organization-limits'
import { isLimitKey } from '../lib/limit-keys'
import { LimitsUsageTable, type LimitUsageRow } from './limits-usage-table'

/**
 * Settings > Usage & limits: the limits that apply to this organization and
 * what it uses, and the modules not available to it. Read-only: the limits
 * are set by the administrator of this installation. When nothing applies
 * (the default) the page says so and the settings rail does not list it.
 */
export function OrganizationLimitsUsage() {
  const { t, locale } = useTranslation()
  const { data, error, isLoading, mutate } = useOrganizationLimits()
  const { modules } = useTenantModules()
  const moduleName = (id: string) =>
    modules.find((m) => m.id === id)?.name ??
    id.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase())

  if (error) {
    return (
      <ErrorState
        title={t('limits.loadError', 'the limits')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) {
    return <Skeleton className="h-80 w-full" />
  }
  if (!data.applies) {
    return (
      <EmptyState
        icon={Gauge}
        title={t('limits.none.title', 'No limits apply')}
        description={t(
          'limits.none.description',
          'This organization has no limits and every module is available.'
        )}
      />
    )
  }

  const rows: LimitUsageRow[] = (data.limits ?? []).flatMap((l) =>
    isLimitKey(l.key)
      ? [
          {
            key: l.key,
            limit: l.limit,
            used: l.used,
            over_limit: l.over_limit,
            uncounted: l.uncounted,
          },
        ]
      : []
  )
  const denied = data.denied_features ?? []

  return (
    <div className="space-y-5">
      {data.over_limit && (
        <Alert variant="destructive">
          <AlertTriangle className="size-4" />
          <AlertTitle>{t('limits.overLimitTitle', 'Over a limit')}</AlertTitle>
          <AlertDescription>
            {t(
              'limits.overLimitNotice',
              'Nothing was removed. New additions of the items marked over limit are refused until some are removed or the limit is raised.'
            )}
          </AlertDescription>
        </Alert>
      )}
      {rows.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{t('limits.usage.title', 'Limits')}</CardTitle>
            <CardDescription>
              {t(
                'limits.usage.description',
                'What this organization may add. To change a limit, contact the administrator of this installation.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <LimitsUsageTable rows={rows} />
          </CardContent>
        </Card>
      )}
      {denied.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{t('limits.denied.title', 'Modules not available')}</CardTitle>
            <CardDescription>
              {t(
                'limits.denied.description',
                'These modules are not available for this organization. Its data is kept.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y" data-testid="limits-denied">
              {denied.map((d) => (
                <li
                  key={d.feature}
                  className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
                >
                  <span className="font-medium">{moduleName(d.feature ?? '')}</span>
                  {d.read_only_until && (
                    <span className="text-muted-foreground">
                      {t('limits.readOnlyUntil', 'Read-only until {date}', {
                        date: new Date(d.read_only_until).toLocaleDateString(locale),
                      })}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
