'use client'

/**
 * The dashboard's scope badge and freshness line: whose figures these are,
 * when they were computed, when the next scheduled refresh runs, Refresh now
 * (budgeted on the server) and the schedule picker for those who may change it.
 */

import { useState } from 'react'
import { AlertTriangle, Building2, RefreshCw, User } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatAbsoluteTime, formatRelativeTime } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import type { DashboardKind, DashboardRefreshSchedule } from '../api/dashboards.types'
import type { DashboardData } from '../api/widget-data'

export const SCHEDULE_OPTIONS: readonly DashboardRefreshSchedule[] = [
  '',
  '5m',
  '15m',
  '1h',
  '6h',
  'daily',
  'manual',
]

/** Select values cannot be empty: the organization default travels as "default". */
const DEFAULT_VALUE = 'default'

export function ScopeBadge({ data, kind }: { data?: DashboardData; kind: DashboardKind }) {
  const { t } = useTranslation()
  const org = (data?.scope ?? kind) === 'organization'
  const hint = org
    ? t(
        'dashboards.scope.organizationHint',
        'Figures for the whole organization. Lists open in your own access.'
      )
    : data?.restricted
      ? t('dashboards.scope.mineRestrictedHint', 'Figures for the assets you can see.')
      : t('dashboards.scope.mineHint', 'Figures computed for your own access.')
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant="outline"
          className="gap-1.5"
          tabIndex={0}
          data-scope={org ? 'organization' : 'personal'}
        >
          {org ? (
            <Building2 className="h-3.5 w-3.5" aria-hidden />
          ) : (
            <User className="h-3.5 w-3.5" aria-hidden />
          )}
          {org
            ? t('dashboards.scope.organization', 'Organization-wide')
            : t('dashboards.scope.mine', 'Your scope')}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>{hint}</TooltipContent>
    </Tooltip>
  )
}

export interface DashboardFreshnessProps {
  kind: DashboardKind
  data?: DashboardData
  /** The dashboard's own schedule (empty: organization default). */
  schedule?: DashboardRefreshSchedule
  /** Whether the viewer may change the schedule (owner, or org manager). */
  canSchedule: boolean
  onRefresh: () => Promise<unknown>
  onSchedule: (schedule: DashboardRefreshSchedule) => Promise<unknown>
}

export function DashboardFreshness({
  kind,
  data,
  schedule = '',
  canSchedule,
  onRefresh,
  onSchedule,
}: DashboardFreshnessProps) {
  const { t, locale } = useTranslation()
  const [refreshing, setRefreshing] = useState(false)
  const [saving, setSaving] = useState(false)

  const scheduleLabel = (s: DashboardRefreshSchedule) =>
    s === ''
      ? t('dashboards.schedule.default', 'Organization default')
      : t(`dashboards.schedule.${s}`, s)

  const refresh = async () => {
    setRefreshing(true)
    try {
      await onRefresh()
      toast.success(t('dashboards.refresh.done', 'Figures refreshed'))
    } catch (e) {
      if (e instanceof ApiClientError && e.statusCode === 429) {
        toast.info(
          t(
            'dashboards.refresh.limited',
            'This dashboard was refreshed a moment ago or is refreshing now. Try again in a minute.'
          )
        )
      } else {
        toast.error(getErrorMessage(e))
      }
    } finally {
      setRefreshing(false)
    }
  }

  const changeSchedule = async (value: string) => {
    const next = (value === DEFAULT_VALUE ? '' : value) as DashboardRefreshSchedule
    setSaving(true)
    try {
      await onSchedule(next)
      toast.success(t('dashboards.schedule.saved', 'Refresh schedule saved'))
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const computed = data?.computed_at
  return (
    <div
      className="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-muted-foreground"
      data-testid="dashboard-freshness"
    >
      <ScopeBadge data={data} kind={kind} />
      {computed && (
        <span title={formatAbsoluteTime(computed, locale)}>
          {t('dashboards.freshness.updated', 'Updated {time}', {
            time: formatRelativeTime(computed, locale),
          })}
        </span>
      )}
      {data?.next_refresh_at ? (
        <span title={formatAbsoluteTime(data.next_refresh_at, locale)}>
          {t('dashboards.freshness.next', 'Next refresh {time}', {
            time: formatRelativeTime(data.next_refresh_at, locale),
          })}
        </span>
      ) : (
        data && <span>{t('dashboards.freshness.manual', 'Refreshed on request only')}</span>
      )}
      {data?.stale && (
        <span className="inline-flex items-center gap-1 text-warning" role="status">
          <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
          {data.last_refresh_error
            ? t(
                'dashboards.freshness.failed',
                'The last refresh failed; these are the last good figures.'
              )
            : t('dashboards.freshness.stale', 'These figures are older than their schedule.')}
        </span>
      )}
      {data && !data.facts_built_at && (
        <span role="status">
          {t('dashboards.freshness.building', 'Dashboard data is being built for the first time.')}
        </span>
      )}
      <span className="ms-auto flex items-center gap-2">
        {canSchedule && (
          <Select
            value={schedule === '' ? DEFAULT_VALUE : schedule}
            onValueChange={changeSchedule}
            disabled={saving}
          >
            <SelectTrigger
              className="h-8 w-[11.5rem] text-xs"
              aria-label={t('dashboards.schedule.label', 'Refresh schedule')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SCHEDULE_OPTIONS.map((s) => (
                <SelectItem key={s || DEFAULT_VALUE} value={s || DEFAULT_VALUE}>
                  {scheduleLabel(s)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <Button
          variant="outline"
          size="sm"
          className="h-8"
          onClick={refresh}
          disabled={refreshing || !data}
        >
          <RefreshCw
            className={cn('me-1.5 h-3.5 w-3.5', refreshing && 'animate-spin')}
            aria-hidden
          />
          {t('dashboards.refresh.now', 'Refresh now')}
        </Button>
      </span>
    </div>
  )
}
