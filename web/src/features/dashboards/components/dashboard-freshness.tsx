'use client'

/**
 * Dashboard freshness pieces, laid out by the `/` header:
 * - `DashboardFreshness`: one muted meta line (whose figures, when computed,
 *   next scheduled refresh) plus a status line only when the figures are
 *   stale or still being built;
 * - `RefreshButton`: Refresh now (budgeted on the server), icon-only on a
 *   phone with the same accessible name;
 * - `ScheduleSelect` (toolbar, from 640px) and `ScheduleMenuItems` (the
 *   actions menu on a phone) for those who may change the schedule.
 */

import { useEffect, useState } from 'react'
import { AlertTriangle, Building2, Clock, RefreshCw, User } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
} from '@/components/ui/dropdown-menu'
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

const toValue = (s: DashboardRefreshSchedule) => s || DEFAULT_VALUE
const fromValue = (v: string) => (v === DEFAULT_VALUE ? '' : v) as DashboardRefreshSchedule

function useScheduleLabel() {
  const { t } = useTranslation()
  return (s: DashboardRefreshSchedule) =>
    s === ''
      ? t('dashboards.schedule.default', 'Organization default')
      : t(`dashboards.schedule.${s}`, s)
}

/** Whose figures these are: an icon and a short label, the full rule on hover or focus. */
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
        <span
          className="inline-flex shrink-0 items-center gap-1 rounded-sm font-medium text-foreground/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
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
        </span>
      </TooltipTrigger>
      <TooltipContent>{hint}</TooltipContent>
    </Tooltip>
  )
}

export interface DashboardFreshnessProps {
  kind: DashboardKind
  data?: DashboardData
}

/**
 * "Your scope · Updated 2m ago · Next in 58m" on one line; the next refresh
 * truncates first on a narrow screen (the full times are in the hover text), and a
 * status line under it only when the figures are stale or still being built.
 */
/** Re-renders its component every minute so relative times keep ticking. */
export function useMinuteTick(): number {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setTick((n) => n + 1), 60_000)
    return () => clearInterval(id)
  }, [])
  return tick
}

export function DashboardFreshness({ kind, data }: DashboardFreshnessProps) {
  const { t, locale } = useTranslation()
  useMinuteTick()
  const computed = data?.computed_at
  const rel = (d: string) => formatRelativeTime(d, locale, new Date(), 'narrow')
  const sep = (
    <span aria-hidden className="shrink-0 px-1.5">
      ·
    </span>
  )
  return (
    <div
      className="flex flex-col gap-1 text-xs text-muted-foreground"
      data-testid="dashboard-freshness"
    >
      <p className="flex min-w-0 items-center" data-testid="dashboard-meta">
        <ScopeBadge data={data} kind={kind} />
        {computed && (
          <>
            {sep}
            <span className="shrink-0" title={formatAbsoluteTime(computed, locale)}>
              {t('dashboards.freshness.updated', 'Updated {time}', { time: rel(computed) })}
            </span>
          </>
        )}
        {data?.next_refresh_at ? (
          <>
            {sep}
            <span
              className="min-w-0 truncate"
              title={formatAbsoluteTime(data.next_refresh_at, locale)}
            >
              {t('dashboards.freshness.next', 'Next {time}', {
                time: rel(data.next_refresh_at),
              })}
            </span>
          </>
        ) : (
          data && (
            <>
              {sep}
              <span className="min-w-0 truncate">
                {t('dashboards.freshness.manual', 'Refreshed on request only')}
              </span>
            </>
          )
        )}
      </p>
      {data?.stale && (
        <p className="flex items-start gap-1 text-warning" role="status">
          <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
          {data.last_refresh_error
            ? t(
                'dashboards.freshness.failed',
                'The last refresh failed; these are the last good figures.'
              )
            : t('dashboards.freshness.stale', 'These figures are older than their schedule.')}
        </p>
      )}
      {data && !data.facts_built_at && (
        <p role="status">
          {t('dashboards.freshness.building', 'Dashboard data is being built for the first time.')}
        </p>
      )}
    </div>
  )
}

/**
 * Refresh now. On a phone it is a 44px icon button whose accessible name is
 * still "Refresh now"; from 640px the label shows. Spins while refreshing.
 */
export function RefreshButton({
  onRefresh,
  disabled,
}: {
  onRefresh: () => Promise<unknown>
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const [refreshing, setRefreshing] = useState(false)
  const refresh = async () => {
    setRefreshing(true)
    try {
      // The Updated line changes: no toast for a change the viewer sees.
      await onRefresh()
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
  return (
    <Button
      variant="outline"
      size="sm"
      className="h-11 w-11 shrink-0 px-0 sm:h-8 sm:w-auto sm:px-3"
      onClick={refresh}
      disabled={refreshing || disabled}
      aria-busy={refreshing || undefined}
      data-testid="dashboard-refresh"
    >
      <RefreshCw
        className={cn('h-4 w-4 sm:me-1.5 sm:h-3.5 sm:w-3.5', refreshing && 'animate-spin')}
        aria-hidden
      />
      <span className="sr-only sm:not-sr-only">{t('dashboards.refresh.now', 'Refresh now')}</span>
    </Button>
  )
}

function useScheduleChange(onSchedule: (s: DashboardRefreshSchedule) => Promise<unknown>) {
  const [saving, setSaving] = useState(false)
  const change = async (value: string) => {
    setSaving(true)
    try {
      // The select shows the saved value: no success toast.
      await onSchedule(fromValue(value))
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setSaving(false)
    }
  }
  return { saving, change }
}

export interface ScheduleControlProps {
  /** The dashboard's own schedule (empty: organization default). */
  schedule?: DashboardRefreshSchedule
  onSchedule: (schedule: DashboardRefreshSchedule) => Promise<unknown>
  className?: string
}

/** The schedule picker in the toolbar (from 640px). */
export function ScheduleSelect({ schedule = '', onSchedule, className }: ScheduleControlProps) {
  const { t } = useTranslation()
  const label = useScheduleLabel()
  const { saving, change } = useScheduleChange(onSchedule)
  return (
    <Select value={toValue(schedule)} onValueChange={change} disabled={saving}>
      <SelectTrigger
        size="sm"
        className={cn('w-auto gap-1.5', className)}
        aria-label={t('dashboards.schedule.label', 'Refresh schedule')}
      >
        <Clock className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {SCHEDULE_OPTIONS.map((s) => (
          <SelectItem key={toValue(s)} value={toValue(s)}>
            {label(s)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

/** The same choice as radio items inside the dashboard's actions menu (phone). */
export function ScheduleMenuItems({ schedule = '', onSchedule, className }: ScheduleControlProps) {
  const { t } = useTranslation()
  const label = useScheduleLabel()
  const { saving, change } = useScheduleChange(onSchedule)
  return (
    <div className={className}>
      <DropdownMenuLabel className="flex items-center gap-1.5 text-xs font-normal text-muted-foreground">
        <Clock className="h-3.5 w-3.5" aria-hidden />
        {t('dashboards.schedule.label', 'Refresh schedule')}
      </DropdownMenuLabel>
      <DropdownMenuRadioGroup value={toValue(schedule)} onValueChange={change}>
        {SCHEDULE_OPTIONS.map((s) => (
          <DropdownMenuRadioItem
            key={toValue(s)}
            value={toValue(s)}
            disabled={saving}
            className="min-h-11 sm:min-h-8"
          >
            {label(s)}
          </DropdownMenuRadioItem>
        ))}
      </DropdownMenuRadioGroup>
    </div>
  )
}
