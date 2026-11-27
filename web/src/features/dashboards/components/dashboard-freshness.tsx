'use client'

/**
 * Dashboard freshness pieces, laid out by the `/` header:
 * - `DashboardFreshness`: one muted meta line (whose figures, when computed,
 *   next scheduled refresh) plus a status line only when the figures are
 *   stale or still being built;
 * - `RefreshButton`: Refresh now (budgeted on the server), icon-only on a
 *   phone (or at every width with `iconOnly`) with the same accessible name;
 * - `scheduleSubmenu`: the refresh schedule as a submenu of the dashboard's
 *   actions menu, for those who may change it.
 */

import { useEffect, useState } from 'react'
import { AlertTriangle, Building2, Clock, RefreshCw, User } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import type { ActionMenuSubmenu } from '@/components/ui/action-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { EmptyState } from '@/features/shared/components/empty-state'
import { MetaLine } from '@/features/shared/components/text-layout'
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

/** Item ids cannot be empty: the organization default travels as "default". */
const toValue = (s: DashboardRefreshSchedule) => s || 'default'

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
      : t('dashboards.scope.mineHint', 'Figures shown for what you can access.')
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className="inline-flex min-w-0 max-w-full items-center gap-1 rounded-sm font-medium text-foreground/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          tabIndex={0}
          data-scope={org ? 'organization' : 'personal'}
        >
          {org ? (
            <Building2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
          ) : (
            <User className="h-3.5 w-3.5 shrink-0" aria-hidden />
          )}
          <span className="truncate">
            {org
              ? t('dashboards.scope.organization', 'Organization-wide')
              : t('dashboards.scope.mine', 'Your scope')}
          </span>
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

/** Whether a scheduled refresh time has already passed. */
function isDue(at: string): boolean {
  return new Date(at).getTime() <= Date.now()
}

/** Re-renders its component every minute so relative times keep ticking. */
export function useMinuteTick(): number {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setTick((n) => n + 1), 60_000)
    return () => clearInterval(id)
  }, [])
  return tick
}

/**
 * "Your scope", "Updated 2m ago" and "Next in 58m" as one MetaLine (the full
 * times are in the hover text). Always one line, so the page header keeps one
 * height in every state; `DashboardDataNotice` says when the figures are stale
 * or still being built.
 */
export function DashboardFreshness({ kind, data }: DashboardFreshnessProps) {
  const { t, locale } = useTranslation()
  useMinuteTick()
  const computed = data?.computed_at
  const rel = (d: string) => formatRelativeTime(d, locale, new Date(), 'narrow')
  return (
    <div
      className="flex flex-col gap-1 text-xs text-muted-foreground"
      data-testid="dashboard-freshness"
    >
      {/* Below 640px the line shares the title row's width with Refresh and
          More, so it never wraps: the times keep their full width and the
          scope label gives way first (its full rule stays in the hint), and
          the schedule facts are left out visually (a screen reader still
          reads them; the schedule is also in More). One line means the
          header keeps its height when the minute tick lengthens a time. */}
      <MetaLine
        data-testid="dashboard-meta"
        className="max-sm:flex-nowrap max-sm:[&>span:not(:first-child)]:shrink-0 max-sm:[&>span:not(:first-child)]:whitespace-nowrap"
        items={[
          <ScopeBadge key="scope" data={data} kind={kind} />,
          computed && (
            <span key="updated" title={formatAbsoluteTime(computed, locale)}>
              {t('dashboards.freshness.updated', 'Updated {time}', { time: rel(computed) })}
            </span>
          ),
          data?.next_refresh_at ? (
            <span
              key="next"
              className="sr-only sm:not-sr-only"
              title={formatAbsoluteTime(data.next_refresh_at, locale)}
            >
              {/* A schedule time already passed reads as due, never "Next 21s ago". */}
              {isDue(data.next_refresh_at)
                ? t('dashboards.freshness.due', 'Refresh due')
                : t('dashboards.freshness.next', 'Next {time}', {
                    time: rel(data.next_refresh_at),
                  })}
            </span>
          ) : (
            data && (
              <span key="manual" className="sr-only sm:not-sr-only">
                {t('dashboards.freshness.manual', 'Refreshed on request only')}
              </span>
            )
          ),
        ]}
      />
    </div>
  )
}

/** Whether the figures need a notice: still being built, or stale. */
export function hasDataNotice(data?: DashboardData): boolean {
  return !!data && (!data.facts_built_at || !!data.stale)
}

/**
 * The organization's figures are being counted for the first time and no
 * widget has a figure yet: the page shows one notice instead of a box per
 * widget that each says the same.
 */
export function isFirstBuild(data?: DashboardData): boolean {
  return !!data && !data.facts_built_at && data.widgets.every((w) => w.state !== 'ready')
}

/**
 * One notice for the first count of the figures: what is happening and
 * when the figures come (the page reads them again every 15 s while it
 * runs, so they appear without a reload).
 */
export function DashboardFirstBuild() {
  const { t } = useTranslation()
  return (
    <div role="status" data-testid="dashboard-first-build">
      <EmptyState
        icon={Clock}
        title={t('dashboards.firstBuild.title', 'Your figures are being prepared')}
        description={t(
          'dashboards.firstBuild.description',
          'The first count of your data usually takes a few minutes. The figures appear here by themselves when they are ready.'
        )}
      />
    </div>
  )
}

/**
 * Why the figures may not be current: still being built for the first time,
 * or older than their schedule (with the last refresh's failure). Under the
 * page header, never inside it, so a notice never moves the header's
 * controls. When another note shows under the header (the seeded layout, a
 * layout hint), the notice opens that note's line (`inline`) instead of
 * taking a row of its own. Building wins over stale: nothing older exists yet.
 */
export function DashboardDataNotice({
  data,
  inline,
}: {
  data?: DashboardData
  /** A run of text that opens another note's line, not a line of its own. */
  inline?: boolean
}) {
  const { t } = useTranslation()
  if (!data || !hasDataNotice(data)) return null
  const building = !data.facts_built_at
  const Icon = building ? Clock : AlertTriangle
  const tone = building ? 'text-muted-foreground' : 'text-warning'
  const text = building
    ? t('dashboards.freshness.building', 'Dashboard data is being built for the first time.')
    : data.last_refresh_error
      ? t(
          'dashboards.freshness.failed',
          'The last refresh failed; these are the last good figures.'
        )
      : t('dashboards.freshness.stale', 'These figures are older than their schedule.')
  if (inline)
    return (
      <span className={tone} role="status" data-testid="dashboard-data-notice">
        <Icon className="me-1.5 inline h-4 w-4 align-[-3px]" aria-hidden />
        {text}
      </span>
    )
  return (
    <p
      className={cn('flex items-start gap-1.5 text-sm', tone)}
      role="status"
      data-testid="dashboard-data-notice"
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      {text}
    </p>
  )
}

/**
 * Refresh now. On a phone it is a 44px icon button whose accessible name is
 * still "Refresh now"; from 640px the label shows. Spins while refreshing.
 */
export function RefreshButton({
  onRefresh,
  disabled,
  iconOnly,
}: {
  onRefresh: () => Promise<unknown>
  disabled?: boolean
  /** Icon-only at every width (the dashboard header); the name stays "Refresh now". */
  iconOnly?: boolean
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
  const label = t('dashboards.refresh.now', 'Refresh now')
  if (iconOnly)
    return (
      <Button
        variant="outline"
        size="icon-sm"
        className="shrink-0"
        onClick={refresh}
        disabled={refreshing || disabled}
        aria-busy={refreshing || undefined}
        aria-label={label}
        title={label}
        data-testid="dashboard-refresh"
      >
        <RefreshCw className={cn('h-4 w-4', refreshing && 'animate-spin')} aria-hidden />
      </Button>
    )
  return (
    <Button
      iconOnlyBelow="sm"
      variant="outline"
      size="sm"
      className="shrink-0"
      onClick={refresh}
      disabled={refreshing || disabled}
      aria-busy={refreshing || undefined}
      data-testid="dashboard-refresh"
    >
      <RefreshCw
        className={cn('h-4 w-4 sm:me-1.5 sm:h-3.5 sm:w-3.5', refreshing && 'animate-spin')}
        aria-hidden
      />
      <span className="sr-only sm:not-sr-only">{label}</span>
    </Button>
  )
}

export interface ScheduleControlProps {
  /** The dashboard's own schedule (empty: organization default). */
  schedule?: DashboardRefreshSchedule
  onSchedule: (schedule: DashboardRefreshSchedule) => Promise<unknown>
}

/**
 * The refresh schedule inside the dashboard's actions menu: a submenu with
 * one item per schedule; the saved one says "(current)" and does nothing.
 */
export function scheduleSubmenu(
  t: ReturnType<typeof useTranslation>['t'],
  schedule: DashboardRefreshSchedule = '',
  onSchedule: ScheduleControlProps['onSchedule']
): ActionMenuSubmenu {
  const label = (s: DashboardRefreshSchedule) =>
    s === ''
      ? t('dashboards.schedule.default', 'Organization default')
      : t(`dashboards.schedule.${s}`, s)
  return {
    kind: 'sub',
    id: 'schedule',
    label: t('dashboards.schedule.label', 'Refresh schedule'),
    icon: Clock,
    items: SCHEDULE_OPTIONS.map((s) => {
      const current = toValue(s) === toValue(schedule)
      return {
        id: `schedule:${toValue(s)}`,
        label: current
          ? t('dashboards.schedule.current', '{label} (current)', { label: label(s) })
          : label(s),
        onSelect: () => {
          if (current) return
          onSchedule(s).catch((e) => toast.error(getErrorMessage(e)))
        },
      }
    }),
  }
}
