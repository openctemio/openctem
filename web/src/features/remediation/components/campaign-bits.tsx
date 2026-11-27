'use client'

/** Small shared pieces of the campaign pages: owner, due date, findings progress, tasks. */

import { useCallback } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useOwnerNames } from '@/features/remediation-hub/api/use-owner-names'
import { cn } from '@/lib/utils'
import { ProgressCell } from '@/features/shared/components/progress-cell'
import type { CampaignSummary, RemediationCampaign } from '../api/use-remediation-campaigns'
import { formatDate } from '@/lib/app-locale'
import { slaCountdown, slaCountLabel } from '@/features/sla/lib/sla'
import { slaStateClass } from '@/lib/sla-colors'

/** "Sam · Ops", or "Unassigned". */
export function useCampaignOwner() {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  return useCallback(
    (c: Pick<RemediationCampaign, 'assigned_to' | 'assigned_team'>) =>
      [owners.user(c.assigned_to), owners.group(c.assigned_team)].filter(Boolean).join(', ') ||
      t('remediationCampaigns.owner.unassigned'),
    [owners, t]
  )
}

/** One rule for when a campaign counts as late: the server's is_overdue. */
function isLate(c: Pick<RemediationCampaign, 'is_overdue' | 'status'>) {
  return c.is_overdue && (c.status === 'draft' || c.status === 'active')
}

/** Whole days from now until a date (negative once past). */
export function daysUntil(iso: string, now = Date.now()): number {
  return Math.round((Date.parse(iso) - now) / 86_400_000)
}

export function formatDay(iso: string, _locale: string) {
  return formatDate(new Date(iso), {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })
}

/**
 * The due date. In a list (no `relative`): the short date ("Apr 29", with the
 * year only when it is not this one) and, when late, a small "23 d overdue"
 * pill in the danger tone, so the cell stays within its column and the full
 * date sits in the title. On a detail page (`relative`): the long date with
 * "in 12 days" / "3 days ago" and the word "overdue".
 */
export function CampaignDue({
  campaign,
  relative,
}: {
  campaign: Pick<RemediationCampaign, 'due_date' | 'is_overdue' | 'status'>
  /** Add "in 12 days" / "3 days ago". */
  relative?: boolean
}) {
  const { t, locale } = useTranslation()
  if (!campaign.due_date) {
    return <span className="text-muted-foreground">{t('remediationCampaigns.due.none')}</span>
  }
  const late = isLate(campaign)
  const days = daysUntil(campaign.due_date)
  if (!relative) {
    const due = new Date(campaign.due_date)
    const sameYear = due.getFullYear() === new Date().getFullYear()
    const short = formatDate(due, {
      day: 'numeric',
      month: 'short',
      ...(sameYear ? {} : { year: 'numeric' }),
    })
    const c = late ? slaCountdown(campaign.due_date) : null
    const mark = c
      ? t(`remediationCampaigns.due.overdue${c.unit === 'hours' ? 'Hours' : 'Days'}`, undefined, {
          count: slaCountLabel(c.count),
        })
      : null
    const full = formatDay(campaign.due_date, locale)
    return (
      <span
        data-slot="campaign-due"
        className="inline-flex items-center gap-1.5 whitespace-nowrap"
        title={mark ? `${full}, ${mark}` : full}
      >
        <span>{short}</span>
        {mark && (
          <span
            className={cn(
              'shrink-0 rounded-md border px-2 py-0.5 text-xs font-medium tabular-nums',
              slaStateClass('overdue')
            )}
          >
            {mark}
          </span>
        )}
      </span>
    )
  }
  let rel = ''
  if (campaign.status === 'draft' || campaign.status === 'active') {
    if (days > 0)
      rel = t(`remediationCampaigns.due.inDays.${days === 1 ? 'one' : 'other'}`, undefined, {
        count: days,
      })
    else if (days === 0) rel = t('remediationCampaigns.due.today')
    else
      rel = t(`remediationCampaigns.due.daysAgo.${days === -1 ? 'one' : 'other'}`, undefined, {
        count: -days,
      })
  }
  return (
    <span className={cn('whitespace-nowrap', late && 'text-destructive font-medium')}>
      {formatDay(campaign.due_date, locale)}
      {rel && ` (${rel})`}
      {late && `, ${t('remediationCampaigns.due.overdue')}`}
    </span>
  )
}

/** Findings closed of the findings of the visible tasks, as a named progress bar. */
export function FindingsProgress({
  summary,
  className,
}: {
  summary: Pick<CampaignSummary, 'findings' | 'closed_findings'>
  className?: string
}) {
  const { t } = useTranslation()
  if (!summary.findings) {
    return (
      <span className="text-muted-foreground" aria-label={t('remediationCampaigns.progress.none')}>
        —
      </span>
    )
  }
  return (
    <ProgressCell
      className={className}
      max={summary.findings}
      parts={[{ value: summary.closed_findings, tone: 'success' }]}
      caption={t('remediationCampaigns.progress.short', undefined, {
        closed: summary.closed_findings,
        total: summary.findings,
      })}
      label={t('remediationCampaigns.progress.label', undefined, {
        closed: summary.closed_findings,
        total: summary.findings,
      })}
    />
  )
}

/**
 * "6 tasks" with "1 overdue, 2 hidden" under it, or "none yet". In a phone
 * card (`inline`) it is one line.
 */
export function CampaignTasksCell({
  summary,
  inline,
}: {
  summary: CampaignSummary
  inline?: boolean
}) {
  const { t } = useTranslation()
  const n = summary.tasks
  if (n === 0 && summary.hidden_tasks === 0) {
    return <span className="text-muted-foreground">{t('remediationCampaigns.tasks.noneYet')}</span>
  }
  const count = t(`remediationCampaigns.tasks.count.${n === 1 ? 'one' : 'other'}`, undefined, {
    count: n,
  })
  const overdue =
    summary.overdue_tasks > 0
      ? t('remediationCampaigns.tasks.overdue', undefined, { count: summary.overdue_tasks })
      : null
  const hidden =
    summary.hidden_tasks > 0
      ? t('remediationCampaigns.tasks.hidden', undefined, { count: summary.hidden_tasks })
      : null
  const extras = (
    <>
      {overdue && <span className="text-destructive">{overdue}</span>}
      {overdue && hidden && ', '}
      {hidden && <span className="text-muted-foreground">{hidden}</span>}
    </>
  )
  if (inline) {
    return (
      <span className="whitespace-nowrap text-sm">
        {count}
        {(overdue || hidden) && ', '}
        {extras}
      </span>
    )
  }
  return (
    <span
      className="block min-w-0 text-sm"
      title={[count, overdue, hidden].filter(Boolean).join(', ')}
    >
      <span className="block truncate">{count}</span>
      {(overdue || hidden) && <span className="block truncate text-xs">{extras}</span>}
    </span>
  )
}
