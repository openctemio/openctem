'use client'

/** Small shared pieces of the campaign pages: owner, due date, findings progress, tasks. */

import { useCallback } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useOwnerNames } from '@/features/remediation-hub/api/use-owner-names'
import { cn } from '@/lib/utils'
import type { CampaignSummary, RemediationCampaign } from '../api/use-remediation-campaigns'

/** "Sam · Ops", or "Unassigned". */
export function useCampaignOwner() {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  return useCallback(
    (c: Pick<RemediationCampaign, 'assigned_to' | 'assigned_team'>) =>
      [owners.user(c.assigned_to), owners.group(c.assigned_team)].filter(Boolean).join(' · ') ||
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

export function formatDay(iso: string, locale: string) {
  return new Date(iso).toLocaleDateString(locale, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })
}

/** The due date; late shows in the danger tone with the word "overdue", not colour alone. */
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
  let rel = ''
  if (relative && (campaign.status === 'draft' || campaign.status === 'active')) {
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
      {late && ` · ${t('remediationCampaigns.due.overdue')}`}
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
  const pct = Math.min(100, Math.round((summary.closed_findings / summary.findings) * 100))
  const label = t('remediationCampaigns.progress.label', undefined, {
    closed: summary.closed_findings,
    total: summary.findings,
  })
  return (
    <div className={cn('flex min-w-0 items-center gap-2', className)}>
      <div
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        className="bg-muted h-2 w-16 shrink-0 overflow-hidden rounded-full"
      >
        <span className="bg-success block h-full" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-muted-foreground whitespace-nowrap text-xs">
        {t('remediationCampaigns.progress.short', undefined, {
          closed: summary.closed_findings,
          total: summary.findings,
        })}
      </span>
    </div>
  )
}

/** "6 tasks · 1 overdue · 2 hidden", or "none yet". */
export function CampaignTasksCell({ summary }: { summary: CampaignSummary }) {
  const { t } = useTranslation()
  const n = summary.tasks
  if (n === 0 && summary.hidden_tasks === 0) {
    return <span className="text-muted-foreground">{t('remediationCampaigns.tasks.noneYet')}</span>
  }
  return (
    <span className="whitespace-nowrap text-sm">
      {t(`remediationCampaigns.tasks.count.${n === 1 ? 'one' : 'other'}`, undefined, { count: n })}
      {summary.overdue_tasks > 0 && (
        <span className="text-destructive">
          {' · '}
          {t('remediationCampaigns.tasks.overdue', undefined, { count: summary.overdue_tasks })}
        </span>
      )}
      {summary.hidden_tasks > 0 && (
        <span className="text-muted-foreground">
          {' · '}
          {t('remediationCampaigns.tasks.hidden', undefined, { count: summary.hidden_tasks })}
        </span>
      )}
    </span>
  )
}
