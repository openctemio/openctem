'use client'

/** Small shared pieces of the remediation hub: state, deadline, progress. */

import { useTranslation } from '@/context/i18n-provider'
import { TonePill } from '@/features/shared/components/tone-pill'
import { StatusChip } from '@/features/shared/components/status-chip'
import Link from '@/components/link'
import { cn } from '@/lib/utils'
import { useRemediationCampaign } from '@/features/remediation/api/use-remediation-campaigns'
import type { RemediationTask, TaskState } from '../api/types'
import { DEADLINE_TONE, deadlineStatus, progressParts } from '../lib/hub'

export function useTaskStateLabel() {
  const { t } = useTranslation()
  return (s: TaskState) => t(`remediationHub.state.${s}`)
}

/** A task state from the one status registry (lib/status-tones.ts). */
export function TaskStatePill({ state, className }: { state: TaskState; className?: string }) {
  const { t } = useTranslation()
  return (
    <StatusChip
      domain="remediationTask"
      value={state}
      title={t(`remediationHub.stateHint.${state}`)}
      className={className}
    />
  )
}

/** The task deadline with its status, and what set it. */
export function DeadlinePill({
  task,
}: {
  task: Pick<RemediationTask, 'deadline' | 'deadline_source'>
}) {
  const { t, locale } = useTranslation()
  const status = deadlineStatus(task.deadline)
  if (status === 'none' || !task.deadline) {
    return (
      <span className="text-muted-foreground text-xs">{t('remediationHub.deadline.none')}</span>
    )
  }
  const date = new Date(task.deadline).toLocaleDateString(locale, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })
  return (
    <TonePill
      tone={DEADLINE_TONE[status]}
      label={date}
      title={
        task.deadline_source
          ? t(`remediationHub.deadline.source.${task.deadline_source}`)
          : undefined
      }
      state={status}
    />
  )
}

/** Verified / closed / claimed / open as one bar, with an accessible summary. */
export function TaskProgress({
  task,
  className,
}: {
  task: Pick<RemediationTask, 'counts'>
  className?: string
}) {
  const { t } = useTranslation()
  const p = progressParts(task)
  const pct = (n: number) => (p.total ? `${(n / p.total) * 100}%` : '0%')
  const summary = t('remediationHub.progress.summary', undefined, {
    verified: p.verified,
    closed: p.closed,
    claimed: p.claimed,
    open: p.open,
    total: p.total,
  })
  return (
    <div className={cn('min-w-0', className)}>
      <div
        className="bg-muted flex h-2 w-full overflow-hidden rounded-full"
        role="img"
        aria-label={summary}
        title={summary}
      >
        <span className="bg-success" style={{ width: pct(p.verified) }} />
        <span className="bg-muted-foreground/50" style={{ width: pct(p.closed) }} />
        <span className="bg-info" style={{ width: pct(p.claimed) }} />
      </div>
    </div>
  )
}

/** The campaign a task belongs to, as a link (its name once it loads). */
export function TaskCampaignLink({ campaignId }: { campaignId: string }) {
  const { t } = useTranslation()
  const { data } = useRemediationCampaign(campaignId)
  return (
    <p className="mt-1 text-xs">
      <Link href={`/remediation/campaigns/${campaignId}`} className="underline">
        {data?.name
          ? t('remediationCampaigns.taskLink.named', undefined, { name: data.name })
          : t('remediationCampaigns.taskLink.unnamed')}
      </Link>
    </p>
  )
}
