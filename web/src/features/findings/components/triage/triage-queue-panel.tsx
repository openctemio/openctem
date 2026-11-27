'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { PriorityClass } from '../../types'
import type { TriageOutcome, TriageSession } from '../../lib/triage-session'
import { PriorityClassBadge } from '../priority-class-badge'
import { FindingTitleCell } from '../cells/finding-title-cell'

const BEFORE = 3
const AFTER = 12

export const OUTCOME_LABELS: Record<TriageOutcome, { key: string; fallback: string }> = {
  confirmed: { key: 'findings.triageMode.outcome.confirmed', fallback: 'Confirmed' },
  fp_requested: { key: 'findings.triageMode.outcome.fpRequested', fallback: 'FP requested' },
  fp_applied: { key: 'findings.triageMode.outcome.fpApplied', fallback: 'False positive' },
  accept_requested: {
    key: 'findings.triageMode.outcome.acceptRequested',
    fallback: 'Acceptance requested',
  },
  accept_applied: { key: 'findings.triageMode.outcome.acceptApplied', fallback: 'Accepted' },
  assigned: { key: 'findings.triageMode.outcome.assigned', fallback: 'Assigned' },
  tasked: { key: 'findings.triageMode.outcome.tasked', fallback: 'Added to a task' },
  retest_requested: { key: 'findings.triageMode.outcome.retest', fallback: 'Retest requested' },
  skipped: { key: 'findings.triageMode.outcome.skipped', fallback: 'Skipped' },
  changed: { key: 'findings.triageMode.outcome.changed', fallback: 'Changed by someone else' },
}

/**
 * The queue around the shown finding, in the queue's order. Shown on demand
 * (the Queue button or `q`) in a side sheet over the page, never as a
 * permanent column: the page shows one finding and its decision.
 */
export function TriageQueuePanel({
  session,
  onSelect,
  className,
}: {
  session: TriageSession
  onSelect: (index: number) => void
  className?: string
}) {
  const { t } = useTranslation()
  const start = Math.max(0, session.index - BEFORE)
  const shown = session.items.slice(start, session.index + AFTER)
  return (
    <nav
      aria-label={t('findings.triageMode.queue', 'Queue')}
      className={cn('p-2', className)}
      data-testid="triage-queue"
    >
      <ol className="space-y-0.5">
        {shown.map((item, i) => {
          const index = start + i
          const current = index === session.index
          const outcome = session.outcomes[item.id]
          return (
            <li key={item.id}>
              <button
                type="button"
                onClick={() => onSelect(index)}
                aria-current={current ? 'true' : undefined}
                className={cn(
                  'grid w-full gap-0.5 rounded-md px-2.5 py-2 text-start text-xs text-muted-foreground hover:bg-muted/60 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                  current && 'bg-muted font-semibold'
                )}
              >
                {outcome ? (
                  <span className="text-xs font-medium">
                    {t(OUTCOME_LABELS[outcome].key, OUTCOME_LABELS[outcome].fallback)}
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5">
                    <PriorityClassBadge
                      priorityClass={item.priorityClass as PriorityClass | undefined}
                      showTooltip={false}
                    />
                    {typeof item.rank === 'number' && (
                      <span className="font-mono tabular-nums">{Math.round(item.rank)}</span>
                    )}
                  </span>
                )}
                <FindingTitleCell
                  className={cn('text-sm', !outcome && 'text-foreground')}
                  title={item.title}
                  target={outcome ? undefined : item.target}
                />
              </button>
            </li>
          )
        })}
      </ol>
    </nav>
  )
}
