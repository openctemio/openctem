'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { PriorityClass } from '../../types'
import type { TriageOutcome, TriageSession } from '../../lib/triage-session'
import { PriorityClassBadge } from '../priority-class-badge'

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
  skipped: { key: 'findings.triageMode.outcome.skipped', fallback: 'Skipped' },
  changed: { key: 'findings.triageMode.outcome.changed', fallback: 'Changed by someone else' },
}

/**
 * The queue around the shown finding, in the queue's order. Hidden on
 * phones (the top bar carries the position there).
 */
export function TriageQueuePanel({
  session,
  onSelect,
}: {
  session: TriageSession
  onSelect: (index: number) => void
}) {
  const { t } = useTranslation()
  const start = Math.max(0, session.index - BEFORE)
  const shown = session.items.slice(start, session.index + AFTER)
  return (
    <nav
      aria-label={t('findings.triageMode.queue', 'Queue')}
      className="hidden min-h-0 overflow-y-auto border-e bg-background p-2 lg:block"
      data-testid="triage-queue"
    >
      <p className="px-2 pt-1 pb-2 text-xs font-medium text-muted-foreground">
        {t('findings.triageMode.queueOrder', 'Queue, in the list order')}
      </p>
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
                  current && 'bg-card font-semibold shadow-[inset_0_0_0_1px_var(--border)]'
                )}
              >
                {outcome ? (
                  <span className="font-mono text-xs font-semibold tracking-wide uppercase">
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
                <span
                  dir="auto"
                  className={cn(
                    'truncate text-sm [unicode-bidi:isolate]',
                    outcome ? 'font-normal' : 'text-foreground'
                  )}
                >
                  {item.title}
                </span>
                {item.assetName && !outcome && (
                  <span dir="auto" className="truncate [unicode-bidi:isolate]">
                    {item.assetName}
                  </span>
                )}
              </button>
            </li>
          )
        })}
      </ol>
    </nav>
  )
}
