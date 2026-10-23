'use client'

/**
 * The priority score breakdown shown inside "Why it matters" (the factors
 * themselves are rendered by finding-why-it-matters.tsx).
 */

import { useTranslation } from '@/context/i18n-provider'
import { Progress } from '@/components/ui/progress'
import type { PriorityScoreBreakdown } from '../../api/use-finding-priority-explanation'

/** One labeled 0-5 sub-score row with a compact meter. */
function SubScoreRow({ label, value }: { label: string; value: number }) {
  const clamped = Math.max(0, Math.min(5, value))
  return (
    <div className="grid grid-cols-[7rem_1fr_2.5rem] items-center gap-2">
      <span className="text-muted-foreground text-xs">{label}</span>
      <Progress value={(clamped / 5) * 100} className="h-1.5" />
      <span className="text-right text-xs tabular-nums">{clamped.toFixed(1)}</span>
    </div>
  )
}

/**
 * Transparent composite score (ctem.org prioritization model). Read-only: it
 * EXPLAINS the class above, it does not decide it — the P0-P3 cascade stays
 * authoritative. Shown only when the backend supplies the breakdown.
 */
export function ScoreBreakdown({ breakdown }: { breakdown: PriorityScoreBreakdown }) {
  const { t } = useTranslation()
  const reductionPct = Math.round(breakdown.control_reduction * 100)
  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs font-medium">
          {t('findings.priorityCard.score', 'Priority score')}
        </span>
        <span className="text-sm font-semibold tabular-nums">
          {breakdown.score.toFixed(1)}
          <span className="text-muted-foreground ml-0.5 text-xs font-normal">/ 15</span>
        </span>
      </div>
      <div className="space-y-1.5">
        <SubScoreRow label={t('findings.priorityCard.impact', 'Impact')} value={breakdown.impact} />
        <SubScoreRow
          label={t('findings.priorityCard.likelihood', 'Likelihood')}
          value={breakdown.likelihood}
        />
        <SubScoreRow
          label={t('findings.priorityCard.expo', 'Exposure')}
          value={breakdown.exposure}
        />
      </div>
      <p className="text-muted-foreground text-xs leading-relaxed">
        {t('findings.priorityCard.formula', '(Impact + Likelihood + Exposure)')}
        {reductionPct > 0
          ? t('findings.priorityCard.formulaControls', ' × (1 − {pct}% controls)', {
              pct: reductionPct,
            })
          : ''}
        {t(
          'findings.priorityCard.formulaNote',
          ' · sub-scores 0–5. Explains the class, does not change it.'
        )}
      </p>
    </div>
  )
}
