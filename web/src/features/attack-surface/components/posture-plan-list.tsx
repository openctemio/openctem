'use client'

/**
 * The fix plan of the external surface posture: the most effective fixes
 * first. The Posture page lists the whole plan; the Overview's posture
 * section the first few.
 *
 * Each row says what is distinct about it (the asset and how many issues it
 * carries). Consecutive steps of one category sit under one category heading,
 * and the score and grade show only on the step that changes them: a long run
 * of fixes that each leave "53 F" unchanged says so once, not on every row.
 * A long plan shows its first steps and the rest on demand.
 */

import { useState } from 'react'
import { PostureGrade } from '@/components/dashboard-kit'
import { Button } from '@/components/ui/button'
import { AssetPeekLink } from '@/features/assets/components/asset-peek'
import { useTranslation } from '@/context/i18n-provider'
import type { PosturePlanStep } from '../lib/posture'

/** How many steps show before "Show more". */
export const PLAN_VISIBLE = 8

interface PlanSection {
  category: string
  steps: { step: PosturePlanStep; index: number; changes: boolean }[]
}

/**
 * The steps in sections of one category each (consecutive runs), each step
 * marked when its score after differs from the one before it (the first step
 * against the current score, when known).
 */
export function planSections(
  steps: readonly PosturePlanStep[],
  currentScore?: number
): PlanSection[] {
  const out: PlanSection[] = []
  let prev = currentScore
  steps.forEach((step, index) => {
    const changes = prev === undefined || step.score_after !== prev
    prev = step.score_after
    const last = out[out.length - 1]
    if (last && last.category === step.category) last.steps.push({ step, index, changes })
    else out.push({ category: step.category, steps: [{ step, index, changes }] })
  })
  return out
}

export function PosturePlanList({
  steps,
  currentScore,
  limit = PLAN_VISIBLE,
}: {
  steps: readonly PosturePlanStep[]
  /** The score now: a step that leaves it unchanged shows no score. */
  currentScore?: number
  /** Steps shown before "Show more"; the rest on demand. */
  limit?: number
}) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const shown = all ? steps : steps.slice(0, limit)
  const hidden = steps.length - shown.length
  const sections = planSections(shown, currentScore)
  return (
    <div className="flex flex-col gap-2">
      <ol className="flex flex-col" data-testid="posture-plan">
        {sections.map((sec, si) => (
          <li key={`${sec.category}-${si}`} className="flex flex-col">
            <span className="pt-2 pb-1 text-xs font-medium text-muted-foreground">
              {t(`dashboardKit.posture.category.${sec.category}`, sec.category)}
            </span>
            <ol className="flex flex-col divide-y">
              {sec.steps.map(({ step: s, index, changes }) => (
                <li
                  key={`${s.asset_id ?? 'none'}-${s.category}-${index}`}
                  className="flex items-center justify-between gap-3 py-2 text-sm"
                  data-testid="posture-plan-step"
                >
                  <span className="flex min-w-0 items-baseline gap-2">
                    <span className="w-5 shrink-0 text-xs text-muted-foreground tabular-nums">
                      {index + 1}
                    </span>
                    <span className="flex min-w-0 flex-col">
                      {s.asset_name ? (
                        // A row opens its asset the one way every attack
                        // surface view does; an id that is not an asset's
                        // stays plain text.
                        <AssetPeekLink assetId={s.asset_id} className="truncate">
                          {s.asset_name}
                        </AssetPeekLink>
                      ) : (
                        <span className="truncate">
                          {t('attackSurface.posture.noAsset', 'Issues without an asset')}
                        </span>
                      )}
                      <span className="text-xs text-muted-foreground tabular-nums">
                        {t('dashboardKit.posture.issues', '{count} issues', {
                          count: s.issues,
                        })}
                      </span>
                    </span>
                  </span>
                  {changes && (
                    <span
                      className="flex shrink-0 items-center gap-2 tabular-nums"
                      data-testid="posture-plan-score"
                    >
                      <span>{s.score_after}</span>
                      <PostureGrade grade={s.grade_after} score={s.score_after} size="sm" />
                    </span>
                  )}
                </li>
              ))}
            </ol>
          </li>
        ))}
      </ol>
      {hidden > 0 && (
        <Button
          variant="outline"
          size="sm"
          className="self-start"
          onClick={() => setAll(true)}
          data-testid="posture-plan-more"
        >
          {t('common.table.showMore', 'Show {count} more', { count: hidden })}
        </Button>
      )}
    </div>
  )
}
