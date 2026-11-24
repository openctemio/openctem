'use client'

/**
 * The fix plan of the external surface posture: the most effective fixes
 * first, each with the score and grade once it is done. The Posture page lists
 * the whole plan; the Overview's posture section the first few.
 */

import Link from '@/components/link'
import { PostureGrade } from '@/components/dashboard-kit'
import { assetDetailHref, isLinkableAssetId } from '@/features/findings/lib/asset-link'
import { useTranslation } from '@/context/i18n-provider'
import type { PosturePlanStep } from '../lib/posture'

export function PosturePlanList({ steps }: { steps: readonly PosturePlanStep[] }) {
  const { t } = useTranslation()
  return (
    <ol className="flex flex-col divide-y" data-testid="posture-plan">
      {steps.map((s, i) => (
        <li
          key={`${s.asset_id ?? 'none'}-${s.category}`}
          className="flex items-center justify-between gap-3 py-2 text-sm"
        >
          <span className="flex min-w-0 items-baseline gap-2">
            <span className="w-5 shrink-0 text-xs text-muted-foreground tabular-nums">{i + 1}</span>
            <span className="flex min-w-0 flex-col">
              {s.asset_id && isLinkableAssetId(s.asset_id) ? (
                <Link href={assetDetailHref(s.asset_id)} className="truncate hover:underline">
                  {s.asset_name}
                </Link>
              ) : (
                <span className="truncate">
                  {s.asset_name || t('attackSurface.posture.noAsset', 'Issues without an asset')}
                </span>
              )}
              <span className="flex gap-2 text-xs text-muted-foreground">
                <span>{t(`dashboardKit.posture.category.${s.category}`, s.category)}</span>
                <span>
                  {t('dashboardKit.posture.issues', '{count} issues', {
                    count: s.issues,
                  })}
                </span>
              </span>
            </span>
          </span>
          <span className="flex shrink-0 items-center gap-2 tabular-nums">
            <span>{s.score_after}</span>
            <PostureGrade grade={s.grade_after} score={s.score_after} size="sm" />
          </span>
        </li>
      ))}
    </ol>
  )
}
