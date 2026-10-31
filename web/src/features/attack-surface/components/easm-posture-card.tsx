'use client'

/**
 * The posture card of the Attack surface overview: grade, score, the change
 * since the last computation, the categories that take the most points and
 * a link to the Posture page.
 */

import Link from '@/components/link'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { PostureCategoryList, PostureHeadline } from '@/components/dashboard-kit'
import { RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { usePosture } from '../hooks/use-posture'
import { scoreDelta, topDeductions, type PostureResponse } from '../lib/posture'

export const POSTURE_HREF = '/attack-surface/posture'

/** The next-grade sentence shared by the card and the page. */
export function useNextGradeSentence() {
  const { t } = useTranslation()
  return (p: PostureResponse): string => {
    if (!p.plan.target) return t('attackSurface.posture.topGrade', 'Top grade: keep it there.')
    if (p.plan.reached)
      return t(
        'attackSurface.posture.nextReached',
        'Fix {count} items to reach {grade} ({floor}).',
        {
          count: p.plan.steps.length,
          grade: p.plan.target,
          floor: p.plan.floor ?? 0,
        }
      )
    return t(
      'attackSurface.posture.nextFar',
      'Next grade {grade} at {floor}: work through the fix plan.',
      {
        grade: p.plan.target,
        floor: p.plan.floor ?? 0,
      }
    )
  }
}

export function EASMPostureCard() {
  const { t } = useTranslation()
  const { posture, error, isLoading } = usePosture()
  const next = useNextGradeSentence()

  let body: React.ReactNode
  if (isLoading && !posture) {
    body = <Skeleton className="h-28 w-full" />
  } else if (error || !posture) {
    body = (
      <p className="text-sm text-muted-foreground">
        {t('attackSurface.posture.loadFailed', 'Could not load the posture.')}
      </p>
    )
  } else if (posture.state.building) {
    body = (
      <p className="text-sm text-muted-foreground" data-testid="posture-building">
        {t(
          'attackSurface.posture.building',
          'The first posture computation is running. It appears here within a few minutes.'
        )}
      </p>
    )
  } else if (!posture.score.measured) {
    body = (
      <p className="text-sm text-muted-foreground">
        {t(
          'attackSurface.posture.noSurface',
          'No surface asset in your view yet, so there is no grade.'
        )}
      </p>
    )
  } else {
    const delta = scoreDelta(posture)
    const top = topDeductions(posture.score.categories)
    body = (
      <div className="flex flex-col gap-3">
        <PostureHeadline
          grade={posture.score.grade}
          score={posture.score.score}
          caption={
            delta != null && delta !== 0
              ? delta > 0
                ? t('attackSurface.posture.up', 'Up {n} since the last computation', { n: delta })
                : t('attackSurface.posture.down', 'Down {n} since the last computation', {
                    n: -delta,
                  })
              : undefined
          }
        />
        <p className="text-sm">{next(posture)}</p>
        {top.length > 0 ? (
          <PostureCategoryList categories={top} />
        ) : (
          <p className="text-sm text-muted-foreground">
            {t('attackSurface.posture.nothingTakesPoints', 'No open issue takes points away.')}
          </p>
        )}
      </div>
    )
  }

  return (
    <Card data-testid="posture-card">
      <CardHeader>
        <CardTitle>{t('attackSurface.posture.title', 'Posture')}</CardTitle>
        <CardDescription>
          {posture?.state.computed_at ? (
            <span>
              {t('attackSurface.posture.computed', 'Computed')}{' '}
              <RelativeTime date={posture.state.computed_at} />
            </span>
          ) : (
            t(
              'attackSurface.posture.cardDescription',
              'A grade from A to F for your external attack surface.'
            )
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {body}
        <Link href={POSTURE_HREF} className="text-sm text-primary hover:underline">
          {t('attackSurface.posture.viewDetails', 'What to fix to raise the grade')}
        </Link>
      </CardContent>
    </Card>
  )
}
