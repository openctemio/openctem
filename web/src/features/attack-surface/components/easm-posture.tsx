'use client'

/**
 * Attack surface > Posture: the grade of the external surface the viewer may
 * see, what each category takes away, the fix plan to the next grade, the
 * risk reduction by asset criticality and the score of each root domain.
 * Formula: server/docs/architecture/easm-posture.md.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Gauge } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Meter } from '@/features/shared/components/meter'
import { EmptyState, MetricStrip, RelativeTime, TonePill } from '@/features/shared'
import { PostureCategoryList, PostureGrade } from '@/components/dashboard-kit'
import { downloadCsv } from '@/hooks/use-csv-export'
import { Permission, usePermissions } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import type { ApiClientError } from '@/lib/api/error-handler'
import { setPostureSchedule, usePosture, useRecalculatePosture } from '../hooks/use-posture'
import { useNextGradeSentence } from './easm-posture-card'
import { PosturePlanList } from './posture-plan-list'
import { POSTURE_SCHEDULES, rootsCsv, scoreDelta, type PostureSchedule } from '../lib/posture'

export function EASMPosture() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const [root, setRoot] = useState<string>('')
  const { posture, error, isLoading, mutate } = usePosture(root || undefined)
  // The organization (or scope) read keeps the root list while one root is open.
  const whole = usePosture(undefined, root !== '')
  const roots = (root ? whole.posture : posture)?.roots ?? []
  const next = useNextGradeSentence()
  const { run, running } = useRecalculatePosture(() => {
    void mutate()
    if (root) void whole.mutate()
  })

  const recalculate = async () => {
    try {
      await run()
      toast.success(t('attackSurface.posture.recalculated', 'Posture recalculated.'))
    } catch (e) {
      const err = e as ApiClientError
      if (err?.statusCode === 429)
        toast.error(
          t(
            'attackSurface.posture.tooSoon',
            'Recalculated less than five minutes ago. Try again later.'
          )
        )
      else if (err?.statusCode === 409)
        toast.error(t('attackSurface.posture.busy', 'A recalculation is already running.'))
      else
        toast.error(
          t('attackSurface.posture.recalculateFailed', 'Could not recalculate. Try again.')
        )
    }
  }

  const changeSchedule = async (v: string) => {
    try {
      await setPostureSchedule(v as PostureSchedule)
      void mutate()
      toast.success(t('attackSurface.posture.scheduleSaved', 'Refresh schedule saved.'))
    } catch {
      toast.error(t('attackSurface.posture.scheduleFailed', 'Could not save the schedule.'))
    }
  }

  const strip = useMemo(() => {
    if (!posture?.score.measured) return []
    const issues = posture.score.categories.reduce((n, c) => n + c.issues, 0)
    return [
      {
        key: 'assets',
        label: t('attackSurface.posture.strip.assets', 'Surface assets'),
        value: posture.score.assets,
        href: '/attack-surface/external',
      },
      {
        key: 'issues',
        label: t('attackSurface.posture.strip.issues', 'Issues counted'),
        value: issues,
        href: '/attack-surface/exposures',
      },
      {
        key: 'roots',
        label: t('attackSurface.posture.strip.roots', 'Root domains'),
        value: root ? 1 : posture.roots_total,
        href: '/attack-surface/external',
      },
    ]
  }, [posture, root, t])

  if (isLoading && !posture) return <Skeleton className="h-64 w-full" />
  if (error || !posture) {
    return (
      <EmptyState
        icon={Gauge}
        title={t('attackSurface.posture.loadFailed', 'Could not load the posture.')}
        description={t('attackSurface.posture.loadFailedHint', 'Reload the page to try again.')}
      />
    )
  }
  const st = posture.state
  const delta = scoreDelta(posture)

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="flex flex-col gap-4 pt-6 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-4">
            <PostureGrade grade={posture.score.grade} score={posture.score.score} />
            <div className="flex min-w-0 flex-col gap-1">
              <span className="text-lg font-semibold">
                {root
                  ? t('attackSurface.posture.rootTitle', 'Posture of {root}', { root })
                  : posture.scoped
                    ? t('attackSurface.posture.scopedTitle', 'Posture of the assets you can see')
                    : t('attackSurface.posture.orgTitle', 'Organization posture')}
              </span>
              {posture.score.measured ? (
                <span className="text-sm">{next(posture)}</span>
              ) : (
                <span className="text-sm text-muted-foreground">
                  {st.building
                    ? t(
                        'attackSurface.posture.building',
                        'The first posture computation is running. It appears here within a few minutes.'
                      )
                    : t(
                        'attackSurface.posture.noSurface',
                        'No surface asset in your view yet, so there is no grade.'
                      )}
                </span>
              )}
              <span className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                {st.computed_at && (
                  <span>
                    {t('attackSurface.posture.computed', 'Computed')}{' '}
                    <RelativeTime date={st.computed_at} />
                  </span>
                )}
                {st.next_refresh_at && (
                  <span>
                    {t('attackSurface.posture.nextRefresh', 'Next refresh')}{' '}
                    <RelativeTime date={st.next_refresh_at} />
                  </span>
                )}
                {delta != null && delta !== 0 && (
                  <span>
                    {delta > 0
                      ? t('attackSurface.posture.up', 'Up {n} since the last computation', {
                          n: delta,
                        })
                      : t('attackSurface.posture.down', 'Down {n} since the last computation', {
                          n: -delta,
                        })}
                  </span>
                )}
                {st.stale && (
                  <TonePill
                    tone="warning"
                    label={t('attackSurface.posture.stale', 'Out of date')}
                  />
                )}
              </span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {root && (
              <Button variant="ghost" size="sm" onClick={() => setRoot('')}>
                {t('attackSurface.posture.allRoots', 'All root domains')}
              </Button>
            )}
            {can(Permission.SettingsWrite) && (
              <Select value={st.refresh_every} onValueChange={changeSchedule}>
                <SelectTrigger aria-label={t('attackSurface.posture.schedule', 'Refresh schedule')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {POSTURE_SCHEDULES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {t(`attackSurface.posture.scheduleOption.${s}`, s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            {can(Permission.AssetsWrite) && (
              <Button size="sm" onClick={recalculate} disabled={running}>
                {running
                  ? t('attackSurface.posture.recalculating', 'Recalculating...')
                  : t('attackSurface.posture.recalculate', 'Recalculate now')}
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {strip.length > 0 && <MetricStrip items={strip} />}

      {posture.score.measured && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>
                {t('attackSurface.posture.categoriesTitle', 'What takes points away')}
              </CardTitle>
              <CardDescription>
                {t(
                  'attackSurface.posture.categoriesDescription',
                  'Each category can take at most its share of the 100 points; the score once its issues are fixed is shown next to it.'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <PostureCategoryList categories={posture.score.categories} showIfFixed />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('attackSurface.posture.planTitle', 'Fix plan')}</CardTitle>
              <CardDescription>
                {posture.plan.target
                  ? t(
                      'attackSurface.posture.planDescription',
                      'The most effective fixes first, until the grade reaches {grade}.',
                      {
                        grade: posture.plan.target,
                      }
                    )
                  : t('attackSurface.posture.topGrade', 'Top grade: keep it there.')}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {posture.plan.steps.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('attackSurface.posture.planEmpty', 'Nothing to fix to reach the next grade.')}
                </p>
              ) : (
                <PosturePlanList steps={posture.plan.steps} currentScore={posture.score.score} />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>
                {t('attackSurface.posture.reductionTitle', 'Risk reduction by asset criticality')}
              </CardTitle>
              <CardDescription>
                {t(
                  'attackSurface.posture.reductionDescription',
                  'The share of all points on assets of each criticality, and the score points fixing them would add.'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="flex flex-col gap-3">
                {posture.reductions.map((r) => {
                  const name = t(
                    `attackSurface.posture.criticality.${r.criticality}`,
                    r.criticality
                  )
                  return (
                    <li
                      key={r.criticality}
                      className="flex flex-col gap-1"
                      data-criticality={r.criticality}
                    >
                      <div className="flex items-baseline justify-between gap-3 text-sm">
                        <span>{name}</span>
                        <span className="flex items-baseline gap-3 tabular-nums">
                          <span className="text-xs text-muted-foreground">
                            {t(
                              'attackSurface.posture.reductionAssets',
                              '{assets} assets, {issues} issues',
                              {
                                assets: r.assets,
                                issues: r.issues,
                              }
                            )}
                          </span>
                          <span className="font-medium">
                            {t('attackSurface.posture.gain', '+{gain}', {
                              gain: r.gain.toFixed(1),
                            })}
                          </span>
                        </span>
                      </div>
                      <Meter
                        value={r.share}
                        max={100}
                        label={t(
                          'attackSurface.posture.shareLabel',
                          '{name}: {share}% of all points',
                          {
                            name,
                            share: r.share,
                          }
                        )}
                      />
                    </li>
                  )
                })}
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-start justify-between gap-3">
              <div className="flex flex-col gap-1.5">
                <CardTitle>{t('attackSurface.posture.rootsTitle', 'Root domains')}</CardTitle>
                <CardDescription>
                  {t(
                    'attackSurface.posture.rootsDescription',
                    'Each root domain scored on its own assets, worst first. Select one to see its posture.'
                  )}
                </CardDescription>
              </div>
              {roots.length > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    downloadCsv(
                      rootsCsv(roots, [
                        t('attackSurface.posture.col.root', 'Root domain'),
                        t('attackSurface.posture.col.grade', 'Grade'),
                        t('attackSurface.posture.col.score', 'Score'),
                        t('attackSurface.posture.col.assets', 'Assets'),
                        t('attackSurface.posture.col.issues', 'Issues'),
                        t('attackSurface.posture.col.top', 'Main category'),
                      ]),
                      'posture-root-domains.csv'
                    )
                  }
                >
                  {t('attackSurface.posture.export', 'Export')}
                </Button>
              )}
            </CardHeader>
            <CardContent>
              {roots.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('attackSurface.posture.rootsEmpty', 'No root domain in your view.')}
                </p>
              ) : (
                // A list like the fix plan beside it (MVP v2): each root on one
                // line, its name opening its posture, then grade and counts.
                // No table frame, so no column is cut on a phone.
                <ul className="flex flex-col divide-y" data-testid="posture-roots">
                  {roots.map((r) => (
                    <li
                      key={r.root_domain}
                      data-state={r.root_domain === root ? 'selected' : undefined}
                      className="flex items-center justify-between gap-3 py-2 text-sm data-[state=selected]:font-medium"
                    >
                      <span className="flex min-w-0 flex-col">
                        <button
                          type="button"
                          aria-pressed={r.root_domain === root}
                          className="truncate text-start hover:underline"
                          onClick={() => setRoot(r.root_domain)}
                        >
                          {r.root_domain}
                        </button>
                        <span className="flex flex-wrap gap-x-2 text-xs font-normal text-muted-foreground">
                          {r.top_category && (
                            <span>
                              {t(`dashboardKit.posture.category.${r.top_category}`, r.top_category)}
                            </span>
                          )}
                          <span>
                            {t(
                              'attackSurface.posture.reductionAssets',
                              '{assets} assets, {issues} issues',
                              { assets: r.assets, issues: r.issues }
                            )}
                          </span>
                        </span>
                      </span>
                      <span className="flex shrink-0 items-center gap-2 tabular-nums">
                        <span>{r.score}</span>
                        <PostureGrade grade={r.grade} score={r.score} size="sm" />
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t('attackSurface.posture.howTitle', 'How the score is computed')}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 text-sm text-muted-foreground">
          <p>
            {t(
              'attackSurface.posture.how1',
              'Every open issue on a surface asset has points by severity (critical 10, high 5, medium 2, low 0.5; a known exploited CVE counts double), multiplied by the asset criticality (critical or crown jewel 2, high 1.5, medium 1, low 0.5).'
            )}
          </p>
          <p>
            {t(
              'attackSurface.posture.how2',
              'Each category takes away up to its maximum, half of it when its points reach a set amount per surface asset; the score is 100 minus the deductions. A is 90 and above, B 80, C 70, D 60, F below 60.'
            )}
          </p>
          {posture.scoped && (
            <p>
              {t(
                'attackSurface.posture.scopedNote',
                'Your figures cover only the assets you can see; issues without an asset are counted for people who see the whole organization.'
              )}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
