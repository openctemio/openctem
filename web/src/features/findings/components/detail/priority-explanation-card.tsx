'use client'

/**
 * "Why this priority" panel.
 *
 * Surfaces the read-only priority explanation the backend already computes
 * (GET /api/v1/findings/{id}/priority-explanation) — the P-class plus the
 * contributing factors (reachability, EPSS, KEV, asset criticality,
 * compensating controls). Read-only.
 *
 * Degrades gracefully: skeleton while loading, and nothing at all when the
 * endpoint has no explanation (404 / unwired) so a finding without one just
 * omits the section.
 */

import { useTranslation } from '@/context/i18n-provider'
import { formatEpssScore } from '@/lib/epss'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import { Gavel, HelpCircle, UserPen } from 'lucide-react'
import { PriorityClassBadge } from '../priority-class-badge'
import {
  useFindingPriorityExplanation,
  type PriorityExplanation,
  type PriorityScoreBreakdown,
} from '../../api/use-finding-priority-explanation'
import type { PriorityClass } from '../../types'
import { PriorityClassSla } from '@/features/sla/components/priority-class-sla'

interface PriorityExplanationCardProps {
  findingId: string
  /** 'page' = larger h3 heading (detail page); 'drawer' = compact h4. */
  variant?: 'page' | 'drawer'
}

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

const PRIORITY_CLASSES: readonly string[] = ['P0', 'P1', 'P2', 'P3']

function isPriorityClass(value: string): value is PriorityClass {
  return PRIORITY_CLASSES.includes(value)
}

/** Build the human-readable contributing-factor chips from the raw factors. */
function factorChips(
  exp: PriorityExplanation,
  t: Translate
): { key: string; label: string; strong: boolean }[] {
  const f = exp.factors
  const chips: { key: string; label: string; strong: boolean }[] = []

  if (f.is_in_kev)
    chips.push({
      key: 'kev',
      label: t('findings.priorityCard.kev', 'Known exploited (KEV)'),
      strong: true,
    })
  if (f.validated_exploitable)
    chips.push({
      key: 'validated',
      label: t('findings.priorityCard.validated', 'Reproduced by validation'),
      strong: true,
    })
  if (f.on_open_threat_path)
    chips.push({
      key: 'threat-path',
      label: t('findings.priorityCard.threatPath', 'On open attack path'),
      strong: true,
    })
  if (f.is_internet_accessible)
    chips.push({
      key: 'internet',
      label: t('findings.priorityCard.internet', 'Internet-accessible'),
      strong: true,
    })
  else if (f.is_reachable || f.reachable)
    chips.push({
      key: 'reachable',
      label: t('findings.priorityCard.reachable', 'Reachable'),
      strong: true,
    })
  else if (f.is_network_accessible)
    chips.push({
      key: 'network',
      label: t('findings.priorityCard.network', 'Network-accessible'),
      strong: false,
    })

  if (f.reachable_from_count > 0)
    chips.push({
      key: 'reach-count',
      label:
        f.reachable_from_count === 1
          ? t('findings.priorityCard.reachCount1', 'Reachable from {count} entry point', {
              count: f.reachable_from_count,
            })
          : t('findings.priorityCard.reachCountN', 'Reachable from {count} entry points', {
              count: f.reachable_from_count,
            }),
      strong: false,
    })

  if (typeof f.epss_score === 'number')
    chips.push({
      key: 'epss',
      label: `EPSS ${formatEpssScore(f.epss_score)}`,
      strong: f.epss_score >= 0.5,
    })

  if (f.asset_criticality)
    chips.push({
      key: 'asset-crit',
      label: t('findings.priorityCard.assetCrit', '{level} asset', { level: f.asset_criticality }),
      strong: f.critical_asset,
    })
  if (f.asset_is_crown_jewel)
    chips.push({
      key: 'crown',
      label: t('findings.priorityCard.crown', 'Crown-jewel asset'),
      strong: true,
    })
  if (f.asset_exposure)
    chips.push({
      key: 'exposure',
      label: t('findings.priorityCard.exposure', '{level} exposure', { level: f.asset_exposure }),
      strong: false,
    })

  if (f.is_protected && f.control_reduction_pct > 0)
    chips.push({
      key: 'control',
      label: t('findings.priorityCard.controls', 'Compensating controls -{pct}%', {
        pct: Math.round(f.control_reduction_pct),
      }),
      strong: false,
    })

  return chips
}

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
      <p className="text-muted-foreground text-[11px] leading-relaxed">
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

export function PriorityExplanationCard({
  findingId,
  variant = 'page',
}: PriorityExplanationCardProps) {
  const { t } = useTranslation()
  const { explanation, isLoading } = useFindingPriorityExplanation(findingId)

  const Heading = variant === 'page' ? 'h3' : 'h4'
  const headingCls =
    variant === 'page'
      ? 'mb-3 flex items-center gap-2 font-semibold'
      : 'flex items-center gap-2 text-sm font-semibold'

  if (isLoading) {
    return (
      <>
        <Separator />
        <div className={variant === 'drawer' ? 'space-y-3' : undefined}>
          <Heading className={headingCls}>
            <HelpCircle className="h-4 w-4" />
            {t('findings.priorityCard.why', 'Why this priority')}
          </Heading>
          <div className="space-y-2">
            <Skeleton className="h-6 w-40" />
            <Skeleton className="h-4 w-full max-w-md" />
            <Skeleton className="h-4 w-32" />
          </div>
        </div>
      </>
    )
  }

  // No explanation available — omit the section entirely (graceful degrade).
  if (!explanation) return null

  const chips = factorChips(explanation, t)
  const cls = explanation.priority_class

  return (
    <>
      <Separator />
      <div className={variant === 'drawer' ? 'space-y-3' : undefined}>
        <Heading className={headingCls}>
          <HelpCircle className="h-4 w-4" />
          {t('findings.priorityCard.why', 'Why this priority')}
        </Heading>

        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            {isPriorityClass(cls) ? (
              <PriorityClassBadge priorityClass={cls} />
            ) : (
              <Badge variant="outline" className="font-mono">
                {cls}
              </Badge>
            )}
            {explanation.source === 'rule' && explanation.rule_name && (
              <Badge variant="secondary" className="gap-1">
                <Gavel className="h-3 w-3" />
                {explanation.rule_name}
              </Badge>
            )}
            {explanation.override && (
              <Badge variant="secondary" className="gap-1">
                <UserPen className="h-3 w-3" />
                {t('findings.priorityCard.manualOverride', 'Set manually')}
              </Badge>
            )}
            {isPriorityClass(cls) && (
              <PriorityClassSla priorityClass={cls} className="text-muted-foreground text-xs" />
            )}
          </div>

          {explanation.reason && (
            <p className="text-muted-foreground text-sm leading-relaxed">{explanation.reason}</p>
          )}

          {explanation.override &&
            explanation.computed_class &&
            explanation.computed_class !== cls && (
              <p className="text-muted-foreground text-xs">
                {t(
                  'findings.priorityCard.overrideComputed',
                  'A person set this class{when}. The automatic classification would be {computed}.',
                  {
                    computed: explanation.computed_class,
                    when: explanation.override.at
                      ? t('findings.priorityCard.overrideOn', ' on {date}', {
                          date: new Date(explanation.override.at).toLocaleDateString(),
                        })
                      : '',
                  }
                )}
              </p>
            )}

          {explanation.stale && explanation.computed_class && (
            <p className="text-muted-foreground text-xs">
              {t(
                'findings.priorityCard.stale',
                'A recompute is pending: with the current inputs this finding would be {computed}.',
                { computed: explanation.computed_class }
              )}
            </p>
          )}

          {chips.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {chips.map((chip) => (
                <Badge key={chip.key} variant={chip.strong ? 'destructive' : 'outline'}>
                  {chip.label}
                </Badge>
              ))}
            </div>
          )}

          {explanation.score_breakdown && (
            <ScoreBreakdown breakdown={explanation.score_breakdown} />
          )}

          {explanation.model_version ? (
            <p className="text-muted-foreground text-xs">
              {t('findings.priorityCard.modelVersion', 'Priority model v{version}', {
                version: explanation.model_version,
              })}
            </p>
          ) : null}
        </div>
      </div>
    </>
  )
}
