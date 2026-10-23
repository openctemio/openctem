'use client'

import { Gauge } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import type { MaturityBreakdown, MaturityComponent } from '../api/use-ctem-maturity'

/** English names for the component names returned by ctemcycle.ComputeMaturity. */
const COMPONENT_FALLBACK: Record<string, string> = {
  validation_coverage: 'Validation coverage',
  resolution_throughput: 'Resolution throughput',
  mttr_trend: 'MTTR trend',
  priority_stability: 'Priority stability',
  scope_stability: 'Scope stability',
}

/** Score to traffic-light accent: the semantic success, warning and destructive tokens. */
export function scoreTone(score: number): string {
  if (score >= 80) return 'text-success'
  if (score >= 50) return 'text-warning'
  return 'text-destructive'
}

function formatNumber(v: number, locale: string, digits: number): string {
  return new Intl.NumberFormat(locale, { maximumFractionDigits: digits }).format(v)
}

function ComponentRow({ c, measured }: { c: MaturityComponent; measured: boolean }) {
  const { t, locale } = useTranslation()
  return (
    <div className="rounded-md border p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-medium">
            {t(
              `insights.maturity.component.${c.name}`,
              COMPONENT_FALLBACK[c.name] ?? c.name.replace(/_/g, ' ')
            )}
          </p>
          <p className="text-muted-foreground mt-0.5 text-xs">{c.detail}</p>
        </div>
        <div className="text-end">
          <span className={cn('text-lg font-semibold tabular-nums', scoreTone(c.score))}>
            {Math.round(c.score)}
          </span>
          <span className="text-muted-foreground text-xs"> / 100</span>
        </div>
      </div>
      <div className="mt-2">
        <Progress value={c.score} />
      </div>
      <div className="text-muted-foreground mt-2 flex items-center justify-between text-xs tabular-nums">
        <span>
          {t('insights.maturity.weight', 'weight')}{' '}
          <span className="text-foreground font-medium">{Math.round(c.weight * 100)}%</span>
        </span>
        <span>
          {t('insights.maturity.raw', 'raw')}{' '}
          <span className="text-foreground font-medium">
            {measured ? formatNumber(c.raw_value, locale, 1) : '—'}
          </span>
        </span>
        <span>
          {t('insights.maturity.contribution', 'contribution')}{' '}
          <span className="text-foreground font-medium">
            {measured ? `+${formatNumber(c.contribution, locale, 1)}` : '—'}
          </span>
        </span>
      </div>
    </div>
  )
}

/**
 * MaturityBreakdownCard renders the composite maturity score and, below
 * it, every weighted component that produces it — so the number is
 * explainable by hand: score = Σ(component.score × weight). Nothing is
 * a black box.
 */
export function MaturityBreakdownCard({
  maturity,
  className,
}: {
  maturity: MaturityBreakdown
  className?: string
}) {
  const { t } = useTranslation()
  const components = maturity.components ?? []
  // One cycle is not a trend: raw values and contributions need at least two.
  const measured = maturity.cycles_analyzed >= 2
  const score = Math.round(maturity.score)

  return (
    <Card className={cn(className)}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Gauge className="text-muted-foreground h-4 w-4" />
          {t('insights.maturity.breakdown.title', 'CTEM program maturity')}
        </CardTitle>
        <CardDescription>
          {t(
            maturity.cycles_analyzed === 1
              ? 'insights.maturity.breakdown.description.one'
              : 'insights.maturity.breakdown.description.other',
            undefined,
            { count: maturity.cycles_analyzed }
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-end justify-between">
          <span className="text-muted-foreground text-sm">
            {t('insights.maturity.breakdown.overall', 'Overall')}
          </span>
          <span className={cn('text-4xl font-bold tabular-nums', scoreTone(score))}>
            {score}
            <span className="text-muted-foreground ms-1 text-base font-normal">/ 100</span>
          </span>
        </div>
        <Progress value={score} />

        <div className="grid gap-2 sm:grid-cols-2">
          {components.map((c) => (
            <ComponentRow key={c.name} c={c} measured={measured} />
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
