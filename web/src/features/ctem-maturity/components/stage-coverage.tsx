'use client'

import { Check, Minus, Layers } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import type { CTEMStageCoverage } from '../api/use-ctem-maturity'

// The five CTEM stages, in program order. Keys map to the boolean flags
// on ctemcycle.CTEMStageCoverage.
const STAGES: {
  key: Exclude<keyof CTEMStageCoverage, 'covered_count'>
  label: string
  hint: string
}[] = [
  { key: 'scoping', label: 'Scoping', hint: 'A scope was frozen at activation' },
  { key: 'discovery', label: 'Discovery', hint: 'Findings were opened' },
  { key: 'prioritization', label: 'Prioritization', hint: 'Priority classes were applied' },
  { key: 'validation', label: 'Validation', hint: 'Closed findings carried evidence' },
  { key: 'mobilization', label: 'Mobilization', hint: 'Findings were resolved' },
]

/**
 * StageCoverageCard shows which of the five CTEM stages the latest
 * closed cycle exercised. Reported ALONGSIDE the maturity score for
 * explainability — deliberately not folded into the weighted number.
 */
export function StageCoverageCard({
  coverage,
  className,
}: {
  coverage: CTEMStageCoverage
  className?: string
}) {
  const { t } = useTranslation()
  return (
    <Card className={cn(className)}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Layers className="text-muted-foreground h-4 w-4" />
          {t('insights.maturity.stages.title', 'CTEM stage coverage')}
        </CardTitle>
        <CardDescription>
          {t(
            'insights.maturity.stages.description',
            'Stages the latest closed cycle exercised: {covered} of {total}. Reported alongside the score, not part of it.',
            { covered: coverage.covered_count, total: STAGES.length }
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {STAGES.map((s) => {
            const covered = Boolean(coverage[s.key])
            return (
              <li key={s.key} className="flex items-center gap-3">
                <span
                  className={cn(
                    'flex h-6 w-6 shrink-0 items-center justify-center rounded-full',
                    covered ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'
                  )}
                  aria-hidden
                >
                  {covered ? <Check className="h-3.5 w-3.5" /> : <Minus className="h-3.5 w-3.5" />}
                </span>
                <div className="min-w-0">
                  <p className={cn('text-sm', covered ? 'font-medium' : 'text-muted-foreground')}>
                    {t(`insights.maturity.stage.${s.key}`, s.label)}
                    <span className="sr-only">
                      {' '}
                      {covered
                        ? t('insights.maturity.stages.covered', 'covered')
                        : t('insights.maturity.stages.notCovered', 'not covered')}
                    </span>
                  </p>
                  <p className="text-muted-foreground text-xs">
                    {t(`insights.maturity.stage.${s.key}.hint`, s.hint)}
                  </p>
                </div>
              </li>
            )
          })}
        </ul>
      </CardContent>
    </Card>
  )
}
