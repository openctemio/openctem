'use client'

import { HealthGlyph } from '@/components/ui/health-glyphs'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { HEALTH_ICON_CLASS } from '@/lib/health-colors'
import type { ScanRecentRun } from '@/lib/api/scan-types'
import { cn } from '@/lib/utils'
import {
  MIN_RUNS_FOR_RATE,
  RUN_OUTCOME_HEALTH,
  runOutcome,
  summarizeRuns,
  type RunHistorySummary,
} from '../lib/run-history'
import type { Translate } from '../lib/translate'

/**
 * A scan's latest runs as a row of glyphs, oldest to newest, then the
 * success rate over the same runs ("-" while fewer than three counted). The
 * glyphs are the run-state glyphs RunStatusBadge draws, so shape and colour
 * mean the same here as everywhere else. The tooltip (and the accessible
 * name) gives the breakdown and says what the rate counts. Rules:
 * lib/run-history.ts.
 */
export function RunHistory({
  runs,
  className,
}: {
  /** Newest first, as the API sends them. */
  runs: ScanRecentRun[] | undefined
  className?: string
}) {
  const { t } = useTranslation()
  const list = runs ?? []
  if (list.length === 0) {
    return <span className="text-meta text-muted-foreground">{t('scans.history.none')}</span>
  }
  const summary = summarizeRuns(list)
  const lines = breakdown(summary, t)
  const rateText = summary.rate === null ? '-' : `${summary.rate}%`
  const label = [
    t('scans.history.title', undefined, { count: list.length }),
    ...lines,
    summary.rate === null
      ? t('scans.history.noRate', undefined, { min: MIN_RUNS_FOR_RATE })
      : t('scans.history.rate', undefined, { rate: summary.rate }),
  ].join('. ')
  const oldestFirst = [...list].reverse()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          role="img"
          tabIndex={0}
          aria-label={label}
          data-slot="run-history"
          className={cn(
            'inline-flex min-w-0 max-w-full items-center gap-2 rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            className
          )}
        >
          <span className="inline-flex shrink-0 items-center gap-0.5" aria-hidden>
            {oldestFirst.map((r) => {
              const state = RUN_OUTCOME_HEALTH[runOutcome(r.status)]
              return (
                <HealthGlyph
                  key={r.id}
                  state={state}
                  className={cn('size-2.5', HEALTH_ICON_CLASS[state])}
                />
              )
            })}
          </span>
          <span
            className={cn(
              'shrink-0 text-meta tabular-nums',
              summary.rate === null ? 'text-muted-foreground' : 'text-foreground'
            )}
            aria-hidden
          >
            {rateText}
          </span>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-meta">
        <p className="font-medium">{t('scans.history.title', undefined, { count: list.length })}</p>
        <ul className="mt-1 space-y-0.5">
          {lines.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        <p className="mt-1 text-muted-foreground">
          {summary.rate === null
            ? t('scans.history.noRate', undefined, { min: MIN_RUNS_FOR_RATE })
            : t('scans.history.rateExplained', undefined, { rate: summary.rate })}
        </p>
      </TooltipContent>
    </Tooltip>
  )
}

function breakdown(s: RunHistorySummary, t: Translate): string[] {
  const out: string[] = []
  if (s.ok) out.push(t('scans.history.ok', undefined, { count: s.ok }))
  if (s.gaps) out.push(t('scans.history.gaps', undefined, { count: s.gaps }))
  if (s.failed) out.push(t('scans.history.failed', undefined, { count: s.failed }))
  if (s.blocked) out.push(t('scans.history.blocked', undefined, { count: s.blocked }))
  if (s.canceled) out.push(t('scans.history.canceled', undefined, { count: s.canceled }))
  if (s.live) out.push(t('scans.history.live', undefined, { count: s.live }))
  return out
}
