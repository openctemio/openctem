'use client'

import { epssScoreToPercent } from '@/lib/epss'
import Link from '@/components/link'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/features/shared'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import type { PriorityClass } from '@/features/findings/types/finding.types'
import { ShieldCheck } from 'lucide-react'
import { KevChip } from './kev-chip'
import { WidgetError } from '../widget-error'
import { useTranslation } from '@/context/i18n-provider'
import type { ExecTopRisk, ExposureChain } from '../../hooks/use-ctem-dashboard'

interface FixNextItem {
  key: string
  title: string
  href: string
  kev: boolean
  priorityClass?: PriorityClass
  /** EPSS as a percentage (0..100), when known: a reason chip, not a rank. */
  epssPct?: number
  meta: string[]
}

interface FixNextQueueProps {
  chains?: ExposureChain[]
  topRisks?: ExecTopRisk[]
  isLoading?: boolean
  limit?: number
  /** The top-risks read failed: show an error, not "nothing to fix". */
  error?: unknown
  onRetry?: () => void
}

const CLASS_RANK: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3 }

/**
 * Findings first, ordered by priority class (the class already folds in KEV,
 * reachability, crown jewels and EPSS); within a class they keep the API's
 * order. Exposure chains follow, by their own score. A bare number is never
 * the rank, so a P1 with a high EPSS never sits above a P0 without one.
 */
export function orderFixNext(chains: ExposureChain[], topRisks: ExecTopRisk[]): FixNextItem[] {
  const riskItems = topRisks
    .map((r, i) => {
      const priorityClass = (r.priority_class?.toUpperCase() as PriorityClass) || undefined
      // Build a stacked deep-link: priority class AND (when exploited) KEV.
      const listParams = new URLSearchParams({ state: 'open' })
      if (priorityClass) listParams.set('priority_class', priorityClass)
      if (r.is_in_kev) listParams.set('is_in_kev', 'true')
      const item: FixNextItem = {
        key: `risk-${i}-${r.title}`,
        title: r.title,
        href: r.finding_id ? `/findings/${r.finding_id}` : `/findings?${listParams.toString()}`,
        kev: r.is_in_kev,
        priorityClass,
        epssPct:
          typeof r.epss_score === 'number'
            ? Math.round(epssScoreToPercent(r.epss_score))
            : undefined,
        meta: [r.asset_name].filter(Boolean),
      }
      return { item, cls: CLASS_RANK[priorityClass ?? ''] ?? 4, i }
    })
    .sort((a, b) => a.cls - b.cls || a.i - b.i)
    .map((x) => x.item)

  const chainItems = [...chains]
    .sort((a, b) => b.score - a.score)
    .map((c, i): FixNextItem => {
      const hopCount = c.hops?.length ?? 0
      return {
        key: `chain-${i}-${c.target_name}`,
        title: `${c.target_name} — via ${c.entry_point_name}`,
        href: '/exposure-chains',
        kev: c.kev_count > 0,
        meta: [
          `${hopCount} hop${hopCount === 1 ? '' : 's'}`,
          ...(c.is_crown_jewel ? ['crown jewel'] : []),
        ],
      }
    })

  return [...riskItems, ...chainItems]
}

export function FixNextQueue({
  chains,
  topRisks,
  isLoading,
  limit = 6,
  error,
  onRetry,
}: FixNextQueueProps) {
  const { t } = useTranslation()
  const items = orderFixNext(chains ?? [], topRisks ?? []).slice(0, limit)

  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <span className="text-sm font-semibold tracking-tight">
          {t('dashboardMetrics.fixNext.title', 'Fix next')}
        </span>
        <span className="text-[11px] text-muted-foreground">
          {t('dashboardMetrics.fixNext.order', 'by priority class')}
        </span>
      </CardHeader>
      <CardContent className="flex-1">
        {isLoading ? (
          <div className="space-y-3">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : !topRisks && error ? (
          <WidgetError onRetry={onRetry} />
        ) : items.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title={t('dashboardMetrics.fixNext.emptyTitle', 'Nothing exploitable right now')}
            description={t(
              'dashboardMetrics.fixNext.emptyDesc',
              'No reachable exposure chains or top risks to triage.'
            )}
            card={false}
          />
        ) : (
          <ul className="divide-y divide-border">
            {items.map((it) => (
              <li key={it.key} className="flex items-center gap-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[13px] font-medium">{it.title}</p>
                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
                    {it.kev && <KevChip />}
                    {it.priorityClass && (
                      <PriorityClassBadge priorityClass={it.priorityClass} showTooltip={false} />
                    )}
                    {it.epssPct !== undefined && (
                      <span className="tabular-nums">
                        {t('dashboardMetrics.fixNext.epss', 'EPSS {pct}%', { pct: it.epssPct })}
                      </span>
                    )}
                    {it.meta.map((m) => (
                      <span key={m} className="truncate">
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
                <Link
                  href={it.href}
                  aria-label={t('dashboardMetrics.fixNext.triageLabel', 'Triage {title}', {
                    title: it.title,
                  })}
                  className="shrink-0 text-[11px] font-semibold text-primary hover:underline focus-visible:underline"
                >
                  {t('dashboardMetrics.fixNext.triage', 'Triage →')}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
