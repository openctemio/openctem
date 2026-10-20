'use client'

import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { coverageState, STATE_BAR, STATE_TEXT } from '../../lib/ctem-colors'
import type { ScanCoverage, ValidationCoverage } from '../../hooks/use-ctem-dashboard'
import { WidgetError } from '../widget-error'

interface CoverageHygieneProps {
  scan?: ScanCoverage
  validation?: ValidationCoverage
  /** Null: no open finding has an SLA (not measured). */
  slaPct?: number | null
  isLoading?: boolean
  /** Every read behind the card failed: show an error, not 0 %. */
  error?: unknown
  onRetry?: () => void
}

/**
 * Scan coverage, or null when it cannot be measured (the read failed or there
 * is no scannable asset in scope).
 */
function scanPct(scan?: ScanCoverage): number | null {
  if (!scan || scan.total_scannable === 0) return null
  return scan.coverage_percent
}

/** Validation coverage, or null with nothing to validate (or no data). */
function validationPct(v?: ValidationCoverage): number | null {
  if (!v || v.total === 0) return null
  return v.overall_pct
}

function Row({ label, pct }: { label: string; pct: number | null }) {
  const state = coverageState(pct ?? 0)
  return (
    <div className="flex items-center gap-2.5 text-xs">
      <span className="w-36 shrink-0 text-muted-foreground">{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded bg-muted">
        <div
          className={cn('h-full rounded', STATE_BAR[state])}
          style={{ width: `${Math.min(100, Math.max(0, pct ?? 0))}%` }}
        />
      </div>
      <span
        className={cn(
          'w-9 text-right tabular-nums',
          pct === null ? 'text-muted-foreground' : STATE_TEXT[state]
        )}
      >
        {pct === null ? '—' : `${pct.toFixed(0)}%`}
      </span>
    </div>
  )
}

export function CoverageHygiene({
  scan,
  validation,
  slaPct,
  isLoading,
  error,
  onRetry,
}: CoverageHygieneProps) {
  const { t } = useTranslation()
  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <span className="text-sm font-semibold tracking-tight">Coverage &amp; hygiene</span>
        <span className="text-[11px] text-muted-foreground">scans · validation · SLA</span>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-center">
        {isLoading ? (
          <div className="space-y-3">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-5 w-full" />
            ))}
          </div>
        ) : error ? (
          <WidgetError onRetry={onRetry} />
        ) : (
          <div className="flex flex-col gap-3">
            <Row label={t('dashboardMetrics.coverage.scan')} pct={scanPct(scan)} />
            <Row
              label={t('dashboardMetrics.coverage.validation')}
              pct={validationPct(validation)}
            />
            <Row label={t('dashboardMetrics.coverage.sla')} pct={slaPct ?? null} />
          </div>
        )}
      </CardContent>
    </Card>
  )
}
