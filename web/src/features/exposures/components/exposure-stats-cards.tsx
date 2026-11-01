'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { SeverityBadge } from '@/features/shared'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'
import type { ExposureStats, ExposureSeverity, ExposureState } from '@/lib/api/exposure-types'
import { SEVERITY_LEVELS } from '@/lib/severity'

const SEVERITIES: ExposureSeverity[] = [...SEVERITY_LEVELS]

interface ExposureSeverityBreakdownProps {
  bySeverity: ExposureStats['by_severity']
  className?: string
}

/** Exposure count per severity: badge, count and a share bar per row. */
export function ExposureSeverityBreakdown({
  bySeverity,
  className,
}: ExposureSeverityBreakdownProps) {
  const { t } = useTranslation()
  const safeBySeverity: Partial<Record<ExposureSeverity, number>> = bySeverity || {}
  const total = Object.values(safeBySeverity).reduce((a, b) => a + (b ?? 0), 0)

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>{t('exposures.stats.bySeverity', 'By severity')}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {SEVERITIES.map((key) => {
            const count = safeBySeverity[key] || 0
            const percentage = total > 0 ? (count / total) * 100 : 0
            return (
              <div key={key} className="space-y-1">
                <div className="flex items-center justify-between text-sm">
                  <SeverityBadge severity={key} />
                  <span className="font-medium tabular-nums">{count.toLocaleString()}</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <div
                    className={cn('h-full rounded-full transition-all', SEVERITY_DOT_COLORS[key])}
                    style={{ width: `${percentage}%` }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}

const STATES: ExposureState[] = ['active', 'in_progress', 'resolved', 'accepted', 'false_positive']

interface ExposureStateBreakdownProps {
  byState: ExposureStats['by_state']
  className?: string
}

/** Exposure count per lifecycle state, as a divided row of numbers. */
export function ExposureStateBreakdown({ byState, className }: ExposureStateBreakdownProps) {
  const { t } = useTranslation()
  const safeByState: Partial<Record<ExposureState, number>> = byState || {}
  const total = Object.values(safeByState).reduce((a, b) => a + (b ?? 0), 0)

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>{t('exposures.stats.byState', 'By state')}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 divide-x divide-y sm:grid-cols-5 sm:divide-y-0">
          {STATES.map((key) => {
            const count = safeByState[key] || 0
            const percentage = total > 0 ? ((count / total) * 100).toFixed(0) : '0'
            return (
              <div key={key} className="px-3 py-2 text-center">
                <p className="text-2xl font-semibold tabular-nums">{count.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">{t(`exposures.state.${key}`)}</p>
                <p className="text-xs text-muted-foreground tabular-nums">{percentage}%</p>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
