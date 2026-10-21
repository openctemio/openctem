'use client'

import Link from '@/components/link'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { STATE_TEXT } from '../../lib/ctem-colors'
import { DRILL } from '../../lib/drill'
import type { ThreatIntelStats } from '../../hooks/use-ctem-dashboard'
import { WidgetError } from '../widget-error'

interface ThreatIntelCardProps {
  stats?: ThreatIntelStats
  isLoading?: boolean
  error?: unknown
  onRetry?: () => void
}

/**
 * One figure. `n` undefined means the API did not report it (an older build):
 * a dash, never a confident 0.
 */
function Kv({
  n,
  label,
  href,
  danger,
}: {
  n: number | undefined
  label: string
  href?: string
  danger?: boolean
}) {
  const body = (
    <div className="flex flex-col gap-0.5">
      <span className={cn('text-lg font-semibold tabular-nums', danger && n && STATE_TEXT.crit)}>
        {n == null ? '—' : n.toLocaleString()}
      </span>
      <span className="text-xs text-muted-foreground">{label}</span>
    </div>
  )
  return href && n != null ? (
    <Link href={href} className="rounded-sm hover:underline focus-visible:underline">
      {body}
    </Link>
  ) : (
    body
  )
}

/**
 * The tenant's exposure to known-exploited and likely-exploited
 * vulnerabilities. Every figure counts this organization's open findings in
 * the viewer's scope; the size of the global KEV catalog is not shown here
 * (it says nothing about this organization).
 */
export function ThreatIntelCard({ stats, isLoading, error, onRetry }: ThreatIntelCardProps) {
  const { t } = useTranslation()
  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <span className="text-sm font-semibold tracking-tight">
          {t('dashboardMetrics.threatIntel.title')}
        </span>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-center">
        {isLoading ? (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : !stats && error ? (
          <WidgetError onRetry={onRetry} />
        ) : stats ? (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Kv
              n={stats.kev?.tenant_open_count}
              label={t('dashboardMetrics.threatIntel.kevOpen')}
              href={DRILL.kevOpen}
            />
            <Kv
              n={stats.kev?.past_due_count}
              label={t('dashboardMetrics.threatIntel.kevPastDue')}
              danger
            />
            <Kv
              n={stats.kev?.tenant_ransomware_open_count}
              label={t('dashboardMetrics.threatIntel.kevRansomware')}
            />
            <Kv
              n={stats.epss?.critical_risk_count}
              label={t('dashboardMetrics.threatIntel.epssHot')}
            />
          </div>
        ) : (
          <p className="py-4 text-center text-xs text-muted-foreground">
            {t('dashboardMetrics.threatIntel.unavailable')}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
