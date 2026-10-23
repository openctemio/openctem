'use client'

import { useCallback, useState } from 'react'
import { toast } from 'sonner'
import { Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useRouter } from 'next/navigation'
import { MetricStrip, formatRiskScore } from '@/features/shared'
import { Can, Permission } from '@/lib/permissions'
import { WidgetError } from '@/features/dashboard/components/widget-error'
import { DRILL } from '@/features/dashboard/lib/drill'
import {
  PERIOD_OPTIONS,
  formatPct,
  formatCount,
  type Period,
} from '@/features/dashboard/lib/format'
import { useExecutiveSummary, downloadExecutiveSummaryCsv } from '../hooks/use-report-schedules'
import { useTranslation } from '@/context/i18n-provider'

export function ExecutiveSummarySection() {
  const { t, locale } = useTranslation()
  const router = useRouter()
  const [days, setDays] = useState<Period>('30')
  const [downloading, setDownloading] = useState(false)
  const { summary, error, isLoading, retry } = useExecutiveSummary(parseInt(days, 10))

  const handleDownload = useCallback(async () => {
    setDownloading(true)
    try {
      await downloadExecutiveSummaryCsv(parseInt(days, 10))
      toast.success(t('reports.executive.exported', 'Executive summary exported'))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t('reports.executive.exportFailed', 'Export failed')
      )
    } finally {
      setDownloading(false)
    }
  }, [days, t])

  return (
    <section className="space-y-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-base font-semibold">
            {t('reports.executive.title', 'Executive summary')}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t(
              'reports.executiveHint',
              'Program-level risk, findings, SLA and MTTR for the selected window.'
            )}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Select value={days} onValueChange={(v) => setDays(v as Period)}>
            <SelectTrigger
              className="h-9 w-[150px]"
              aria-label={t('insights.period.label', 'Period')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PERIOD_OPTIONS.map((r) => (
                <SelectItem key={r.value} value={r.value}>
                  {t(r.labelKey, r.fallback)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {/* The export route is gated on the same grant as the summary itself. */}
          <Can permission={Permission.DashboardRead}>
            <Button
              variant="outline"
              size="sm"
              className="h-9"
              onClick={handleDownload}
              disabled={downloading}
            >
              <Download className="me-2 h-4 w-4" />
              {downloading
                ? t('reports.executive.preparing', 'Preparing…')
                : t('reports.executive.download', 'Download CSV')}
            </Button>
          </Can>
        </div>
      </div>
      {!summary && error ? (
        <WidgetError onRetry={() => void retry()} className="rounded-lg border py-6" />
      ) : (
        <MetricStrip
          loading={isLoading}
          items={[
            {
              key: 'risk',
              label: t('reports.executive.risk', 'Risk score'),
              value: summary ? formatRiskScore(summary.risk_score_current) : '—',
            },
            {
              key: 'open',
              label: t('reports.executive.open', 'Open findings'),
              value: summary ? formatCount(summary.findings_total, locale) : '—',
            },
            {
              key: 'p0',
              label: t('reports.executive.p0', 'P0 open'),
              value: summary ? summary.p0_open : '—',
              tone: 'danger',
              onClick: () => router.push(DRILL.p0Open),
            },
            {
              key: 'sla',
              label: t('dashboardMetrics.executive.sla'),
              value: summary
                ? formatPct(summary.sla_compliance_pct, { n: summary.findings_total, locale })
                : '—',
            },
          ]}
        />
      )}
    </section>
  )
}
