'use client'

import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import type { EPSSStats, KEVStats } from '@/lib/api/threatintel-types'

/** EPSS probabilities the API counts the organization's open findings at (intel_service.go). */
const EPSS_HIGH = 0.1
const EPSS_CRITICAL = 0.5

interface ThreatIntelOverviewProps {
  epssStats: EPSSStats
  kevStats: KEVStats
  /** Kept for callers; the page header already shows sync freshness. */
  lastSyncAt?: string
  isLoading?: boolean
  className?: string
}

/**
 * The threat landscape in two parts that never mix:
 *  - the organization's open findings that EPSS or CISA KEV flag (each number
 *    is a link to the findings list it counts);
 *  - the size of the two global catalogs, as plain text, since they say
 *    nothing about this organization.
 */
export function ThreatIntelOverview({
  epssStats,
  kevStats,
  isLoading,
  className,
}: ThreatIntelOverviewProps) {
  const { t } = useTranslation()
  const loading = isLoading || !epssStats || !kevStats

  const kevOpen = kevStats?.tenant_open_count ?? 0
  const items: MetricStripItem[] = [
    {
      key: 'epss-critical',
      label: t('threatIntel.landscape.epssCritical'),
      value: epssStats?.critical_risk_count ?? 0,
      tone: 'danger',
      description: t('threatIntel.landscape.epssCriticalHint'),
      href: `/findings?epss_score_gte=${EPSS_CRITICAL}`,
    },
    {
      key: 'epss-high',
      label: t('threatIntel.landscape.epssHigh'),
      value: epssStats?.high_risk_count ?? 0,
      tone: 'warning',
      description: t('threatIntel.landscape.epssHighHint'),
      href: `/findings?epss_score_gte=${EPSS_HIGH}`,
    },
    {
      key: 'kev-open',
      label: t('threatIntel.landscape.kevOpen'),
      value: kevOpen,
      tone: 'danger',
      detail:
        kevOpen > 0
          ? t('threatIntel.landscape.kevOpenDetail', undefined, {
              ransomware: (kevStats?.tenant_ransomware_open_count ?? 0).toLocaleString(),
              recent: (kevStats?.tenant_new_kev_matches_30d ?? 0).toLocaleString(),
            })
          : undefined,
      description: t('threatIntel.landscape.kevOpenHint'),
      href: '/findings?is_in_kev=true',
    },
    {
      key: 'kev-past-due',
      label: t('threatIntel.landscape.kevPastDue'),
      value: kevStats?.past_due_count ?? 0,
      tone: 'danger',
      description: t('threatIntel.landscape.kevPastDueHint'),
      href: '/findings?is_in_kev=true',
    },
  ]

  return (
    <div className={cn('space-y-5', className)}>
      <section className="space-y-3">
        <div>
          <h2 className="text-base font-semibold">{t('threatIntel.landscape.yoursTitle')}</h2>
          <p className="text-sm text-muted-foreground">{t('threatIntel.landscape.yoursHint')}</p>
        </div>
        <MetricStrip items={items} loading={loading} />
      </section>

      <section className="space-y-1" aria-labelledby="threat-intel-catalogs">
        <h2 id="threat-intel-catalogs" className="text-base font-semibold">
          {t('threatIntel.landscape.catalogsTitle')}
        </h2>
        {loading ? null : (
          <dl className="grid gap-1 text-sm text-muted-foreground sm:grid-cols-[auto_1fr] sm:gap-x-4">
            <dt className="font-medium text-foreground">
              {t('threatIntel.landscape.epssCatalog')}
            </dt>
            <dd>
              {t('threatIntel.landscape.epssCatalogValue', undefined, {
                count: (epssStats.total_scores ?? 0).toLocaleString(),
              })}
            </dd>
            <dt className="font-medium text-foreground">{t('threatIntel.landscape.kevCatalog')}</dt>
            <dd>
              {t('threatIntel.landscape.kevCatalogValue', undefined, {
                count: (kevStats.total_entries ?? 0).toLocaleString(),
                recent: (kevStats.recently_added_last_30_days ?? 0).toLocaleString(),
                ransomware: (kevStats.ransomware_related_count ?? 0).toLocaleString(),
              })}
            </dd>
          </dl>
        )}
      </section>
    </div>
  )
}
