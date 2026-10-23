'use client'

import { useTranslation } from '@/context/i18n-provider'
import { MetricStrip, type MetricStripItem } from '@/features/shared'
import type { ThreatModelDetail } from '../types'

interface CoverageStatsProps {
  model: ThreatModelDetail
}

/**
 * Coverage headline + open/mitigated/covered/total rollup for a threat model.
 * "Coverage" = share of threats that are mitigated or covered (not open /
 * theoretical), as reported by the backend `coverage_pct`.
 */
export function CoverageStats({ model }: CoverageStatsProps) {
  const { t } = useTranslation()
  const coverage = Math.round(model.coverage_pct)
  const items: MetricStripItem[] = [
    {
      key: 'coverage',
      label: t('threatModel.stats.coverage', 'Coverage'),
      value: `${coverage}%`,
      hint: t('threatModel.stats.addressed', '{done} of {total} addressed', {
        done: model.threats_mitigated + model.threats_covered,
        total: model.threats_total,
      }),
    },
    { key: 'total', label: t('threatModel.stats.threats', 'Threats'), value: model.threats_total },
    {
      key: 'open',
      label: t('threatModel.stats.open', 'Open'),
      value: model.threats_open,
      tone: 'danger',
      hint: t('threatModel.stats.unmitigated', 'unmitigated'),
    },
    {
      key: 'mitigated',
      label: t('threatModel.stats.mitigated', 'Mitigated'),
      value: model.threats_mitigated,
      hint: t('threatModel.stats.fixed', 'fixed'),
    },
    {
      key: 'covered',
      label: t('threatModel.stats.covered', 'Covered'),
      value: model.threats_covered,
      hint: t('threatModel.stats.compensating', 'compensating control'),
    },
  ]
  return <MetricStrip items={items} />
}
