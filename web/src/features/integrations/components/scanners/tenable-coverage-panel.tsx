'use client'

/**
 * Rolling coverage through the Tenable.sc connector (api RFC-047 §9): the
 * license Tenable.sc reports (used / limit), whether a batch is running, what
 * the next batch may use, and how fresh the inventory's scans are. A number
 * that cannot be computed yet says so instead of showing 0.
 */

import { Meter, MetricStrip, type MetricStripItem } from '@/features/shared'
import { coverageNumbers } from '@/features/integrations/lib/tenable-sc'
import type { Integration } from '@/features/integrations/types/integration.types'
import { useScanCoverage } from '@/lib/api/scan-coverage-hooks'
import { useTranslation } from '@/context/i18n-provider'

export function TenableCoveragePanel({ integration }: { integration: Integration }) {
  const { t } = useTranslation()
  const n = coverageNumbers(integration)
  const { data: freshness, isLoading } = useScanCoverage(30)
  const notEnough = t('tenableSc.coverage.notEnoughData', 'Not enough data')

  if (!n.enabled) {
    return (
      <p className="text-muted-foreground text-sm">
        {t(
          'tenableSc.coverage.off',
          'Rolling coverage is off for {name}. Turn it on in the connector settings to scan the inventory in license-sized batches.',
          { name: integration.name }
        )}
      </p>
    )
  }

  const outcome = (o: string) =>
    o === 'completed'
      ? t('tenableSc.coverage.outcomeCompleted', 'completed')
      : o === 'failed'
        ? t('tenableSc.coverage.outcomeFailed', 'failed')
        : o

  const licenseKnown = n.licensed !== null && n.limit !== null && n.active !== null
  const items: MetricStripItem[] = [
    {
      key: 'license',
      label: t('tenableSc.coverage.licenseUsed', 'License used'),
      value: licenseKnown ? `${n.active} / ${n.limit}` : notEnough,
      hint: licenseKnown
        ? n.limit !== n.licensed
          ? t('tenableSc.coverage.cappedBelow', 'capped below the {licensed} licensed IPs', {
              licensed: n.licensed ?? 0,
            })
          : t('tenableSc.coverage.activeReported', 'active IPs reported by Tenable.sc')
        : t('tenableSc.coverage.firstSync', 'reported by the first successful sync'),
      detail: licenseKnown ? (
        <Meter
          value={n.active ?? 0}
          max={n.limit ?? 0}
          label={t('tenableSc.coverage.meterLabel', '{active} of {limit} licensed IPs in use', {
            active: n.active ?? 0,
            limit: n.limit ?? 0,
          })}
          tone={n.headroom === 0 ? 'destructive' : 'default'}
        />
      ) : undefined,
    },
    {
      key: 'batch',
      label: t('tenableSc.coverage.currentBatch', 'Current batch'),
      value: n.batchOpen
        ? t('tenableSc.coverage.running', 'Running')
        : t('tenableSc.coverage.noneRunning', 'None running'),
      hint: n.batchOpen
        ? t(
            'tenableSc.coverage.batchWaits',
            'the next batch waits until it is scanned and ingested'
          )
        : n.lastBatchOutcome
          ? t('tenableSc.coverage.lastBatch', 'last batch {outcome}', {
              outcome: outcome(n.lastBatchOutcome),
            })
          : t('tenableSc.coverage.noBatchYet', 'no batch dispatched yet'),
    },
    {
      key: 'next',
      label: t('tenableSc.coverage.nextBatch', 'Next batch'),
      value:
        n.headroom === null
          ? notEnough
          : n.batchOpen
            ? t('tenableSc.coverage.afterCurrent', 'After the current batch')
            : t('tenableSc.coverage.ips', '{count} IPs', { count: n.headroom }),
      hint:
        n.headroom === 0
          ? t(
              'tenableSc.coverage.licenseFull',
              'license full: waits for Tenable.sc to age data out'
            )
          : n.safetyMargin > 0
            ? t('tenableSc.coverage.keepsMargin', 'keeps a margin of {margin} IPs', {
                margin: n.safetyMargin,
              })
            : t('tenableSc.coverage.withinHeadroom', 'within the license headroom'),
      tone: n.headroom === 0 ? 'warning' : 'default',
    },
    {
      key: 'fresh',
      label: t('tenableSc.coverage.scannedIn30Days', 'Scanned in 30 days'),
      value: isLoading
        ? '…'
        : freshness && freshness.total_scannable > 0
          ? `${freshness.coverage_percent.toFixed(1)}%`
          : notEnough,
      hint: freshness
        ? t(
            'tenableSc.coverage.freshnessHint',
            '{covered} of {total} hosts, {never} never scanned',
            {
              covered: freshness.covered_in_window,
              total: freshness.total_scannable,
              never: freshness.never_scanned,
            }
          )
        : undefined,
      tone: freshness && freshness.critical_never_scanned > 0 ? 'danger' : 'default',
    },
  ]

  return <MetricStrip items={items} loading={false} />
}
