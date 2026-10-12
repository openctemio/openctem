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

const NOT_ENOUGH = 'Not enough data'

export function TenableCoveragePanel({ integration }: { integration: Integration }) {
  const n = coverageNumbers(integration)
  const { data: freshness, isLoading } = useScanCoverage(30)

  if (!n.enabled) {
    return (
      <p className="text-muted-foreground text-sm">
        Rolling coverage is off for {integration.name}. Turn it on in the connector settings to scan
        the inventory in license-sized batches.
      </p>
    )
  }

  const licenseKnown = n.licensed !== null && n.limit !== null && n.active !== null
  const items: MetricStripItem[] = [
    {
      key: 'license',
      label: 'License used',
      value: licenseKnown ? `${n.active} / ${n.limit}` : NOT_ENOUGH,
      hint: licenseKnown
        ? n.limit !== n.licensed
          ? `capped below the ${n.licensed} licensed IPs`
          : 'active IPs reported by Tenable.sc'
        : 'reported by the first successful sync',
      detail: licenseKnown ? (
        <Meter
          value={n.active ?? 0}
          max={n.limit ?? 0}
          label={`${n.active} of ${n.limit} licensed IPs in use`}
          tone={n.headroom === 0 ? 'destructive' : 'default'}
        />
      ) : undefined,
    },
    {
      key: 'batch',
      label: 'Current batch',
      value: n.batchOpen ? 'Running' : 'None running',
      hint: n.batchOpen
        ? 'the next batch waits until it is scanned and ingested'
        : n.lastBatchOutcome
          ? `last batch ${n.lastBatchOutcome}`
          : 'no batch dispatched yet',
    },
    {
      key: 'next',
      label: 'Next batch',
      value:
        n.headroom === null
          ? NOT_ENOUGH
          : n.batchOpen
            ? 'After the current batch'
            : `${n.headroom} IPs`,
      hint:
        n.headroom === 0
          ? 'license full: waits for Tenable.sc to age data out'
          : n.safetyMargin > 0
            ? `keeps a margin of ${n.safetyMargin} IPs`
            : 'within the license headroom',
      tone: n.headroom === 0 ? 'warning' : 'default',
    },
    {
      key: 'fresh',
      label: 'Scanned in 30 days',
      value: isLoading
        ? '…'
        : freshness && freshness.total_scannable > 0
          ? `${freshness.coverage_percent.toFixed(1)}%`
          : NOT_ENOUGH,
      hint: freshness
        ? `${freshness.covered_in_window} of ${freshness.total_scannable} hosts, ${freshness.never_scanned} never scanned`
        : undefined,
      tone: freshness && freshness.critical_never_scanned > 0 ? 'danger' : 'default',
    },
  ]

  return <MetricStrip items={items} loading={false} />
}
