'use client'

/**
 * What an upload or a scan run did to the organization's findings (RFC-122
 * receipts): new, still detected, reopened, closed, untouched, skipped and
 * failed, and whether its coverage could close anything. Token classes only;
 * the label carries the meaning, never colour alone.
 */

import { useTranslation } from '@/context/i18n-provider'
import Link from '@/components/link'
import { Skeleton } from '@/components/ui/skeleton'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { cn } from '@/lib/utils'
import {
  useFindingReceipts,
  useReceipts,
  type FindingReceipt,
  type ReceiptResponse,
} from '../api/receipts-api'

type T = ReturnType<typeof useTranslation>['t']

function Cell({ label, value, tone }: { label: string; value: number | null; tone?: 'danger' }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-muted-foreground text-xs">{label}</div>
      <div
        className={cn(
          'text-sm font-medium tabular-nums',
          tone === 'danger' && value ? 'text-destructive' : undefined
        )}
      >
        {value === null ? '—' : value}
      </div>
    </div>
  )
}

/** The counts of one receipt and what its coverage means. */
export function ReceiptSummary({ receipt }: { receipt: ReceiptResponse }) {
  const { t } = useTranslation()
  const c = receipt.counts
  const full = receipt.coverage?.type === 'full'
  return (
    <div className="space-y-2" data-testid="receipt-summary">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Cell label={t('findings.receipts.created', 'New')} value={c?.created ?? 0} />
        <Cell label={t('findings.receipts.updated', 'Still detected')} value={c?.updated ?? 0} />
        <Cell label={t('findings.receipts.reactivated', 'Reopened')} value={c?.reactivated ?? 0} />
        <Cell label={t('findings.receipts.closed', 'Closed')} value={c?.closed ?? 0} />
        <Cell
          label={t('findings.receipts.untouched', 'Untouched')}
          value={c?.untouched === undefined || c?.untouched === null ? null : c.untouched}
        />
        <Cell label={t('findings.receipts.skipped', 'Skipped')} value={c?.skipped ?? 0} />
        <Cell
          label={t('findings.receipts.failed', 'Failed')}
          value={c?.failed ?? 0}
          tone="danger"
        />
      </div>
      <p className="text-muted-foreground text-xs">
        {full
          ? t(
              'findings.receipts.coverageFull',
              'Full coverage of its scope: open findings of that scope it did not report could be closed.'
            )
          : t(
              'findings.receipts.coveragePartial',
              'Partial coverage: it closes nothing, so untouched is not counted.'
            )}
        {full && receipt.coverage?.note === 'held'
          ? ' ' +
            t(
              'findings.receipts.held',
              'The close was held for review: it would have closed too large a share of the open findings.'
            )
          : ''}
        {!full && receipt.coverage?.note === 'incomplete'
          ? ' ' +
            t(
              'findings.receipts.incomplete',
              'Full coverage was declared, but a file failed, a record was skipped or the upload was cut short, so nothing was closed.'
            )
          : ''}
        {!full && receipt.coverage?.note === 'scope_changed'
          ? ' ' +
            t(
              'findings.receipts.scopeChanged',
              'Full coverage was declared, but an asset left your scope before the close, so nothing was closed.'
            )
          : ''}
        {receipt.actions_truncated
          ? ' ' +
            t(
              'findings.receipts.truncated',
              'Only the first 50,000 findings are listed one by one; the counts are complete.'
            )
          : ''}
      </p>
    </div>
  )
}

/** The latest uploads of the organization (or, without the organization view, yours). */
export function RecentImports() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useReceipts({ sourceKind: 'upload', perPage: 5 })
  if (error) return null
  return (
    <section className="space-y-2" aria-labelledby="recent-imports-title">
      <h3 id="recent-imports-title" className="text-sm font-medium">
        {t('findings.receipts.recentTitle', 'Recent imports')}
      </h3>
      {isLoading ? (
        <Skeleton className="h-12 w-full" />
      ) : (data?.data?.length ?? 0) === 0 ? (
        <p className="text-muted-foreground text-xs">
          {t('findings.receipts.recentEmpty', 'No imports yet.')}
        </p>
      ) : (
        <ul className="divide-y rounded-md border text-sm" data-testid="recent-imports">
          {data?.data?.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 p-2">
              <span className="flex items-center gap-2">
                <RelativeTime date={r.started_at} className="text-xs" />
                {r.format ? <span className="font-mono text-xs">{r.format}</span> : null}
              </span>
              <span className="text-muted-foreground text-xs tabular-nums">
                {t(
                  'findings.receipts.recentLine',
                  '{created} new, {updated} still detected, {closed} closed',
                  {
                    created: r.counts?.created ?? 0,
                    updated: r.counts?.updated ?? 0,
                    closed: r.counts?.closed ?? 0,
                  }
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

/** The receipt of one scan run, shown on the run page; nothing when there is none to show. */
export function RunReceiptSection({ runId }: { runId: string }) {
  const { t } = useTranslation()
  const { data } = useReceipts({ sourceKind: 'scan_run', sourceRef: runId, perPage: 1 })
  const receipt = data?.data?.[0]
  if (!receipt) return null
  return (
    <DetailSection title={t('findings.receipts.runTitle', 'What this run did to findings')}>
      <ReceiptSummary receipt={receipt} />
    </DetailSection>
  )
}

function kindLabel(t: T, kind?: string): string {
  switch (kind) {
    case 'upload':
      return t('findings.receipts.kindUpload', 'Import')
    case 'scan_run':
      return t('findings.receipts.kindScanRun', 'Scan run')
    case 'command':
      return t('findings.receipts.kindCommand', 'Scan task')
    case 'ci_run':
      return t('findings.receipts.kindCiRun', 'CI run')
    case 'connector':
      return t('findings.receipts.kindConnector', 'Connector sync')
    default:
      return t('findings.receipts.kindSensor', 'Sensor report')
  }
}

function actionLabel(t: T, action?: string): string {
  switch (action) {
    case 'created':
      return t('findings.receipts.actionCreated', 'created it')
    case 'reopened':
      return t('findings.receipts.actionReopened', 'reopened it')
    case 'closed':
      return t('findings.receipts.actionClosed', 'closed it')
    default:
      return t('findings.receipts.actionStillDetected', 'still detected it')
  }
}

/** "Last seen in": the newest upload or run that acted on the finding. */
export function FindingLastSeenIn({ findingId }: { findingId: string }) {
  const { t } = useTranslation()
  const { data } = useFindingReceipts(findingId)
  const last: FindingReceipt | undefined = data?.data?.[0]
  if (!last) return <span className="text-muted-foreground">—</span>
  const label = kindLabel(t, last.source?.kind)
  return (
    <span
      className="flex flex-wrap items-center gap-x-2 gap-y-1"
      data-testid="finding-last-seen-in"
    >
      {last.source?.kind === 'scan_run' && last.source.ref ? (
        <Link
          href={`/scans/runs?run=${encodeURIComponent(last.source.ref)}`}
          className="underline-offset-2 hover:underline"
        >
          {label}
        </Link>
      ) : (
        <span>{label}</span>
      )}
      {last.tool ? <span className="font-mono text-xs">{last.tool}</span> : null}
      <span className="text-muted-foreground">{actionLabel(t, last.action)}</span>
      <RelativeTime date={last.at} className="text-xs" />
    </span>
  )
}
