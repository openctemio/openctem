'use client'

/**
 * The finding page's import history (research 229 §8.4, the rail): every
 * upload or run that acted on this finding, newest first, with what it did
 * (created, still detected, reopened, closed, suppressed, held). It answers
 * "who keeps reporting this, and when did it last see it" without leaving
 * the page.
 *
 * Read: GET /api/v1/findings/{id}/imports (at most 20 rows), the same SWR key
 * as the "Last seen in" fact, so the page makes one request for both. The API
 * answers 404 for a finding outside the caller's data scope; a refusal hides
 * the panel (no oracle), a failure shows a Retry row. A finding no upload or
 * run ever reported (added by hand) has no history, and the panel is absent.
 */

import { useState, type ReactNode } from 'react'
import { History } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import { ListItem } from '@/features/shared/components/text-layout'
import { useFindingReceipts, type FindingReceipt } from '../../api/receipts-api'
import { receiptKindLabel } from '../receipt-summary'
import { SectionLoadError, isLoadFailure } from './section-load-error'

/** Rows shown before "Show all". */
export const IMPORT_HISTORY_PREVIEW = 4

type T = ReturnType<typeof useTranslation>['t']

/** The short chip for what one receipt did to the finding. */
export function receiptActionChip(t: T, action?: string): string {
  switch (action) {
    case 'created':
      return t('findings.importHistory.actionCreated', 'New')
    case 'reopened':
      return t('findings.importHistory.actionReopened', 'Reopened')
    case 'closed':
      return t('findings.importHistory.actionClosed', 'Resolved')
    case 'suppressed':
      return t('findings.importHistory.actionSuppressed', 'Suppressed by a rule')
    case 'held':
      return t('findings.importHistory.actionHeld', 'Held for review')
    case 'still_detected':
      return t('findings.importHistory.actionStillDetected', 'Still detected')
    default:
      return t('findings.importHistory.actionOther', 'Reported')
  }
}

function ReceiptRow({ receipt }: { receipt: FindingReceipt }) {
  const { t } = useTranslation()
  const label = receiptKindLabel(t, receipt.source?.kind)
  const title =
    receipt.source?.kind === 'scan_run' && receipt.source.ref ? (
      <Link
        href={`/scans/runs?run=${encodeURIComponent(receipt.source.ref)}`}
        className="underline-offset-2 hover:underline"
      >
        {label}
      </Link>
    ) : (
      label
    )
  const meta: ReactNode[] = []
  if (receipt.tool) {
    meta.push(
      <span key="tool" className="font-mono">
        {receipt.tool}
      </span>
    )
  }
  meta.push(<RelativeTime key="at" date={receipt.at} />)
  return (
    <ListItem
      className="px-0"
      title={title}
      trailing={
        <Badge
          variant="outline"
          className="text-xs font-normal"
          data-slot="import-history-action"
          data-action={receipt.action}
        >
          {receiptActionChip(t, receipt.action)}
        </Badge>
      }
      meta={meta}
    />
  )
}

export function FindingImportHistory({
  findingId,
  className,
}: {
  findingId: string
  className?: string
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useFindingReceipts(findingId)
  useSettleSignal(isLoading)
  const [expanded, setExpanded] = useState(false)

  if (isLoadFailure(error)) {
    return (
      <SectionLoadError
        title={t('findings.importHistory.loadTitle', 'the import history')}
        onRetry={() => void mutate()}
        className={className}
      />
    )
  }
  const rows = data?.data ?? []
  if (error || rows.length === 0) return null

  const shown = expanded ? rows : rows.slice(0, IMPORT_HISTORY_PREVIEW)
  const hidden = rows.length - shown.length

  return (
    <DetailSection
      title={t('findings.importHistory.title', 'Import history')}
      icon={History}
      count={rows.length}
      className={className}
    >
      <ul className="divide-y" data-testid="finding-import-history">
        {shown.map((r) => (
          <ReceiptRow key={`${r.receipt_id}-${r.action}`} receipt={r} />
        ))}
      </ul>
      {hidden > 0 || expanded ? (
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs"
          aria-expanded={expanded}
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded
            ? t('findings.importHistory.showFewer', 'Show fewer')
            : t('findings.importHistory.showAll', 'Show all {count}', { count: rows.length })}
        </Button>
      ) : null}
    </DetailSection>
  )
}
