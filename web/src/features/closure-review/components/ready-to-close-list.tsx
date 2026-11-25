'use client'

import { useCallback, useMemo, useState } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ConfirmDialog, ConfirmSample } from '@/components/confirm-dialog'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import type { DataTableBulk, DataTableSelection } from '@/features/shared/components/data-table'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RefreshButton } from '@/components/list-page-parts'
import { PageStack } from '@/features/shared/components/page-stack'
import {
  QueueCard,
  QueueDecisionActions,
  QueueEmpty,
  useQueueAnnouncer,
} from '@/features/shared/components/queue'
import { TonePill } from '@/features/shared/components/tone-pill'
import { ApprovalFindingLink } from '@/features/findings/components/approval-finding-link'
import { accessStateOf } from '@/lib/api/access-state'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { toDisplayText } from '@/lib/untrusted-text'
import { useTranslation } from '@/context/i18n-provider'

import { decideClosureProposals, refreshClosureReview, useClosureProposals } from '../api'
import {
  DISMISS_REASONS,
  MAX_DECISION_BATCH,
  type ClosureProposal,
  type DecideResult,
  type DismissReason,
} from '../types'
import { closureColumns } from './closure-columns'
import { ClosureEvidence } from './closure-evidence'

const REASON_LABEL: Record<DismissReason, string> = {
  still_present_manual_check: 'Still there: checked by hand',
  scan_not_trustworthy: 'The scan cannot be trusted',
  wrong_asset: 'Wrong asset',
  other: 'Other',
}

// Confirm close + Keep open in en and vi, and the cell padding.
const ACTIONS_WIDTH = 236
// "A person closes" / "Người đóng" whole as a mark.
const REVIEW_WIDTH = 148

type Pending = { kind: 'confirm' | 'dismiss'; rows: ClosureProposal[] } | null

/**
 * Ready to close: closes the platform proposes, for a person to confirm
 * (the finding closes as fixed) or keep open with a reason. Rows are only
 * the caller's data scope; confirming asks for a recent
 * sign-in (the API client shows the dialog and retries).
 */
export function ReadyToCloseList({
  page,
  perPage,
  pagination,
  onPaginationChange,
}: {
  page: number
  perPage: number
  pagination: { pageIndex: number; pageSize: number }
  onPaginationChange: (p: { pageIndex: number; pageSize: number }) => void
}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canDecide = can(Permission.FindingsVerify)
  const { data, error, isLoading, isValidating, mutate } = useClosureProposals(page, perPage)
  const announcer = useQueueAnnouncer()
  const [selected, setSelected] = useState<ClosureProposal[]>([])
  const [resetKey, setResetKey] = useState(0)
  const [pending, setPending] = useState<Pending>(null)
  const [reason, setReason] = useState<DismissReason>('still_present_manual_check')
  const [note, setNote] = useState('')

  const clearSelection = useCallback(() => {
    setSelected([])
    setResetKey((k) => k + 1)
  }, [])
  const onSelectionChange = useCallback(
    (selection: DataTableSelection<ClosureProposal> | null) =>
      setSelected(selection?.kind === 'ids' ? selection.rows : []),
    []
  )

  const report = useCallback(
    (kind: 'confirm' | 'dismiss', res: DecideResult) => {
      const done = res.applied.length
      const skipped = Object.keys(res.skipped).length
      const msg =
        kind === 'confirm'
          ? t('findings.closureReview.confirmed', 'Closed {count} findings', { count: done })
          : t('findings.closureReview.kept', 'Kept {count} findings open', { count: done })
      if (skipped > 0) {
        const text = `${msg}. ${t(
          'findings.closureReview.skipped',
          '{count} were not changed: seen again, changed by someone, or no longer yours to decide.',
          { count: skipped }
        )}`
        toast.warning(text)
        announcer.announce(text)
      } else {
        toast.success(msg)
        announcer.announce(msg)
      }
    },
    [t, announcer]
  )

  const run = useCallback(async () => {
    if (!pending) return
    const ids = pending.rows.map((r) => r.id).slice(0, MAX_DECISION_BATCH)
    try {
      const res = await decideClosureProposals(
        pending.kind === 'confirm'
          ? { proposal_ids: ids, decision: 'confirm' }
          : { proposal_ids: ids, decision: 'dismiss', reason, note: note.trim() || undefined }
      )
      report(pending.kind, res)
      setPending(null)
      setNote('')
      clearSelection()
      await Promise.all([mutate(), refreshClosureReview()])
    } catch (err) {
      const msg = getErrorMessage(err)
      toast.error(msg)
      announcer.announce(msg)
    }
  }, [pending, reason, note, report, clearSelection, mutate, announcer])

  const rowName = useCallback((r: ClosureProposal) => toDisplayText(r.finding_title, 80), [])

  // The row's decision controls; the table cell and the phone card share them.
  const actionsCell = useCallback(
    (row: ClosureProposal, layout: 'row' | 'compact' = 'row') => (
      <QueueDecisionActions
        name={rowName(row)}
        itemId={row.id}
        canDecide={canDecide}
        approveLabel={t('findings.closureReview.confirm', 'Confirm close')}
        rejectLabel={t('findings.closureReview.keepOpen', 'Keep open')}
        onApprove={() => setPending({ kind: 'confirm', rows: [row] })}
        onReject={() => setPending({ kind: 'dismiss', rows: [row] })}
        layout={layout}
      />
    ),
    [canDecide, rowName, t]
  )

  const criticalPill = useCallback(
    (row: ClosureProposal) =>
      row.tier === 'critical' ? (
        <TonePill
          tone="destructive"
          label={t('findings.closureReview.criticalShort', 'A person closes')}
          title={t('findings.closureReview.critical', 'Critical: a person closes it')}
        />
      ) : null,
    [t]
  )

  const columns = useMemo<ColumnDef<ClosureProposal>[]>(() => {
    const shared = closureColumns<ClosureProposal>(t, {
      method: (r) => r.method,
      at: (r) => r.evidence_at,
      methodLabel: t('findings.closureReview.col.why', 'Why it can close'),
      atLabel: t('findings.closureReview.col.scanned', 'Scanned'),
      // Five columns and the selection: the time goes first on a narrower frame.
      atHideBelow: 1060,
    })
    const reviewLabel = t('findings.closureReview.col.review', 'Review')
    const actionsLabel = t('findings.closureReview.col.actions', 'Actions')
    const cols: ColumnDef<ClosureProposal>[] = [
      ...shared.slice(0, 2),
      {
        // Only a critical close waits for a person whatever the closing mode.
        id: 'review',
        meta: { kind: 'status', width: REVIEW_WIDTH, label: reviewLabel },
        header: reviewLabel,
        enableSorting: false,
        cell: ({ row }) =>
          criticalPill(row.original) ?? <span className="text-muted-foreground">-</span>,
      },
      ...shared.slice(2),
    ]
    if (canDecide) {
      cols.push({
        id: 'actions',
        meta: { kind: 'actions', width: ACTIONS_WIDTH, label: actionsLabel },
        header: () => <span className="sr-only">{actionsLabel}</span>,
        enableHiding: false,
        enableSorting: false,
        cell: ({ row }) => actionsCell(row.original),
      })
    }
    return cols
  }, [actionsCell, canDecide, criticalPill, t])

  const bulk: DataTableBulk<ClosureProposal> | undefined = canDecide
    ? {
        rowLabel: rowName,
        noun: t('findings.closureReview.selectedNoun', 'selected'),
        onSelectionChange,
        actions: (
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPending({ kind: 'confirm', rows: selected })}
            >
              {t('findings.closureReview.confirm', 'Confirm close')}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPending({ kind: 'dismiss', rows: selected })}
            >
              {t('findings.closureReview.keepOpen', 'Keep open')}
            </Button>
          </>
        ),
      }
    : undefined

  // A refused read is "no access", not a failure with Retry.
  const noAccess = !data && accessStateOf(error) === 'no_access'
  const total = data?.total ?? 0
  const viewTitle = t('findings.closureReview.viewName.ready', 'Closes waiting for review')
  const count = pending?.rows.length ?? 0

  return (
    <>
      <PageStack>
        {noAccess ? (
          <NoAccessState
            title={t('findings.closureReview.errorName', 'Ready to close')}
            permission={Permission.FindingsRead}
          />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            caption={viewTitle}
            // The first read: skeleton rows under a frame that stays.
            isLoading={isLoading && !data}
            isRefreshing={isValidating && !!data}
            refreshingLabel={t('findings.closureReview.refreshing', 'Refreshing closes')}
            error={data ? undefined : error}
            onRetry={() => void mutate()}
            errorTitle={t('findings.closureReview.errorName', 'Ready to close')}
            manualPagination
            showSearch={false}
            showColumnToggle={false}
            toolbarEnd={
              <RefreshButton
                onClick={() => void mutate()}
                loading={isValidating}
                label={t('findings.closureReview.refresh', 'Refresh')}
              />
            }
            pageCount={data?.total_pages ?? 0}
            rowCount={total}
            pagination={pagination}
            onPaginationChange={onPaginationChange}
            paginationNoun={t('findings.closureReview.paginationNoun', 'findings')}
            getRowId={(r) => r.id}
            pinActions
            bulk={bulk}
            resetSelectionKey={resetKey}
            showSelectionCount={false}
            emptyState={
              <QueueEmpty
                kind="nothing-waiting"
                title={t('findings.closureReview.emptyTitle', 'Nothing waits for review')}
                hint={t(
                  'findings.closureReview.emptyDescription',
                  'When a scan that checked the asset no longer finds an issue and your closing mode asks for review, the finding waits here.'
                )}
              />
            }
            mobileRow={(row) => (
              <QueueCard
                data-testid="closure-phone-card"
                href={`/findings/${encodeURIComponent(row.finding_id)}`}
                title={
                  <ApprovalFindingLink
                    findingId={row.finding_id}
                    findingTitle={row.finding_title}
                  />
                }
                state={<SeverityBadge severity={row.severity} />}
                reason={
                  <ClosureEvidence
                    method={row.method}
                    evidence={row.evidence}
                    at={row.evidence_at}
                  />
                }
                meta={[
                  criticalPill(row),
                  row.asset_name ? (
                    <span key="asset" dir="auto">
                      {toDisplayText(row.asset_name, 120)}
                    </span>
                  ) : null,
                ]}
                actions={actionsCell(row, 'compact')}
              />
            )}
          />
        )}
      </PageStack>
      {announcer.region}
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(o) => !o && setPending(null)}
        title={
          pending?.kind === 'confirm'
            ? t('findings.closureReview.confirmTitle', 'Close {count} findings as fixed?', {
                count,
              })
            : t('findings.closureReview.keepTitle', 'Keep {count} findings open?', { count })
        }
        desc={
          pending?.kind === 'confirm'
            ? t(
                'findings.closureReview.confirmDesc',
                'Each finding closes as fixed, verified by the scan shown, with you as the person who confirmed it. A finding seen again since then stays open.'
              )
            : t(
                'findings.closureReview.keepDesc',
                'The findings stay open and the proposal is dismissed with your reason.'
              )
        }
        confirmText={
          pending?.kind === 'confirm'
            ? t('findings.closureReview.confirm', 'Confirm close')
            : t('findings.closureReview.keepOpen', 'Keep open')
        }
        handleConfirm={run}
        disabled={pending?.kind === 'dismiss' && reason === 'other' && note.trim() === ''}
      >
        {pending && (
          <ConfirmSample
            names={pending.rows.map((r) => toDisplayText(r.finding_title, 120))}
            total={pending.rows.length}
          />
        )}
        {pending?.kind === 'dismiss' && (
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="closure-keep-reason">
                {t('findings.closureReview.reason', 'Reason')}
              </Label>
              <Select value={reason} onValueChange={(v) => setReason(v as DismissReason)}>
                <SelectTrigger id="closure-keep-reason">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DISMISS_REASONS.map((r) => (
                    <SelectItem key={r} value={r}>
                      {t(`findings.closureReview.reasons.${r}`, REASON_LABEL[r])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="closure-keep-note">
                {reason === 'other'
                  ? t('findings.closureReview.noteRequired', 'Note (required)')
                  : t('findings.closureReview.note', 'Note (optional)')}
              </Label>
              <Textarea
                id="closure-keep-note"
                value={note}
                maxLength={1000}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
          </div>
        )}
      </ConfirmDialog>
    </>
  )
}
