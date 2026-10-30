'use client'

import { useCallback, useMemo, useState } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { Check, CircleSlash, ListChecks } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
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
import { TableSkeleton } from '@/components/list-page-parts'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import { BulkActionBar } from '@/features/shared/components/bulk-action-bar'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { TonePill } from '@/features/shared/components/tone-pill'
import { ApprovalFindingLink } from '@/features/findings/components/approval-finding-link'
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
import { ClosureEvidence } from './closure-evidence'

const REASON_LABEL: Record<DismissReason, string> = {
  still_present_manual_check: 'Still there: checked by hand',
  scan_not_trustworthy: 'The scan cannot be trusted',
  wrong_asset: 'Wrong asset',
  other: 'Other',
}

type Pending = { kind: 'confirm' | 'dismiss'; rows: ClosureProposal[] } | null

/**
 * Ready to close: closes the platform proposes, for a person to confirm
 * (the finding closes as fixed) or keep open with a reason. Rows are only
 * the caller's data scope; confirming more than one asks for a recent
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
  const { data, error, isLoading, mutate } = useClosureProposals(page, perPage)
  const [selected, setSelected] = useState<ClosureProposal[]>([])
  const [resetKey, setResetKey] = useState(0)
  const [pending, setPending] = useState<Pending>(null)
  const [reason, setReason] = useState<DismissReason>('still_present_manual_check')
  const [note, setNote] = useState('')

  const clearSelection = useCallback(() => setResetKey((k) => k + 1), [])

  const report = useCallback(
    (kind: 'confirm' | 'dismiss', res: DecideResult) => {
      const done = res.applied.length
      const skipped = Object.keys(res.skipped).length
      const msg =
        kind === 'confirm'
          ? t('findings.closureReview.confirmed', 'Closed {count} findings', { count: done })
          : t('findings.closureReview.kept', 'Kept {count} findings open', { count: done })
      if (skipped > 0) {
        toast.warning(
          `${msg}. ${t(
            'findings.closureReview.skipped',
            '{count} were not changed: seen again, changed by someone, or no longer yours to decide.',
            { count: skipped }
          )}`
        )
      } else {
        toast.success(msg)
      }
    },
    [t]
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
      toast.error(getErrorMessage(err))
    }
  }, [pending, reason, note, report, clearSelection, mutate])

  const columns = useMemo<ColumnDef<ClosureProposal>[]>(() => {
    const cols: ColumnDef<ClosureProposal>[] = []
    if (canDecide) {
      cols.push({
        id: 'select',
        header: ({ table }) => (
          <Checkbox
            checked={
              table.getIsAllPageRowsSelected() ||
              (table.getIsSomePageRowsSelected() && 'indeterminate')
            }
            onCheckedChange={(v) => table.toggleAllPageRowsSelected(!!v)}
            aria-label={t('findings.closureReview.selectAll', 'Select all rows on this page')}
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(v) => row.toggleSelected(!!v)}
            aria-label={t('findings.closureReview.selectRow', 'Select {title}', {
              title: toDisplayText(row.original.finding_title, 80),
            })}
          />
        ),
        enableSorting: false,
        enableHiding: false,
      })
    }
    cols.push(
      {
        id: 'finding',
        header: t('findings.closureReview.col.finding', 'Finding'),
        cell: ({ row }) => (
          <div className="grid gap-1">
            <div className="flex flex-wrap items-center gap-1.5">
              <SeverityBadge severity={row.original.severity} />
              {row.original.tier === 'critical' && (
                <TonePill
                  tone="destructive"
                  label={t('findings.closureReview.critical', 'Critical: a person closes it')}
                />
              )}
            </div>
            <ApprovalFindingLink
              findingId={row.original.finding_id}
              findingTitle={row.original.finding_title}
            />
            {row.original.asset_name && (
              <span className="text-xs text-muted-foreground" dir="auto">
                {toDisplayText(row.original.asset_name, 120)}
              </span>
            )}
          </div>
        ),
      },
      {
        id: 'evidence',
        header: t('findings.closureReview.col.why', 'Why it can close'),
        cell: ({ row }) => (
          <ClosureEvidence
            method={row.original.method}
            evidence={row.original.evidence}
            at={row.original.evidence_at}
          />
        ),
      }
    )
    if (canDecide) {
      cols.push({
        id: 'actions',
        header: () => (
          <span className="sr-only">{t('findings.closureReview.col.actions', 'Actions')}</span>
        ),
        cell: ({ row }) => (
          <div className="flex justify-end gap-1.5">
            <Button size="sm" onClick={() => setPending({ kind: 'confirm', rows: [row.original] })}>
              <Check className="h-4 w-4" />
              {t('findings.closureReview.confirm', 'Confirm close')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setPending({ kind: 'dismiss', rows: [row.original] })}
            >
              <CircleSlash className="h-4 w-4" />
              {t('findings.closureReview.keepOpen', 'Keep open')}
            </Button>
          </div>
        ),
      })
    }
    return cols
  }, [canDecide, t])

  if (error) {
    return (
      <ErrorState
        title={t('findings.closureReview.errorName', 'Ready to close')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <TableSkeleton />

  const rows = data.data
  const count = pending?.rows.length ?? 0
  return (
    <>
      <DataTable
        columns={columns}
        data={rows}
        manualPagination
        pageCount={data.total_pages}
        rowCount={data.total}
        pagination={pagination}
        onPaginationChange={onPaginationChange}
        getRowId={(r) => r.id}
        onSelectionChange={setSelected}
        resetSelectionKey={resetKey}
        emptyState={
          <EmptyState
            icon={ListChecks}
            title={t('findings.closureReview.emptyTitle', 'Nothing waits for review')}
            description={t(
              'findings.closureReview.emptyDescription',
              'When a covered scan no longer finds an issue and your closing mode asks for review, the finding waits here.'
            )}
          />
        }
      />
      {canDecide && (
        <BulkActionBar
          count={selected.length}
          onClear={clearSelection}
          noun={t('findings.closureReview.selectedNoun', 'selected')}
        >
          <Button size="sm" onClick={() => setPending({ kind: 'confirm', rows: selected })}>
            <Check className="h-4 w-4" />
            {t('findings.closureReview.confirm', 'Confirm close')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setPending({ kind: 'dismiss', rows: selected })}
          >
            <CircleSlash className="h-4 w-4" />
            {t('findings.closureReview.keepOpen', 'Keep open')}
          </Button>
        </BulkActionBar>
      )}
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
