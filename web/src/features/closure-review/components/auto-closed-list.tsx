'use client'

import { useCallback, useMemo, useState } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { History, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { TableSkeleton } from '@/components/list-page-parts'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { ApprovalFindingLink } from '@/features/findings/components/approval-finding-link'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { toDisplayText } from '@/lib/untrusted-text'
import { useTranslation } from '@/context/i18n-provider'

import { refreshClosureReview, reopenNotFixed, useRecentlyAutoClosed } from '../api'
import type { AutoClosedFinding } from '../types'
import { ClosureEvidence } from './closure-evidence'

/**
 * Recently auto-closed: what the platform closed by itself in the last 7
 * days, with the scan behind each close and a one-click "Reopen: not fixed".
 */
export function AutoClosedList({
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
  const canReopen = can(Permission.FindingsStatus)
  const { data, error, isLoading, mutate } = useRecentlyAutoClosed(page, perPage)
  const [target, setTarget] = useState<AutoClosedFinding | null>(null)
  const [note, setNote] = useState('')

  const reopen = useCallback(async () => {
    if (!target) return
    try {
      await reopenNotFixed(target.finding_id, note.trim() || undefined)
      toast.success(t('findings.closureReview.reopened', 'Reopened. The finding is open again.'))
      setTarget(null)
      setNote('')
      await Promise.all([mutate(), refreshClosureReview()])
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }, [target, note, t, mutate])

  const columns = useMemo<ColumnDef<AutoClosedFinding>[]>(() => {
    const cols: ColumnDef<AutoClosedFinding>[] = [
      {
        id: 'finding',
        header: t('findings.closureReview.col.finding', 'Finding'),
        cell: ({ row }) => (
          <div className="grid gap-1">
            <SeverityBadge severity={row.original.severity} />
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
        header: t('findings.closureReview.col.whyClosed', 'Why it closed'),
        cell: ({ row }) => (
          <ClosureEvidence
            method={row.original.verification}
            evidence={row.original.evidence}
            at={row.original.resolved_at}
          />
        ),
      },
    ]
    if (canReopen) {
      cols.push({
        id: 'actions',
        header: () => (
          <span className="sr-only">{t('findings.closureReview.col.actions', 'Actions')}</span>
        ),
        cell: ({ row }) => (
          <div className="flex justify-end">
            <Button size="sm" variant="outline" onClick={() => setTarget(row.original)}>
              <RotateCcw className="h-4 w-4" />
              {t('findings.closureReview.reopen', 'Reopen: not fixed')}
            </Button>
          </div>
        ),
      })
    }
    return cols
  }, [canReopen, t])

  if (error) {
    return (
      <ErrorState
        title={t('findings.closureReview.autoClosedErrorName', 'Recently auto-closed')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <TableSkeleton />

  return (
    <>
      <DataTable
        columns={columns}
        data={data.data}
        manualPagination
        pageCount={data.total_pages}
        rowCount={data.total}
        pagination={pagination}
        onPaginationChange={onPaginationChange}
        getRowId={(r) => r.finding_id}
        emptyState={
          <EmptyState
            icon={History}
            title={t(
              'findings.closureReview.autoClosedEmptyTitle',
              'Nothing closed automatically this week'
            )}
            description={t(
              'findings.closureReview.autoClosedEmptyDescription',
              'Findings the platform closes by itself show here for 7 days, so you can reopen a wrong close.'
            )}
          />
        }
      />
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(o) => !o && setTarget(null)}
        title={t('findings.closureReview.reopenTitle', 'Reopen this finding?')}
        desc={t(
          'findings.closureReview.reopenDesc',
          'It opens again as confirmed, and the automatic close is recorded as wrong. It does not count as a regression.'
        )}
        confirmText={t('findings.closureReview.reopen', 'Reopen: not fixed')}
        handleConfirm={reopen}
      >
        <div className="grid gap-1.5">
          <Label htmlFor="closure-reopen-note">
            {t('findings.closureReview.note', 'Note (optional)')}
          </Label>
          <Textarea
            id="closure-reopen-note"
            value={note}
            maxLength={1000}
            onChange={(e) => setNote(e.target.value)}
          />
        </div>
      </ConfirmDialog>
    </>
  )
}
