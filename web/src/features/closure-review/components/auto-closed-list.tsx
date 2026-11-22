'use client'

import { useCallback, useMemo, useState } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { RotateCcw } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { ClosureCaption } from './closure-caption'
import { PageStack } from '@/features/shared/components/page-stack'
import { QueueCard, QueueEmpty, useQueueAnnouncer } from '@/features/shared/components/queue'
import { ApprovalFindingLink } from '@/features/findings/components/approval-finding-link'
import { accessStateOf } from '@/lib/api/access-state'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { toDisplayText } from '@/lib/untrusted-text'
import { useTranslation } from '@/context/i18n-provider'

import { refreshClosureReview, reopenNotFixed, useRecentlyAutoClosed } from '../api'
import type { AutoClosedFinding } from '../types'
import { closureColumns } from './closure-columns'
import { ClosureEvidence } from './closure-evidence'

// "Reopen: not fixed" / its vi form whole, and the cell padding.
const ACTIONS_WIDTH = 224

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
  const { data, error, isLoading, isValidating, mutate } = useRecentlyAutoClosed(page, perPage)
  const announcer = useQueueAnnouncer()
  const [target, setTarget] = useState<AutoClosedFinding | null>(null)
  const [note, setNote] = useState('')

  const reopen = useCallback(async () => {
    if (!target) return
    try {
      await reopenNotFixed(target.finding_id, note.trim() || undefined)
      const msg = t('findings.closureReview.reopened', 'Reopened. The finding is open again.')
      toast.success(msg)
      announcer.announce(msg)
      setTarget(null)
      setNote('')
      await Promise.all([mutate(), refreshClosureReview()])
    } catch (err) {
      const msg = getErrorMessage(err)
      toast.error(msg)
      announcer.announce(msg)
    }
  }, [target, note, t, mutate, announcer])

  const reopenButton = useCallback(
    (row: AutoClosedFinding) =>
      canReopen ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => setTarget(row)}
          aria-label={t('queue.decision.actionNamed', '{action} {name}', {
            action: t('findings.closureReview.reopen', 'Reopen: not fixed'),
            name: toDisplayText(row.finding_title, 80),
          })}
        >
          <RotateCcw aria-hidden />
          {t('findings.closureReview.reopen', 'Reopen: not fixed')}
        </Button>
      ) : null,
    [canReopen, t]
  )

  const columns = useMemo<ColumnDef<AutoClosedFinding>[]>(() => {
    const cols = closureColumns<AutoClosedFinding>(t, {
      method: (r) => r.verification,
      at: (r) => r.resolved_at,
      methodLabel: t('findings.closureReview.col.whyClosed', 'Why it closed'),
      atLabel: t('findings.closureReview.col.closed', 'Closed'),
    })
    const actionsLabel = t('findings.closureReview.col.actions', 'Actions')
    if (canReopen) {
      cols.push({
        id: 'actions',
        meta: { kind: 'actions', width: ACTIONS_WIDTH, label: actionsLabel },
        header: () => <span className="sr-only">{actionsLabel}</span>,
        enableHiding: false,
        enableSorting: false,
        cell: ({ row }) => <div className="flex justify-end">{reopenButton(row.original)}</div>,
      })
    }
    return cols
  }, [canReopen, reopenButton, t])

  const noAccess = !data && accessStateOf(error) === 'no_access'
  const total = data?.total ?? 0
  const viewTitle = t(
    'findings.closureReview.viewName.autoClosed',
    'Closed automatically, last 7 days'
  )
  const errorTitle = t('findings.closureReview.autoClosedErrorName', 'Recently auto-closed')

  return (
    <>
      <PageStack>
        {noAccess ? (
          <NoAccessState title={errorTitle} permission={Permission.FindingsRead} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            caption={viewTitle}
            isLoading={isLoading && !data}
            isRefreshing={isValidating && !!data}
            refreshingLabel={t('findings.closureReview.refreshing', 'Refreshing closes')}
            error={data ? undefined : error}
            onRetry={() => void mutate()}
            errorTitle={errorTitle}
            manualPagination
            showSearch={false}
            pageCount={data?.total_pages ?? 0}
            rowCount={total}
            pagination={pagination}
            onPaginationChange={onPaginationChange}
            paginationNoun={t('findings.closureReview.paginationNoun', 'findings')}
            getRowId={(r) => r.finding_id}
            pinActions
            emptyState={
              <QueueEmpty
                kind="nothing-waiting"
                title={t(
                  'findings.closureReview.autoClosedEmptyTitle',
                  'Nothing closed automatically this week'
                )}
                hint={t(
                  'findings.closureReview.autoClosedEmptyDescription',
                  'Findings the platform closes by itself show here for 7 days, so you can reopen a wrong close.'
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
                    method={row.verification}
                    evidence={row.evidence}
                    at={row.resolved_at}
                  />
                }
                meta={[
                  row.asset_name ? (
                    <span key="asset" dir="auto">
                      {toDisplayText(row.asset_name, 120)}
                    </span>
                  ) : null,
                ]}
                actions={reopenButton(row)}
              />
            )}
          />
        )}
        <ClosureCaption
          total={total}
          loading={(isLoading && !data) || noAccess}
          refreshing={isValidating}
          onRefresh={() => void mutate()}
        />
      </PageStack>
      {announcer.region}
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
