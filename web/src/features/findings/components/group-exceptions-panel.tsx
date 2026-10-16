'use client'

/**
 * Group exceptions in the approvals inbox: one row per exception (source
 * task, status, tier and sign-offs, member count, deadline) and a side panel
 * with its members and the decision (approve, reject with a reason, cancel
 * by the requester). See api/docs/rfcs/RFC-111-approval-policy.md.
 * The API decides who may act; the UI hides what the caller could not do.
 */

import { useCallback, useMemo, useState } from 'react'
import { type ColumnDef, type PaginationState } from '@tanstack/react-table'
import { formatDistanceToNow } from 'date-fns'
import { Ban, Check, Loader2, X } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { Can, Permission } from '@/lib/permissions'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import {
  approvalBatchApi,
  useApprovalBatch,
  useApprovalBatches,
  type ApprovalBatch,
} from '../api/use-approval-batches'
import type { ApprovalStatus } from '../types/finding.types'
import { approveErrorOutcome, approveResultOutcome, kindLabel } from '../lib/approval-policy'
import { closureReasonLabel } from '../lib/closure'
import { ApprovalTierCell } from './approval-tier-cell'

type Translate = ReturnType<typeof useTranslation>['t']

const STATUS_STYLES: Record<string, string> = {
  pending: 'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30',
  approved: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30',
  rejected: 'bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30',
  canceled: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/30',
  expired: 'bg-muted text-muted-foreground border-border',
}

const STATUS_FALLBACK: Record<string, string> = {
  pending: 'Pending',
  approved: 'Approved',
  rejected: 'Rejected',
  canceled: 'Canceled',
  expired: 'Expired',
}

function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation()
  return (
    <Badge variant="outline" className={cn('text-xs', STATUS_STYLES[status])}>
      {t(`findings.approvals.status.${status}`, STATUS_FALLBACK[status] ?? status)}
    </Badge>
  )
}

function ago(date: string | undefined): string {
  if (!date) return '-'
  const d = new Date(date)
  return Number.isNaN(d.getTime()) ? '-' : formatDistanceToNow(d, { addSuffix: true })
}

/** What a group exception decision did, for its toast. */
function appliedDescription(t: Translate, batch: ApprovalBatch): string {
  const canceled = batch.canceled?.length ?? 0
  const base = t('findingApprovals.group.appliedDesc', '{count} finding(s) moved to {kind}.', {
    count: batch.applied ?? batch.member_count,
    kind: kindLabel(t, batch.requested_status),
  })
  return canceled > 0
    ? `${base} ${t(
        'findingApprovals.group.canceledDesc',
        '{count} left out because they changed meanwhile.',
        { count: canceled }
      )}`
    : base
}

interface GroupExceptionsPanelProps {
  status?: ApprovalStatus
  pagination: PaginationState
  onPaginationChange: (p: PaginationState) => void
  currentUserId: string | undefined
  /** The group exception shown in the side panel. */
  openId: string | null
  onOpenChange: (id: string | null) => void
  /** After a decision: refresh other lists and badges. */
  onDecided?: () => void | Promise<unknown>
}

export function GroupExceptionsPanel({
  status,
  pagination,
  onPaginationChange,
  currentUserId,
  openId,
  onOpenChange,
  onDecided,
}: GroupExceptionsPanelProps) {
  const { t } = useTranslation()
  const { data, isLoading, mutate } = useApprovalBatches(
    pagination.pageIndex + 1,
    pagination.pageSize,
    status
  )
  const rows = useMemo(() => data?.data ?? [], [data?.data])
  const pageCount = data ? Math.max(1, Math.ceil(data.total / pagination.pageSize)) : 1

  const columns = useMemo<ColumnDef<ApprovalBatch>[]>(
    () => [
      {
        id: 'status',
        header: t('findings.approvals.col.status', 'Status'),
        cell: ({ row }) => <StatusBadge status={row.original.status} />,
      },
      {
        id: 'task',
        header: t('findingApprovals.group.col.task', 'Remediation task'),
        cell: ({ row }) => (
          <Link
            href={`/remediation/tasks/${encodeURIComponent(row.original.source_id)}`}
            className="line-clamp-2 max-w-[280px] font-medium hover:underline"
          >
            {row.original.source_title ||
              t('findingApprovals.group.untitledTask', 'Remediation task')}
          </Link>
        ),
      },
      {
        id: 'kind',
        header: t('findings.approvals.col.requestedStatus', 'Requested status'),
        cell: ({ row }) => (
          <span className="text-sm whitespace-nowrap">
            {kindLabel(t, row.original.requested_status)}
          </span>
        ),
      },
      {
        id: 'tier',
        header: t('findings.approvals.col.tier', 'Approval'),
        cell: ({ row }) => <ApprovalTierCell approval={row.original} showSingleProgress />,
      },
      {
        id: 'members',
        header: t('findingApprovals.group.col.members', 'Findings'),
        cell: ({ row }) => <span className="font-mono text-sm">{row.original.member_count}</span>,
      },
      {
        id: 'decide_by',
        header: t('findings.approvals.col.decideBy', 'Decide by'),
        cell: ({ row }) => (
          <span className="text-sm whitespace-nowrap text-muted-foreground">
            {row.original.status === 'pending' ? ago(row.original.decide_by) : '-'}
          </span>
        ),
      },
      {
        id: 'actions',
        enableHiding: false,
        cell: ({ row }) => (
          <Button variant="outline" size="sm" onClick={() => onOpenChange(row.original.id)}>
            {t('findingApprovals.group.view', 'View')}
          </Button>
        ),
      },
    ],
    [onOpenChange, t]
  )

  const decided = useCallback(async () => {
    await Promise.all([mutate(), onDecided?.()])
  }, [mutate, onDecided])

  return (
    <>
      {isLoading && !data ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <DataTable
          columns={columns}
          data={rows}
          manualPagination
          pageCount={pageCount}
          rowCount={data?.total ?? 0}
          pagination={pagination}
          onPaginationChange={onPaginationChange}
          getRowId={(row) => row.id}
          showColumnToggle={false}
          emptyMessage={t('findingApprovals.group.empty', 'No group exceptions')}
          emptyDescription={t(
            'findingApprovals.group.emptyDesc',
            'An exception asked for on a remediation task appears here.'
          )}
        />
      )}
      <GroupExceptionSheet
        id={openId}
        onOpenChange={(open) => !open && onOpenChange(null)}
        currentUserId={currentUserId}
        onDecided={decided}
      />
    </>
  )
}

/** One group exception: its details, members and the decision. */
export function GroupExceptionSheet({
  id,
  onOpenChange,
  currentUserId,
  onDecided,
}: {
  id: string | null
  onOpenChange: (open: boolean) => void
  currentUserId: string | undefined
  onDecided?: () => void | Promise<unknown>
}) {
  const { t } = useTranslation()
  const { data: batch, error, isLoading, mutate } = useApprovalBatch(id)
  const [busy, setBusy] = useState<null | 'approve' | 'reject' | 'cancel'>(null)
  const [rejectOpen, setRejectOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [cancelOpen, setCancelOpen] = useState(false)

  const pending = batch?.status === 'pending'
  // The four-eyes rule: someone else decides your own request.
  const own = !!batch?.requested_by && batch.requested_by === currentUserId
  const remaining = batch ? batch.approvals_required - batch.approvals_collected : 0

  const after = async () => {
    await Promise.all([mutate(), onDecided?.()])
  }

  const approve = async () => {
    if (!batch || busy) return
    setBusy('approve')
    try {
      // A re-authentication prompt (STEP_UP_REQUIRED) is answered by the API
      // client, which retries once; a cancelled prompt ends up below.
      const res = await approvalBatchApi.approve(batch.id)
      const outcome = approveResultOutcome(res)
      if (outcome.kind === 'recorded') {
        toast.success(t('findings.approvals.toast.signed', 'Your approval is recorded'), {
          description: t(
            'findingApprovals.group.signedDesc',
            '{count} more approval(s) needed before the findings change.',
            { count: outcome.remaining }
          ),
        })
      } else {
        toast.success(t('findingApprovals.group.approved', 'Group exception approved'), {
          description: appliedDescription(t, res),
        })
      }
      await after()
    } catch (err) {
      const outcome = approveErrorOutcome(t, err)
      toast.error(
        outcome.kind === 'refused'
          ? outcome.message
          : getErrorMessage(
              err,
              t('findings.approvals.toast.approveFailed', 'Failed to approve request')
            )
      )
      if (outcome.kind === 'refused') await after()
    } finally {
      setBusy(null)
    }
  }

  const reject = async () => {
    if (!batch || busy || !reason.trim()) return
    setBusy('reject')
    try {
      await approvalBatchApi.reject(batch.id, reason.trim())
      toast.success(t('findingApprovals.group.rejected', 'Group exception rejected'))
      setRejectOpen(false)
      setReason('')
      await after()
    } catch (err) {
      const outcome = approveErrorOutcome(t, err)
      toast.error(
        outcome.kind === 'refused'
          ? outcome.message
          : getErrorMessage(
              err,
              t('findings.approvals.toast.rejectFailed', 'Failed to reject request')
            )
      )
    } finally {
      setBusy(null)
    }
  }

  const cancel = async () => {
    if (!batch || busy) return
    setBusy('cancel')
    try {
      await approvalBatchApi.cancel(batch.id)
      toast.success(t('findingApprovals.group.canceled', 'Group exception canceled'))
      setCancelOpen(false)
      await after()
    } catch (err) {
      const outcome = approveErrorOutcome(t, err)
      toast.error(
        outcome.kind === 'refused'
          ? outcome.message
          : getErrorMessage(
              err,
              t('findings.approvals.toast.cancelFailed', 'Failed to cancel request')
            )
      )
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <Sheet open={!!id} onOpenChange={onOpenChange}>
        <SheetContent side="right" className="w-full sm:max-w-xl">
          <SheetHeader>
            <SheetTitle>{t('findingApprovals.group.sheetTitle', 'Group exception')}</SheetTitle>
            <SheetDescription>
              {batch ? (
                <Link
                  href={`/remediation/tasks/${encodeURIComponent(batch.source_id)}`}
                  className="hover:underline"
                >
                  {batch.source_title ||
                    t('findingApprovals.group.untitledTask', 'Remediation task')}
                </Link>
              ) : (
                t('findingApprovals.group.loading', 'Loading…')
              )}
            </SheetDescription>
          </SheetHeader>
          <SheetBody className="space-y-4">
            {error ? (
              <p role="alert" className="text-sm text-destructive">
                {getErrorMessage(
                  error,
                  t('findingApprovals.group.loadFailed', 'Could not load this group exception.')
                )}
              </p>
            ) : isLoading || !batch ? (
              <Skeleton className="h-48 w-full" />
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={batch.status} />
                  <Badge variant="outline" className="text-xs">
                    {kindLabel(t, batch.requested_status)}
                  </Badge>
                  <ApprovalTierCell approval={batch} showSingleProgress />
                </div>
                <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
                  <dt className="text-muted-foreground">
                    {t('findings.approvalDialog.reasonLabel', 'Reason:')}
                  </dt>
                  <dd>{closureReasonLabel(t, batch.closure_reason)}</dd>
                  {batch.expires_at && (
                    <>
                      <dt className="text-muted-foreground">
                        {t('findings.approvalDialog.expires', 'Expires:')}
                      </dt>
                      <dd>{new Date(batch.expires_at).toLocaleDateString()}</dd>
                    </>
                  )}
                  {pending && (
                    <>
                      <dt className="text-muted-foreground">
                        {t('findingApprovals.group.decideBy', 'Decide by')}
                      </dt>
                      <dd>{ago(batch.decide_by)}</dd>
                    </>
                  )}
                  <dt className="text-muted-foreground">
                    {t('findings.approvals.col.created', 'Created')}
                  </dt>
                  <dd>{ago(batch.created_at)}</dd>
                </dl>
                <p className="rounded-md border bg-muted/50 p-2 text-sm whitespace-pre-wrap break-words">
                  {batch.justification}
                </p>
                {batch.rejection_reason && (
                  <p className="text-sm">
                    <span className="text-muted-foreground">
                      {t('findingApprovals.group.rejectionReason', 'Rejected because:')}
                    </span>{' '}
                    {batch.rejection_reason}
                  </p>
                )}
                <section className="space-y-2">
                  <h3 className="text-sm font-semibold">
                    {t('findingApprovals.group.memberCount', '{count} finding(s)', {
                      count: batch.member_count,
                    })}
                  </h3>
                  <ul className="divide-y rounded-md border text-sm" data-testid="batch-members">
                    {(batch.members ?? []).map((m) => (
                      <li
                        key={m.approval_id}
                        className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2"
                      >
                        <Link
                          href={`/findings/${encodeURIComponent(m.finding_id)}`}
                          className="min-w-0 flex-1 basis-40 truncate hover:underline"
                          title={m.title}
                        >
                          {m.title || m.finding_id}
                        </Link>
                        {m.severity && <SeverityBadge severity={m.severity as Severity} />}
                        {m.status !== 'pending' && <StatusBadge status={m.status} />}
                        {m.expires_at && (
                          <span className="text-xs whitespace-nowrap text-muted-foreground">
                            {t('findingApprovals.group.endsOn', 'ends {date}', {
                              date: new Date(m.expires_at).toLocaleDateString(),
                            })}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
                {pending && own && (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'findings.approvals.ownRequestHint',
                      'Another approver must decide your own request.'
                    )}
                  </p>
                )}
              </>
            )}
          </SheetBody>
          {batch && pending && (
            <SheetFooter className="flex-row flex-wrap justify-end gap-2">
              {own && (
                <Can permission={Permission.FindingsWrite}>
                  <Button variant="outline" onClick={() => setCancelOpen(true)} disabled={!!busy}>
                    <Ban className="me-2 h-4 w-4" aria-hidden />
                    {t('findings.approvals.action.cancel', 'Cancel request')}
                  </Button>
                </Can>
              )}
              {!own && (
                <Can permission={Permission.FindingsApprove}>
                  <Button
                    variant="outline"
                    onClick={() => {
                      setReason('')
                      setRejectOpen(true)
                    }}
                    disabled={!!busy}
                  >
                    <X className="me-2 h-4 w-4 text-red-500" aria-hidden />
                    {t('findings.approvals.action.reject', 'Reject')}
                  </Button>
                  <Button onClick={() => void approve()} disabled={!!busy}>
                    {busy === 'approve' ? (
                      <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />
                    ) : (
                      <Check className="me-2 h-4 w-4" aria-hidden />
                    )}
                    {remaining > 1
                      ? t('findingApprovals.group.approveSign', 'Add my approval')
                      : t('findingApprovals.group.approveAll', 'Approve {count} finding(s)', {
                          count: batch.member_count,
                        })}
                  </Button>
                </Can>
              )}
            </SheetFooter>
          )}
        </SheetContent>
      </Sheet>

      <Dialog open={rejectOpen} onOpenChange={(v) => !busy && setRejectOpen(v)}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>
              {t('findingApprovals.group.rejectTitle', 'Reject group exception')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'findingApprovals.group.rejectDesc',
                'Every finding keeps its status. Give a reason; the requester sees it.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-2">
            <Textarea
              aria-label={t('findings.approvals.rejectPlaceholder', 'Reason for rejection…')}
              placeholder={t('findings.approvals.rejectPlaceholder', 'Reason for rejection…')}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              maxLength={2000}
            />
            <p className="text-end text-xs text-muted-foreground">{reason.length}/2000</p>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRejectOpen(false)} disabled={!!busy}>
              {t('findings.approvals.cancel', 'Cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() => void reject()}
              disabled={!!busy || !reason.trim()}
            >
              {busy === 'reject' && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
              {t('findings.approvals.action.reject', 'Reject')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={cancelOpen}
        onOpenChange={setCancelOpen}
        title={t('findingApprovals.group.cancelTitle', 'Cancel this group exception?')}
        desc={t(
          'findingApprovals.group.cancelDesc',
          'Every finding keeps its current status. Ask again if needed.'
        )}
        cancelBtnText={t('confirm.findingApproval.keep', 'Keep request')}
        confirmText={t('confirm.findingApproval.cancel', 'Cancel request')}
        destructive
        isLoading={busy === 'cancel'}
        handleConfirm={cancel}
      />
    </>
  )
}
