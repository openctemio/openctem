'use client'

import { useState, useCallback, useMemo } from 'react'
import Link from '@/components/link'
import { type ColumnDef } from '@tanstack/react-table'
import { formatDistanceToNow } from 'date-fns'
import {
  MoreHorizontal,
  Check,
  X,
  Ban,
  BellRing,
  Loader2,
  ArrowLeft,
  RefreshCw,
  AlertCircle,
  ShieldCheck,
  Layers,
} from 'lucide-react'
import { toast } from 'sonner'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared/components/page-header'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import { DataTableColumnHeader } from '@/features/shared/components/data-table/data-table-column-header'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsCount } from '@/components/ui/tabs'
import { SegmentedLens } from '@/features/shared/components/segmented-lens'
import { RefreshButton, TableSkeleton } from '@/components/list-page-parts'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission } from '@/lib/permissions'

import { useDisplayUser } from '@/hooks/use-display-user'
import { refreshPendingApprovalCount } from '@/hooks/use-dynamic-badges'
import {
  useApprovals,
  useApproveStatus,
  useRejectApproval,
  useCancelApproval,
  remindApprovers,
} from '@/features/findings/api/use-findings-api'
import type { ApiApproval, ApprovalStatus } from '@/features/findings/types'
import { FINDING_STATUS_CONFIG } from '@/features/findings/types'
import { ApprovalFindingLink } from '@/features/findings/components/approval-finding-link'
import { useListParams } from '@/hooks/use-list-params'
import {
  approvalRequester,
  approvalTabCounts,
  canCancelApproval,
  isOwnApproval,
} from '@/features/findings/lib/approvals'
import { useTranslation } from '@/context/i18n-provider'
import { AIProposalBadge } from '@/features/findings/components/ai-proposal-badge'
import { closureReasonLabel } from '@/features/findings/lib/closure'
import { FindingSelfApproveDialog } from '@/features/findings/components/finding-self-approve-dialog'
import { approveErrorOutcome, approveResultOutcome } from '@/features/findings/lib/approval-policy'
import { ApprovalTierCell } from '@/features/findings/components/approval-tier-cell'
import { GroupExceptionsPanel } from '@/features/findings/components/group-exceptions-panel'
import { useApprovalBatches } from '@/features/findings/api/use-approval-batches'

// ============================================
// CONSTANTS
// ============================================

const APPROVAL_BADGE_STYLES: Record<ApprovalStatus, string> = {
  pending: 'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30',
  approved: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30',
  rejected: 'bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30',
  canceled: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/30',
  expired: 'bg-muted text-muted-foreground border-border',
}

/** English fallbacks; the localised label is findings.approvals.status.<status>. */
const APPROVAL_STATUS_LABELS: Record<ApprovalStatus, string> = {
  pending: 'Pending',
  approved: 'Approved',
  rejected: 'Rejected',
  canceled: 'Canceled',
  expired: 'Expired',
}

/** English fallbacks for the platform actors that request changes. */
const APPROVAL_ACTOR_LABELS: Record<string, string> = {
  ai_triage: 'AI triage',
  vex: 'VEX statement',
  ticket: 'Linked ticket',
}

/**
 * The status lens over both kinds of request. Pending (what needs a decision)
 * is the default and needs no URL value; canceled and expired requests are
 * closed without a decision and are listed under All.
 */
const APPROVAL_LENSES = ['pending', 'approved', 'rejected', 'all'] as const
type ApprovalLens = (typeof APPROVAL_LENSES)[number]

function parseApprovalLens(raw: string): ApprovalLens {
  return (APPROVAL_LENSES as readonly string[]).includes(raw) ? (raw as ApprovalLens) : 'pending'
}

// ============================================
// HELPERS
// ============================================

function formatDate(dateString: string): string {
  return formatDistanceToNow(new Date(dateString), { addSuffix: true })
}

type Translate = ReturnType<typeof useTranslation>['t']

function getRequestedStatusLabel(t: Translate, status: string): string {
  const config = FINDING_STATUS_CONFIG[status as keyof typeof FINDING_STATUS_CONFIG]
  return config ? t(config.labelKey, config.label) : status
}

function RequesterCell({
  approval,
  currentUserId,
}: {
  approval: ApiApproval
  currentUserId: string | undefined
}) {
  const { t } = useTranslation()
  const who = approvalRequester(approval, currentUserId)
  switch (who.kind) {
    case 'actor':
      return (
        <span className="text-sm text-muted-foreground">
          {t(
            `findings.approvals.actor.${who.actor}`,
            APPROVAL_ACTOR_LABELS[who.actor] ?? who.actor
          )}
        </span>
      )
    case 'you':
      return (
        <span className="text-sm font-medium">{t('findings.approvals.requesterYou', 'You')}</span>
      )
    case 'member':
      return <span className="text-sm">{who.name}</span>
    default:
      return (
        <span className="text-sm text-muted-foreground">
          {t('findings.approvals.requesterFormer', 'Former member')}
        </span>
      )
  }
}

// ============================================
// MAIN PAGE COMPONENT
// ============================================

export default function ApprovalsPage() {
  const { t } = useTranslation()
  // Tab (status) and page live in the URL, like every list.
  const list = useListParams({ filters: { status: '', view: '', batch: '' } })
  // Finding requests, or group exceptions (one decision over a task's findings).
  const view: 'requests' | 'groups' = list.filters.view === 'groups' ? 'groups' : 'requests'
  // The group exception in the side panel: picked here, or named by a link.
  const [pickedBatch, setPickedBatch] = useState<string | null>(null)
  const openBatch = pickedBatch ?? (list.filters.batch || null)
  const lens = parseApprovalLens(list.filters.status)
  const lensStatus: ApprovalStatus | undefined = lens === 'all' ? undefined : lens
  const currentUserId = useDisplayUser()?.id

  // Action state
  const [approveDialogOpen, setApproveDialogOpen] = useState(false)
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false)
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false)
  const [selectedApproval, setSelectedApproval] = useState<ApiApproval | null>(null)
  const [rejectionReason, setRejectionReason] = useState('')
  const [actionInProgress, setActionInProgress] = useState<string | null>(null)
  // The sole member's own approval (shown only when the API offers it).
  const [selfApproveTarget, setSelfApproveTarget] = useState<ApiApproval | null>(null)

  // One server page of the lens; the counts cover every status.
  const {
    data,
    isLoading,
    error,
    mutate: mutateList,
  } = useApprovals(list.page, list.perPage, lensStatus)
  // Pending group exceptions, for the view switch's count.
  const { data: pendingGroups, mutate: mutatePendingGroups } = useApprovalBatches(1, 1, 'pending')
  // A decision changes the lists and the sidebar's Approvals badge.
  const mutate = useCallback(
    () => Promise.all([mutateList(), mutatePendingGroups(), refreshPendingApprovalCount()]),
    [mutateList, mutatePendingGroups]
  )

  // Action hooks
  const { trigger: triggerApprove, isMutating: isApproving } = useApproveStatus(
    selectedApproval?.id ?? ''
  )
  const { trigger: triggerReject, isMutating: isRejecting } = useRejectApproval(
    selectedApproval?.id ?? ''
  )
  const { trigger: triggerCancel, isMutating: isCancelling } = useCancelApproval(
    selectedApproval?.id ?? ''
  )

  const approvals = useMemo(() => data?.data ?? [], [data?.data])
  const selfApprovalAvailable = data?.self_approval_available === true
  const counts = useMemo(() => approvalTabCounts(data?.status_counts), [data?.status_counts])
  const pageCount = data ? Math.max(1, Math.ceil(data.total / list.perPage)) : 1

  const { setFilter } = list
  const changeLens = useCallback(
    (next: ApprovalLens) => setFilter('status', next === 'pending' ? '' : next),
    [setFilter]
  )
  const changeView = useCallback(
    (next: string) => {
      setPickedBatch(null)
      setFilter('view', next === 'groups' ? 'groups' : '')
    },
    [setFilter]
  )
  const changeOpenBatch = useCallback(
    (id: string | null) => {
      setPickedBatch(id)
      if (!id && list.filters.batch) setFilter('batch', '')
    },
    [list.filters.batch, setFilter]
  )

  const isInitialLoading = isLoading && !data
  const pendingTotal = counts.pending + (pendingGroups?.total ?? 0)

  // ============================================
  // ACTION HANDLERS
  // ============================================

  const handleApproveClick = useCallback((approval: ApiApproval) => {
    setSelectedApproval(approval)
    setApproveDialogOpen(true)
  }, [])

  const handleRejectClick = useCallback((approval: ApiApproval) => {
    setSelectedApproval(approval)
    setRejectionReason('')
    setRejectDialogOpen(true)
  }, [])

  const handleCancelClick = useCallback((approval: ApiApproval) => {
    setSelectedApproval(approval)
    setCancelDialogOpen(true)
  }, [])

  const handleApproveConfirm = async () => {
    if (!selectedApproval || actionInProgress) return
    setActionInProgress(selectedApproval.id)
    try {
      // A re-authentication prompt (STEP_UP_REQUIRED) is answered by the API
      // client, which retries once; a cancelled prompt ends up below.
      const outcome = approveResultOutcome(await triggerApprove())
      if (outcome.kind === 'recorded') {
        toast.success(t('findings.approvals.toast.signed', 'Your approval is recorded'), {
          description: t(
            'findings.approvals.toast.signedDesc',
            '{count} more approval(s) needed before the status changes.',
            { count: outcome.remaining }
          ),
        })
      } else {
        toast.success(t('findings.approvals.toast.approved', 'Approval request approved'), {
          description: t(
            'findings.approvals.toast.approvedDesc',
            'Finding status will be changed to {status}',
            { status: getRequestedStatusLabel(t, selectedApproval.requested_status) }
          ),
        })
      }
      await mutate()
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
      if (outcome.kind === 'refused') await mutate()
    } finally {
      setActionInProgress(null)
      setSelectedApproval(null)
      setApproveDialogOpen(false)
    }
  }

  const handleRejectConfirm = async () => {
    if (!selectedApproval || actionInProgress || !rejectionReason.trim()) return
    setActionInProgress(selectedApproval.id)
    try {
      await triggerReject({ reason: rejectionReason.trim() })
      toast.success(t('findings.approvals.toast.rejected', 'Approval request rejected'))
      setRejectionReason('')
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('findings.approvals.toast.rejectFailed', 'Failed to reject request'))
      )
    } finally {
      setActionInProgress(null)
      setSelectedApproval(null)
      setRejectDialogOpen(false)
    }
  }

  const handleCancelConfirm = async () => {
    if (!selectedApproval || actionInProgress) return
    setActionInProgress(selectedApproval.id)
    try {
      await triggerCancel()
      toast.success(t('findings.approvals.toast.canceled', 'Approval request canceled'))
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('findings.approvals.toast.cancelFailed', 'Failed to cancel request'))
      )
    } finally {
      setActionInProgress(null)
      setSelectedApproval(null)
      setCancelDialogOpen(false)
    }
  }

  // Nudge the approvers of your own pending request (rate-limited per hour
  // by the API).
  const handleRemind = useCallback(
    async (approval: ApiApproval) => {
      if (actionInProgress) return
      setActionInProgress(approval.id)
      try {
        const res = await remindApprovers(approval.id)
        toast.success(
          t('findings.approvals.toast.reminded', 'Reminded {count} approver(s)', {
            count: res?.reminded ?? 0,
          })
        )
      } catch (err) {
        if (err instanceof ApiClientError && err.statusCode === 409) {
          toast.error(
            t(
              'findings.approvals.toast.remindTooSoon',
              'The approvers were already reminded in the last hour.'
            )
          )
        } else {
          toast.error(
            getErrorMessage(
              err,
              t('findings.approvals.toast.remindFailed', 'Failed to send the reminder')
            )
          )
        }
      } finally {
        setActionInProgress(null)
      }
    },
    [actionInProgress, t]
  )

  const handleRefresh = async () => {
    await mutate()
    toast.success(t('findings.approvals.toast.refreshed', 'Approvals refreshed'))
  }

  // The list toolbar: the status lens first, refresh at the end.
  const statusLens = (
    <SegmentedLens<ApprovalLens>
      label={t('findings.approvals.lens.label', 'Request status')}
      value={lens}
      onChange={changeLens}
      options={APPROVAL_LENSES.map((value) => ({
        value,
        label:
          value === 'all'
            ? t('findings.approvals.tabAll', 'All')
            : t(`findings.approvals.status.${value}`, APPROVAL_STATUS_LABELS[value]),
      }))}
    />
  )
  const refreshButton = (
    <RefreshButton
      onClick={() => void handleRefresh()}
      loading={isLoading}
      label={t('findings.approvals.refresh', 'Refresh')}
    />
  )

  // ============================================
  // TABLE COLUMNS
  // ============================================

  const columns: ColumnDef<ApiApproval>[] = useMemo(
    () => [
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.approvals.col.status', 'Status')}
          />
        ),
        cell: ({ row }) => {
          const status = row.getValue('status') as ApprovalStatus
          return (
            <div className="flex flex-wrap items-center gap-1">
              <Badge variant="outline" className={cn('text-xs', APPROVAL_BADGE_STYLES[status])}>
                {t(`findings.approvals.status.${status}`, APPROVAL_STATUS_LABELS[status] ?? status)}
              </Badge>
              {row.original.self_approved && (
                <Badge
                  variant="outline"
                  className="text-xs border-warning/40 text-warning"
                  title={t(
                    'findingApprovals.selfApprove.badgeTitle',
                    "Approved by its own requester, the organization's only member"
                  )}
                >
                  {t('findingApprovals.selfApprove.badge', 'Self-approved')}
                </Badge>
              )}
              {row.original.single_person && (
                <Badge
                  variant="outline"
                  className="text-xs border-info/40 text-info"
                  title={t(
                    'findingApprovals.single.badgeTitle',
                    "Decided by one person: the organization's false-positive level did not require a second"
                  )}
                >
                  {t('findingApprovals.single.badge', 'Single person')}
                </Badge>
              )}
            </div>
          )
        },
        enableSorting: true,
      },
      {
        accessorKey: 'finding_id',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.approvals.col.finding', 'Finding')}
          />
        ),
        cell: ({ row }) => (
          <ApprovalFindingLink
            findingId={row.original.finding_id}
            findingTitle={row.original.finding_title}
          />
        ),
        enableSorting: false,
      },
      {
        accessorKey: 'requested_status',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.approvals.col.requestedStatus', 'Requested status')}
          />
        ),
        cell: ({ row }) => {
          const status = row.getValue('requested_status') as string
          const config = FINDING_STATUS_CONFIG[status as keyof typeof FINDING_STATUS_CONFIG]
          return (
            <Badge
              variant="outline"
              className={cn('text-xs', config?.bgColor, config?.textColor, config?.color)}
            >
              {getRequestedStatusLabel(t, status)}
            </Badge>
          )
        },
        enableSorting: true,
      },
      {
        id: 'tier',
        header: t('findings.approvals.col.tier', 'Approval'),
        cell: ({ row }) => <ApprovalTierCell approval={row.original} />,
        enableSorting: false,
      },
      {
        id: 'requester',
        header: t('findings.approvals.col.requester', 'Requester'),
        cell: ({ row }) => <RequesterCell approval={row.original} currentUserId={currentUserId} />,
        enableSorting: false,
      },
      {
        accessorKey: 'justification',
        header: t('findings.approvals.col.justification', 'Justification'),
        cell: ({ row }) => {
          const text = row.getValue('justification') as string
          return (
            <div className="flex max-w-[300px] flex-col gap-1">
              <AIProposalBadge approval={row.original} />
              <span className="text-sm text-muted-foreground line-clamp-2" title={text}>
                {text}
              </span>
            </div>
          )
        },
        enableSorting: false,
      },
      {
        accessorKey: 'created_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.approvals.col.created', 'Created')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-muted-foreground text-sm whitespace-nowrap">
            {formatDate(row.getValue('created_at'))}
          </span>
        ),
        enableSorting: true,
      },
      {
        accessorKey: 'decide_by',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.approvals.col.decideBy', 'Decide by')}
          />
        ),
        cell: ({ row }) => {
          const by = row.original.decide_by
          return (
            <span className="text-muted-foreground text-sm whitespace-nowrap">
              {by && row.original.status === 'pending' ? formatDate(by) : '-'}
            </span>
          )
        },
        enableSorting: false,
      },
      {
        accessorKey: 'expires_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.approvals.col.expires', 'Acceptance ends')}
          />
        ),
        cell: ({ row }) => {
          const expires = row.getValue('expires_at') as string | undefined
          return (
            <span className="text-muted-foreground text-sm whitespace-nowrap">
              {expires ? formatDate(expires) : '-'}
            </span>
          )
        },
        enableSorting: true,
      },
      {
        id: 'actions',
        enableHiding: false,
        cell: ({ row }) => {
          const approval = row.original
          if (approval.status !== 'pending') return null
          // A member of a group exception is decided only with its group.
          if (approval.batch_id) {
            return (
              <Link
                href={`/findings/approvals?view=groups&batch=${encodeURIComponent(approval.batch_id)}`}
                className="inline-flex items-center gap-1 text-xs whitespace-nowrap text-muted-foreground hover:text-foreground hover:underline"
                data-testid="approval-batch-link"
              >
                <Layers className="h-3.5 w-3.5" aria-hidden />
                {t('findingApprovals.group.memberOf', 'Part of a group exception')}
              </Link>
            )
          }
          const mayCancel = canCancelApproval(approval, currentUserId)
          // The four-eyes rule: someone else decides your own request.
          const own = isOwnApproval(approval, currentUserId)
          const ownReason = t(
            'findings.approvals.ownRequestHint',
            'Another approver must decide your own request.'
          )
          return (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  className="h-8 w-8 p-0"
                  disabled={actionInProgress === approval.id}
                >
                  {actionInProgress === approval.id ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <MoreHorizontal className="h-4 w-4" />
                  )}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {selfApprovalAvailable && approval.requested_by === currentUserId && (
                  <Can permission={Permission.FindingsApprove}>
                    <DropdownMenuItem onClick={() => setSelfApproveTarget(approval)}>
                      <ShieldCheck className="me-2 h-4 w-4 text-warning" />
                      {t('findingApprovals.selfApprove.action', 'Approve myself (sole member)')}
                    </DropdownMenuItem>
                  </Can>
                )}
                <Can permission={Permission.FindingsApprove}>
                  <DropdownMenuItem
                    disabled={own}
                    title={own ? ownReason : undefined}
                    onClick={() => handleApproveClick(approval)}
                  >
                    <Check className="me-2 h-4 w-4 text-emerald-500" />
                    {t('findings.approvals.action.approve', 'Approve')}
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    disabled={own}
                    title={own ? ownReason : undefined}
                    onClick={() => handleRejectClick(approval)}
                  >
                    <X className="me-2 h-4 w-4 text-red-500" />
                    {t('findings.approvals.action.reject', 'Reject')}
                  </DropdownMenuItem>
                  {own && (
                    <p className="max-w-[220px] px-2 py-1.5 text-xs text-muted-foreground">
                      {ownReason}
                    </p>
                  )}
                </Can>
                {mayCancel && (
                  <Can permission={Permission.FindingsWrite}>
                    <DropdownMenuItem onClick={() => handleRemind(approval)}>
                      <BellRing className="me-2 h-4 w-4" />
                      {t('findings.approvals.action.remind', 'Remind approvers')}
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleCancelClick(approval)}>
                      <Ban className="me-2 h-4 w-4" />
                      {t('findings.approvals.action.cancel', 'Cancel request')}
                    </DropdownMenuItem>
                  </Can>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )
        },
      },
    ],
    [
      actionInProgress,
      handleApproveClick,
      handleRejectClick,
      handleCancelClick,
      handleRemind,
      currentUserId,
      selfApprovalAvailable,
      t,
    ]
  )

  // ============================================
  // ERROR STATE (full page, like findings page)
  // ============================================

  if (error && !isLoading) {
    return (
      <Main>
        <div className="flex flex-col items-center justify-center py-20">
          <AlertCircle className="h-12 w-12 text-destructive mb-4" />
          <h2 className="text-lg font-semibold mb-2">
            {t('findings.approvals.loadFailed', 'Failed to load approvals')}
          </h2>
          <p className="text-muted-foreground mb-4">
            {error?.message ||
              t('findings.approvals.unexpectedError', 'An unexpected error occurred')}
          </p>
          <Button onClick={() => mutate()}>
            <RefreshCw className="me-2 h-4 w-4" />
            {t('findings.approvals.retry', 'Retry')}
          </Button>
        </div>
      </Main>
    )
  }

  // ============================================
  // RENDER
  // ============================================

  return (
    <>
      <Main>
        {/* Back link */}
        <div className="mb-2">
          <Link
            href="/findings"
            className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            {t('findings.approvals.backToFindings', 'Back to Findings')}
          </Link>
        </div>

        <PageHeader
          title={t('findings.approvals.title', 'Approval requests')}
          description={
            isInitialLoading
              ? t('findings.approvals.loading', 'Loading approvals…')
              : pendingTotal > 0
                ? t('findings.approvals.summaryPending', '{count} waiting for a decision', {
                    count: pendingTotal,
                  })
                : t('findings.approvals.summaryNone', 'Nothing is waiting for a decision')
          }
        />

        {/* The one tab row: the two kinds of request are different objects
            with their own columns. Each tab counts only what waits for a
            decision, and shows nothing at zero. */}
        <Tabs value={view} onValueChange={changeView} className="mt-6">
          <TabsList aria-label={t('findingApprovals.group.viewLabel', 'Kind of request')}>
            <TabsTrigger value="requests">
              {t('findingApprovals.group.viewRequests', 'Finding requests')}
              <TabsCount value={counts.pending || null} />
            </TabsTrigger>
            <TabsTrigger value="groups">
              {t('findingApprovals.group.viewGroups', 'Group exceptions')}
              <TabsCount value={pendingGroups?.total || null} />
            </TabsTrigger>
          </TabsList>
        </Tabs>

        <div className="mt-4">
          {isInitialLoading ? (
            <TableSkeleton />
          ) : view === 'groups' ? (
            <GroupExceptionsPanel
              status={lensStatus}
              pagination={list.pagination}
              onPaginationChange={list.setPagination}
              currentUserId={currentUserId}
              openId={openBatch}
              onOpenChange={changeOpenBatch}
              onDecided={mutate}
              toolbarStart={statusLens}
              toolbarEnd={refreshButton}
            />
          ) : (
            <DataTable
              columns={columns}
              data={approvals}
              manualPagination
              pageCount={pageCount}
              rowCount={data?.total ?? 0}
              pagination={list.pagination}
              onPaginationChange={list.setPagination}
              getRowId={(row) => row.id}
              showColumnToggle={false}
              showSearch={false}
              toolbarStart={statusLens}
              toolbarEnd={refreshButton}
              emptyMessage={
                lens === 'pending'
                  ? t('findings.approvals.emptyPending', 'No pending requests')
                  : t('findings.approvals.empty', 'No approval requests')
              }
              emptyDescription={
                lens === 'pending'
                  ? t(
                      'findings.approvals.emptyPendingDesc',
                      'A false positive or risk acceptance that needs a second person appears here. Decided requests are under Approved, Rejected and All.'
                    )
                  : lens === 'all'
                    ? t(
                        'findings.approvals.emptyAll',
                        'There are no approval requests to review at this time.'
                      )
                    : t('findings.approvals.emptyStatus', 'No requests with the status {status}.', {
                        status: t(
                          `findings.approvals.status.${lens}`,
                          APPROVAL_STATUS_LABELS[lens]
                        ),
                      })
              }
            />
          )}
        </div>
      </Main>

      {/* Approve Confirmation Dialog */}
      <ConfirmDialog
        open={approveDialogOpen}
        onOpenChange={setApproveDialogOpen}
        title={t('confirm.findingApproval.approveTitle', 'Approve this status change?')}
        desc={
          selectedApproval &&
          (selectedApproval.approvals_required ?? 0) - (selectedApproval.approvals_collected ?? 0) >
            1
            ? t(
                'confirm.findingApproval.approveDescMore',
                'Your approval is recorded. The finding moves to the requested status once {count} more approval(s) are in.',
                {
                  count:
                    (selectedApproval.approvals_required ?? 0) -
                    (selectedApproval.approvals_collected ?? 0) -
                    1,
                }
              )
            : t(
                'confirm.findingApproval.approveDesc',
                'The finding moves to the requested status at once.'
              )
        }
        confirmText={
          isApproving ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.suppression.approving', 'Approving…')}
            </>
          ) : (
            t('confirm.suppression.approve', 'Approve')
          )
        }
        isLoading={isApproving}
        handleConfirm={handleApproveConfirm}
      >
        {selectedApproval && (
          <div className="rounded-lg border bg-muted/50 p-3 my-2">
            <p className="font-medium">
              {t('findings.approvals.changeTo', 'Change to')}{' '}
              <Badge
                variant="outline"
                className={cn(
                  'text-xs ms-1',
                  FINDING_STATUS_CONFIG[
                    selectedApproval.requested_status as keyof typeof FINDING_STATUS_CONFIG
                  ]?.bgColor,
                  FINDING_STATUS_CONFIG[
                    selectedApproval.requested_status as keyof typeof FINDING_STATUS_CONFIG
                  ]?.textColor
                )}
              >
                {getRequestedStatusLabel(t, selectedApproval.requested_status)}
              </Badge>
            </p>
            {selectedApproval.closure_reason && (
              <p className="text-sm mt-1">
                {t('findings.approvalDialog.reasonLabel', 'Reason:')}{' '}
                {closureReasonLabel(t, selectedApproval.closure_reason)}
              </p>
            )}
            <p className="text-sm text-muted-foreground mt-1 line-clamp-2">
              {selectedApproval.justification}
            </p>
            <div className="mt-2">
              <AIProposalBadge approval={selectedApproval} withHint />
            </div>
          </div>
        )}
      </ConfirmDialog>

      {/* Reject Dialog */}
      <Dialog open={rejectDialogOpen} onOpenChange={setRejectDialogOpen}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>{t('findings.approvals.rejectTitle', 'Reject request')}</DialogTitle>
            <DialogDescription>
              {t('findings.approvals.rejectDesc', 'Give a reason for rejecting this request.')}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4">
            {selectedApproval && (
              <div className="rounded-lg border bg-muted/50 p-3">
                <p className="text-sm font-medium">
                  {getRequestedStatusLabel(t, selectedApproval.requested_status)}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                  {selectedApproval.justification}
                </p>
              </div>
            )}
            <div className="grid gap-2">
              <Textarea
                placeholder={t('findings.approvals.rejectPlaceholder', 'Reason for rejection…')}
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                rows={3}
                maxLength={2000}
              />
              <p className="text-xs text-muted-foreground text-end">
                {rejectionReason.length}/2000
              </p>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRejectDialogOpen(false)}
              disabled={isRejecting}
            >
              {t('findings.approvals.cancel', 'Cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={handleRejectConfirm}
              disabled={isRejecting || !rejectionReason.trim()}
            >
              {isRejecting ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  {t('findings.approvals.rejecting', 'Rejecting…')}
                </>
              ) : (
                t('findings.approvals.action.reject', 'Reject')
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Cancel Confirmation Dialog */}
      <ConfirmDialog
        open={cancelDialogOpen}
        onOpenChange={setCancelDialogOpen}
        title={t('confirm.findingApproval.cancelTitle', 'Cancel this approval request?')}
        desc={t(
          'confirm.findingApproval.cancelDesc',
          'The request is withdrawn and the finding keeps its current status. This cannot be undone; ask again if needed.'
        )}
        cancelBtnText={t('confirm.findingApproval.keep', 'Keep request')}
        confirmText={
          isCancelling ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.findingApproval.cancelling', 'Cancelling…')}
            </>
          ) : (
            t('confirm.findingApproval.cancel', 'Cancel request')
          )
        }
        destructive
        isLoading={isCancelling}
        handleConfirm={handleCancelConfirm}
      />

      <FindingSelfApproveDialog
        approval={selfApproveTarget}
        onOpenChange={(open) => !open && setSelfApproveTarget(null)}
        onApproved={() => void mutate()}
      />
    </>
  )
}
