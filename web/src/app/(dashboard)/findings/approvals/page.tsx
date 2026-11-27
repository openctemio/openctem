'use client'

import { useState, useCallback, useMemo } from 'react'
import Link from '@/components/link'
import { type ColumnDef } from '@tanstack/react-table'
import { Ban, BellRing, Loader2, ShieldCheck, Layers } from 'lucide-react'
import { toast } from 'sonner'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared/components/page-header'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsContent, TabsCount } from '@/components/ui/tabs'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { PageStack } from '@/features/shared/components/page-stack'
import { RefreshButton } from '@/components/list-page-parts'
import { type ActionMenuEntry } from '@/components/ui/action-menu'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { toDisplayText } from '@/lib/untrusted-text'
import { formatAbsoluteTime, formatCalendarDate, formatRelativeTime } from '@/lib/format-metric'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { accessStateOf } from '@/lib/api/access-state'
import { Permission, usePermissions } from '@/lib/permissions'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import {
  QueueCard,
  QueueDecideBy,
  QueueDecisionActions,
  QueueEmpty,
  decideByState,
  useQueueAnnouncer,
} from '@/features/shared/components/queue'

import { useDisplayUser } from '@/hooks/use-display-user'
import { refreshPendingApprovalCount } from '@/hooks/use-dynamic-badges'
import {
  useApprovals,
  useCancelApproval,
  remindApprovers,
} from '@/features/findings/api/use-findings-api'
import type { ApiApproval, ApprovalStatus } from '@/features/findings/types'
import { FINDING_STATUS_CONFIG, type FindingStatus } from '@/features/findings/types'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import { ApprovalFindingLink } from '@/features/findings/components/approval-finding-link'
import { useListParams } from '@/hooks/use-list-params'
import {
  approvalRequester,
  approvalTabCounts,
  canCancelApproval,
  isOwnApproval,
} from '@/features/findings/lib/approvals'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { Tag } from '@/components/ui/tag'
import type { DataTableColumnMeta } from '@/features/shared/components/data-table/column-meta'
import { ApprovalStatusLozenge } from '@/features/shared/components/approval-status-lozenge'
import { AIProposalBadge } from '@/features/findings/components/ai-proposal-badge'
import { FindingSelfApproveDialog } from '@/features/findings/components/finding-self-approve-dialog'
import {
  requestedStatusLabel,
  useApprovalDecision,
} from '@/features/findings/components/approval-decision'
import { ApprovalTierCell } from '@/features/findings/components/approval-tier-cell'
import { GroupExceptionsPanel } from '@/features/findings/components/group-exceptions-panel'
import { useApprovalBatches } from '@/features/findings/api/use-approval-batches'
import { useApprovalBulkDecide } from '@/features/findings/components/approval-bulk-decide'

// ============================================
// CONSTANTS
// ============================================

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

/**
 * Column widths in px (the kind's default where none is given) and the frame
 * widths below which a column leaves the table. The request's finding, what
 * is asked and the decision stay at every width; the phone card and both
 * decision dialogs show every field.
 */
const APPROVALS_WIDTH = {
  findingMin: 192,
  // "Chấp nhận rủi ro" whole.
  requested: 144,
  tier: 160,
  requester: 116,
  justificationMin: 156,
  // "Overdue, 15 Nov" / "Quá hạn, 15 thg 11" whole.
  decideBy: 148,
  expires: 120,
  // Approve + Reject (or "Your request" + More) in en and vi, and the cell padding.
  actions: 196,
} as const
/**
 * Each threshold is the sum of the columns still shown when that column
 * joins them, so the table always fits its frame (1024 with the sidebar open
 * leaves a 698 px frame) and the page never scrolls sideways. Columns leave
 * in this order: Created, Acceptance ends, Approval, Requester, Justification
 * (Display > Columns brings any of them back). With the Status column (every
 * lens but Pending) each threshold is 128 px wider, and Decide by, empty on
 * every decided row, leaves last.
 */
const APPROVALS_HIDE_BELOW = {
  pending: { created: 1360, expires: 1232, tier: 1112, requester: 952, justification: 836 },
  withStatus: {
    created: 1488,
    expires: 1360,
    tier: 1240,
    requester: 1080,
    justification: 964,
    decideBy: 808,
  },
} as const

/** The table's selection column (`bulkSelectColumn`), in px. */
const SELECT_COLUMN_WIDTH = 40

// ============================================
// HELPERS
// ============================================

/**
 * The requester's reason on one line, after the AI mark when an AI wrote it.
 * Model or member input: plain text, capped, bidi-isolated.
 */
function JustificationCell({ approval, lines = 1 }: { approval: ApiApproval; lines?: 1 | 2 }) {
  const text = toDisplayText(approval.justification, 500)
  return (
    // In a row the text takes the room the column has and never widens it
    // (zero intrinsic width, filled to the cell).
    <div className={lines === 1 ? 'flex w-0 min-w-full items-center gap-2' : 'grid gap-1'}>
      {/* The AI mark keeps its place; in a narrow cell its label shortens
          before the text gives way (both whole on hover). */}
      <span className={lines === 1 ? 'flex min-w-0 shrink empty:hidden' : 'empty:hidden'}>
        <AIProposalBadge approval={approval} truncate={lines === 1} />
      </span>
      <span
        dir="auto"
        // A table row is one line: a longer reason ends in an ellipsis (the
        // row's cells never wrap, so a line clamp would cut it mid-word with
        // none). A phone card gets two lines. The full text is the title.
        data-cut-tooltip=""
        className={cn(
          'text-sm text-muted-foreground [unicode-bidi:isolate]',
          lines === 1 ? 'min-w-8 flex-1 truncate' : 'line-clamp-2 break-words'
        )}
        title={text}
      >
        {text}
      </span>
    </div>
  )
}

/** A relative time in the app's locale, with the absolute time on hover. */
function RelativeTime({ value, locale }: { value: string; locale: string }) {
  return (
    <time
      dateTime={value}
      title={formatAbsoluteTime(value, locale)}
      className="text-muted-foreground text-sm whitespace-nowrap"
    >
      {formatRelativeTime(value, locale)}
    </time>
  )
}

function RequesterCell({
  approval,
  currentUserId,
  inline = false,
}: {
  approval: ApiApproval
  currentUserId: string | undefined
  /** In a facts line: the line's own size. */
  inline?: boolean
}) {
  const { t } = useTranslation()
  const who = approvalRequester(approval, currentUserId)
  switch (who.kind) {
    case 'actor':
      return (
        <span className={cn(!inline && 'text-sm', 'text-muted-foreground')}>
          {t(
            `findings.approvals.actor.${who.actor}`,
            APPROVAL_ACTOR_LABELS[who.actor] ?? who.actor
          )}
        </span>
      )
    case 'you':
      return (
        <span className={cn(!inline && 'text-sm', 'font-medium')}>
          {t('findings.approvals.requesterYou', 'You')}
        </span>
      )
    case 'member':
      return <span className={cn(!inline && 'text-sm')}>{who.name}</span>
    default:
      return (
        <span className={cn(!inline && 'text-sm', 'text-muted-foreground')}>
          {t('findings.approvals.requesterFormer', 'Former member')}
        </span>
      )
  }
}

// ============================================
// MAIN PAGE COMPONENT
// ============================================

export default function ApprovalsPage() {
  const { t, locale } = useTranslation()
  const { can } = usePermissions()
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
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false)
  const [remindTarget, setRemindTarget] = useState<ApiApproval | null>(null)
  const [selectedApproval, setSelectedApproval] = useState<ApiApproval | null>(null)
  const [actionInProgress, setActionInProgress] = useState<string | null>(null)
  // The sole member's own approval (shown only when the API offers it).
  const [selfApproveTarget, setSelfApproveTarget] = useState<ApiApproval | null>(null)

  // One server page of the lens; the counts cover every status.
  const {
    data,
    isLoading,
    isValidating,
    error,
    mutate: mutateList,
  } = useApprovals(list.page, list.perPage, lensStatus)
  // The page of group exceptions the other view lists (the same read as its
  // panel's, so one request), for that view's count in the title row.
  const { data: groupsPage } = useApprovalBatches(
    list.page,
    list.perPage,
    lensStatus,
    view === 'groups'
  )
  // Pending group exceptions, for the view switch's count.
  const { data: pendingGroups, mutate: mutatePendingGroups } = useApprovalBatches(1, 1, 'pending')
  // A decision changes the lists and the sidebar's Approvals badge.
  const mutate = useCallback(
    () => Promise.all([mutateList(), mutatePendingGroups(), refreshPendingApprovalCount()]),
    [mutateList, mutatePendingGroups]
  )

  // Every outcome is also said to assistive technology (one status region).
  const announcer = useQueueAnnouncer()
  const { announce } = announcer
  // Approve and reject: the shared decision dialogs (also on My Work).
  const decision = useApprovalDecision({ onDecided: mutate, announce })
  // Approve or reject the selected requests at once (pending and every
  // status: a decided one is reported as already decided).
  const requestName = useCallback(
    (a: ApiApproval) =>
      toDisplayText(a.finding_title || t('findings.approvalLink.untitled', 'Untitled finding'), 80),
    [t]
  )
  const bulkDecide = useApprovalBulkDecide<ApiApproval>({
    kind: 'approval',
    idOf: (a) => a.id,
    nameOf: requestName,
    canDecide: can(Permission.FindingsApprove) && (lens === 'pending' || lens === 'all'),
    onDecided: mutate,
    announce,
  })
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

  // ============================================
  // ACTION HANDLERS
  // ============================================

  const { openApprove: handleApproveClick, openReject: handleRejectClick } = decision

  const handleCancelClick = useCallback((approval: ApiApproval) => {
    setSelectedApproval(approval)
    setCancelDialogOpen(true)
  }, [])

  const handleCancelConfirm = async () => {
    if (!selectedApproval || actionInProgress) return
    setActionInProgress(selectedApproval.id)
    try {
      await triggerCancel()
      announce(t('findings.approvals.toast.canceled', 'Approval request canceled'))
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
        const reminded = t(
          'findings.approvals.toast.reminded',
          'Reminded {count, plural, one {# approver} other {# approvers}}',
          {
            count: res?.reminded ?? 0,
          }
        )
        announce(reminded)
        toast.success(reminded)
      } catch (err) {
        if (err instanceof ApiClientError && err.statusCode === 409) {
          const tooSoon = t(
            'findings.approvals.toast.remindTooSoon',
            'The approvers were already reminded in the last hour.'
          )
          announce(tooSoon)
          toast.error(tooSoon)
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
    [actionInProgress, announce, t]
  )

  // The spinning button is the feedback; the list itself shows the result.
  const handleRefresh = async () => {
    await mutate()
  }

  // The list toolbar: the status lens is its one filter token (a filter of
  // the rows, not a second row of tabs); its counts are the finding requests'
  // and are shown only on that view.
  const statusLens = (
    <FilterSelect<Exclude<ApprovalLens, 'all'>>
      label={t('findings.approvals.lens.status', 'Status')}
      value={lens === 'all' ? '' : lens}
      onChange={(next) => changeLens(next === '' ? 'all' : next)}
      allCount={view === 'requests' ? counts.all : undefined}
      options={APPROVAL_LENSES.filter((v) => v !== 'all').map((value) => ({
        value,
        label: t(`findings.approvals.status.${value}`, APPROVAL_STATUS_LABELS[value]),
        count: view === 'requests' ? counts[value] : undefined,
      }))}
    />
  )
  const refreshButton = (
    <RefreshButton
      onClick={() => void handleRefresh()}
      loading={isValidating}
      label={t('findings.approvals.refresh', 'Refresh')}
    />
  )

  // The row's decision controls; the table cell and the phone card share them.
  const actionsCell = useCallback(
    (approval: ApiApproval, layout: 'row' | 'compact' = 'row') => {
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
      // Per row from the API; the list-wide flag for an older server.
      const mineSelf =
        approval.self_approval_available === true ||
        (selfApprovalAvailable && approval.requested_by === currentUserId)
      const findingTitle = toDisplayText(
        approval.finding_title || t('findings.approvalLink.untitled', 'Untitled finding'),
        80
      )
      const menuItems: ActionMenuEntry[] = [
        ...(mineSelf && can(Permission.FindingsApprove)
          ? [
              {
                id: 'self-approve',
                label: t('findingApprovals.selfApprove.action', 'Approve myself (sole member)'),
                icon: ShieldCheck,
                onSelect: () => setSelfApproveTarget(approval),
              },
            ]
          : []),
        ...(mayCancel && can(Permission.FindingsWrite)
          ? [
              {
                id: 'remind',
                label: t('findings.approvals.action.remind', 'Remind approvers'),
                icon: BellRing,
                onSelect: () => setRemindTarget(approval),
              },
              {
                id: 'cancel',
                label: t('findings.approvals.action.cancel', 'Cancel request'),
                icon: Ban,
                destructive: true,
                onSelect: () => handleCancelClick(approval),
              },
            ]
          : []),
      ]
      return (
        <QueueDecisionActions
          name={findingTitle}
          itemId={approval.id}
          layout={layout}
          canDecide={can(Permission.FindingsApprove)}
          own={own}
          ownLabel={t('findings.approvals.ownRequestShort', 'Your request')}
          ownReason={t(
            'findings.approvals.ownRequestHint',
            'Another approver must decide your own request.'
          )}
          busy={actionInProgress === approval.id || decision.busyId === approval.id}
          onApprove={() => handleApproveClick(approval)}
          onReject={() => handleRejectClick(approval)}
          approveLabel={t('findings.approvals.action.approve', 'Approve')}
          rejectLabel={t('findings.approvals.action.reject', 'Reject')}
          stepUpHint={t(
            'myWork.review.stepUpHint',
            'You confirm your sign-in before the approval is saved.'
          )}
          menu={menuItems}
        />
      )
    },
    [
      actionInProgress,
      decision.busyId,
      handleApproveClick,
      handleRejectClick,
      handleCancelClick,
      currentUserId,
      selfApprovalAvailable,
      can,
      t,
    ]
  )

  /** The request's state, and how it was decided when that is unusual. */
  const statusCell = useCallback(
    (approval: ApiApproval) => (
      <div className="flex items-center gap-1 whitespace-nowrap">
        <ApprovalStatusLozenge
          status={approval.status}
          label={t(
            `findings.approvals.status.${approval.status}`,
            APPROVAL_STATUS_LABELS[approval.status] ?? approval.status
          )}
        />
        {approval.self_approved && (
          <Tag
            label={t('findingApprovals.selfApprove.badge', 'Self-approved')}
            title={t(
              'findingApprovals.selfApprove.badgeTitle',
              "Approved by its own requester, the organization's only member"
            )}
          />
        )}
        {approval.single_person && (
          <Tag
            label={t('findingApprovals.single.badge', 'Single person')}
            title={t(
              'findingApprovals.single.badgeTitle',
              "Decided by one person: the organization's false-positive level did not require a second"
            )}
          />
        )}
      </div>
    ),
    [t]
  )

  const requestedCell = useCallback(
    (approval: ApiApproval) => {
      const status = approval.requested_status
      const config = FINDING_STATUS_CONFIG[status as keyof typeof FINDING_STATUS_CONFIG]
      return config ? (
        <FindingStatusBadge status={status as FindingStatus} />
      ) : (
        <Badge variant="outline">{requestedStatusLabel(t, status)}</Badge>
      )
    },
    [t]
  )

  // ============================================
  // TABLE COLUMNS
  // ============================================

  // Under the Pending lens every row is pending: the Status column would say
  // one word down the whole table, so it shows on the other lenses only.
  const showStatusColumn = lens !== 'pending'
  const selectable = !!bulkDecide.bulk

  const columns: ColumnDef<ApiApproval>[] = useMemo(() => {
    const label = {
      finding: t('findings.approvals.col.finding', 'Finding'),
      status: t('findings.approvals.col.status', 'Status'),
      requested: t('findings.approvals.col.requestedStatus', 'Requested status'),
      tier: t('findings.approvals.col.tier', 'Approval'),
      requester: t('findings.approvals.col.requester', 'Requester'),
      justification: t('findings.approvals.col.justification', 'Justification'),
      created: t('findings.approvals.col.created', 'Created'),
      decideBy: t('findings.approvals.col.decideBy', 'Decide by'),
      expires: t('findings.approvals.col.expires', 'Acceptance ends'),
      actions: t('findings.approvals.col.actions', 'Decision'),
    }
    const meta = (m: DataTableColumnMeta) => m
    // The selection column (an approver's) takes its width from every threshold.
    const base: Record<string, number> = showStatusColumn
      ? APPROVALS_HIDE_BELOW.withStatus
      : APPROVALS_HIDE_BELOW.pending
    const extra = selectable ? SELECT_COLUMN_WIDTH : 0
    const hideBelow = Object.fromEntries(
      Object.entries(base).map(([k, v]) => [k, v + extra])
    ) as Record<keyof typeof APPROVALS_HIDE_BELOW.withStatus, number> &
      Partial<Record<'decideBy', number>>
    const all: ColumnDef<ApiApproval>[] = [
      {
        // The row's name: what the request is about. Frozen at the start.
        accessorKey: 'finding_id',
        meta: meta({
          kind: 'name',
          pin: 'start',
          minWidth: APPROVALS_WIDTH.findingMin,
          label: label.finding,
        }),
        header: label.finding,
        enableHiding: false,
        enableSorting: false,
        cell: ({ row }) => (
          // The title takes the room the column has and never widens it.
          <div className="w-0 min-w-full">
            <ApprovalFindingLink
              findingId={row.original.finding_id}
              findingTitle={row.original.finding_title}
              lines={1}
            />
          </div>
        ),
      },
      {
        accessorKey: 'status',
        meta: meta({ kind: 'status', minWidth: 128, maxWidth: 264, label: label.status }),
        header: label.status,
        enableSorting: false,
        cell: ({ row }) => statusCell(row.original),
      },
      {
        accessorKey: 'requested_status',
        meta: meta({ kind: 'status', width: APPROVALS_WIDTH.requested, label: label.requested }),
        header: label.requested,
        enableSorting: false,
        cell: ({ row }) => requestedCell(row.original),
      },
      {
        id: 'tier',
        meta: meta({
          kind: 'text',
          width: APPROVALS_WIDTH.tier,
          hideBelow: hideBelow.tier,
          label: label.tier,
        }),
        header: label.tier,
        enableSorting: false,
        cell: ({ row }) => <ApprovalTierCell approval={row.original} inline />,
      },
      {
        id: 'requester',
        meta: meta({
          kind: 'owner',
          width: APPROVALS_WIDTH.requester,
          hideBelow: hideBelow.requester,
          label: label.requester,
        }),
        header: label.requester,
        enableSorting: false,
        cell: ({ row }) => (
          <div className="truncate">
            <RequesterCell approval={row.original} currentUserId={currentUserId} />
          </div>
        ),
      },
      {
        accessorKey: 'justification',
        meta: meta({
          kind: 'text',
          minWidth: APPROVALS_WIDTH.justificationMin,
          hideBelow: hideBelow.justification,
          label: label.justification,
        }),
        header: label.justification,
        enableSorting: false,
        cell: ({ row }) => <JustificationCell approval={row.original} />,
      },
      {
        accessorKey: 'decide_by',
        meta: meta({
          kind: 'due',
          width: APPROVALS_WIDTH.decideBy,
          hideBelow: hideBelow.decideBy,
          label: label.decideBy,
        }),
        header: label.decideBy,
        enableSorting: false,
        cell: ({ row }) => (
          <QueueDecideBy
            value={row.original.status === 'pending' ? row.original.decide_by : undefined}
          />
        ),
      },
      {
        accessorKey: 'expires_at',
        meta: meta({
          kind: 'date',
          width: APPROVALS_WIDTH.expires,
          hideBelow: hideBelow.expires,
          label: label.expires,
        }),
        header: label.expires,
        enableSorting: false,
        cell: ({ row }) =>
          row.original.expires_at ? (
            <time
              dateTime={row.original.expires_at}
              title={formatAbsoluteTime(row.original.expires_at, locale)}
              className="text-sm whitespace-nowrap text-muted-foreground tabular-nums"
            >
              {formatCalendarDate(row.original.expires_at, locale)}
            </time>
          ) : (
            <span className="text-sm text-muted-foreground">-</span>
          ),
      },
      {
        accessorKey: 'created_at',
        meta: meta({
          kind: 'datetime-recent',
          hideBelow: hideBelow.created,
          label: label.created,
        }),
        header: label.created,
        enableSorting: false,
        cell: ({ row }) => <RelativeTime value={row.original.created_at} locale={locale} />,
      },
      {
        id: 'actions',
        meta: meta({ kind: 'actions', width: APPROVALS_WIDTH.actions, label: label.actions }),
        header: () => <span className="sr-only">{label.actions}</span>,
        enableHiding: false,
        enableSorting: false,
        cell: ({ row }) => actionsCell(row.original),
      },
    ]
    return showStatusColumn
      ? all
      : all.filter((c) => !('accessorKey' in c && c.accessorKey === 'status'))
  }, [
    actionsCell,
    currentUserId,
    locale,
    requestedCell,
    selectable,
    showStatusColumn,
    statusCell,
    t,
  ])

  // ============================================
  // STATES
  // ============================================

  // A refused read is "no access", not a failure with Retry.
  const noAccess = !data && accessStateOf(error) === 'no_access'
  const showAll = (
    <Button variant="outline" size="sm" onClick={() => changeLens('all')}>
      {t('findings.approvals.showAll', 'Show all requests')}
    </Button>
  )
  // Three ways the queue is empty: it never held a request, nothing waits, or
  // the status lens left no row.
  const emptyState =
    counts.all === 0 ? (
      <QueueEmpty
        kind="first-run"
        title={t('findings.approvals.empty', 'No approval requests')}
        hint={t(
          'findings.approvals.emptyFirstRun',
          'A false positive or risk acceptance that needs a second person appears here.'
        )}
      />
    ) : lens === 'pending' ? (
      <QueueEmpty
        kind="nothing-waiting"
        title={t('findings.approvals.summaryNone', 'Nothing is waiting for a decision')}
        hint={t(
          'findings.approvals.emptyPendingDesc',
          'A false positive or risk acceptance that needs a second person appears here. To see decided requests, change the Status filter.'
        )}
        action={showAll}
      />
    ) : (
      <QueueEmpty
        kind="no-match"
        title={t('findings.approvals.emptyStatus', 'No requests with the status {status}.', {
          status: t(
            `findings.approvals.status.${lens}`,
            lens === 'all' ? 'All' : APPROVAL_STATUS_LABELS[lens]
          ),
        })}
        action={showAll}
      />
    )

  const groupsTotal = groupsPage?.total ?? 0
  const viewTitle =
    view === 'groups'
      ? t(`findingApprovals.group.viewName.${lens}`, 'Group exceptions')
      : t(`findings.approvals.viewName.${lens}`, 'Requests')
  const total = view === 'groups' ? groupsTotal : (data?.total ?? 0)
  const titleRow = (
    // Count once: under Pending the selected tab already shows the number of
    // the view, so the row names the view for assistive technology only and
    // shows no count (the row then takes no room); another lens holds a
    // number no tab shows, so it stays and the row then shows the view's
    // name beside it (a count never stands alone on a line). Refresh sits at
    // the end of the toolbar, so no line ever holds it alone.
    <ListTitleRow
      title={viewTitle}
      titleHidden
      count={
        lens === 'pending' ? undefined : (
          <ListCount
            total={total}
            loading={view === 'groups' ? !groupsPage : isInitialLoading || noAccess}
            label={
              view === 'groups'
                ? t(
                    'findingApprovals.group.total',
                    '{count, plural, one {# group exception} other {# group exceptions}}',
                    { count: total }
                  )
                : t(
                    'findings.approvals.total',
                    '{count, plural, one {# request} other {# requests}}',
                    { count: total }
                  )
            }
          />
        )
      }
    />
  )

  // ============================================
  // RENDER
  // ============================================

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader title={t('findings.approvals.title', 'Approval requests')} />

          {/* The one tab row: the two kinds of request are different objects
            with their own columns. Each tab counts only what waits for a
            decision, and shows nothing at zero. */}
          <Tabs value={view} onValueChange={changeView}>
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

            {/* The tab panel: its id is what the tab triggers point at. */}
            <TabsContent value={view}>
              <PageStack>
                {titleRow}
                {view === 'groups' ? (
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
                ) : noAccess ? (
                  <NoAccessState
                    title={t('findings.approvals.errorTitle', 'approval requests')}
                    permission={Permission.FindingsRead}
                  />
                ) : (
                  <DataTable
                    columns={columns}
                    data={approvals}
                    caption={viewTitle}
                    // The first read: skeleton rows under a toolbar that stays.
                    isLoading={isInitialLoading}
                    isRefreshing={isValidating && !!data}
                    refreshingLabel={t('findings.approvals.refreshing', 'Refreshing requests')}
                    // A failed read keeps the page, its tabs and the other
                    // view; the table says what failed and offers Retry.
                    error={error}
                    onRetry={() => void mutate()}
                    errorTitle={t('findings.approvals.errorTitle', 'approval requests')}
                    manualPagination
                    pageCount={pageCount}
                    rowCount={data?.total ?? 0}
                    pagination={list.pagination}
                    onPaginationChange={list.setPagination}
                    paginationNoun={t('findings.approvals.paginationNoun', 'requests')}
                    getRowId={(row) => row.id}
                    pinActions
                    showSearch={false}
                    toolbarStart={statusLens}
                    toolbarEnd={refreshButton}
                    emptyState={emptyState}
                    bulk={bulkDecide.bulk}
                    resetSelectionKey={bulkDecide.resetKey}
                    showSelectionCount={false}
                    mobileRow={(approval, selection) => (
                      <QueueCard
                        data-testid="approval-phone-card"
                        selection={selection}
                        selectLabel={t('findings.bulkDecide.selectRow', 'Select {name}', {
                          name: requestName(approval),
                        })}
                        href={`/findings/${encodeURIComponent(approval.finding_id)}`}
                        title={
                          <ApprovalFindingLink
                            findingId={approval.finding_id}
                            findingTitle={approval.finding_title}
                          />
                        }
                        // The state; under Pending (every card is pending) what
                        // is asked for takes its place.
                        state={showStatusColumn ? statusCell(approval) : requestedCell(approval)}
                        reason={
                          <div className="grid gap-1">
                            <JustificationCell approval={approval} lines={2} />
                            {approval.expires_at && (
                              <span className="text-meta text-muted-foreground">
                                {t('findings.approvals.col.expires', 'Acceptance ends')}{' '}
                                {formatCalendarDate(approval.expires_at, locale)}
                              </span>
                            )}
                          </div>
                        }
                        // What is asked, by when, then who asked (cut first).
                        meta={[
                          showStatusColumn ? (
                            <span key="asked">{requestedCell(approval)}</span>
                          ) : null,
                          approval.decide_by && approval.status === 'pending' ? (
                            <span key="due">
                              {/* "Overdue, 12 Nov" says it alone. */}
                              {decideByState(approval.decide_by) !== 'overdue' && (
                                <>{t('findings.approvals.col.decideBy', 'Decide by')} </>
                              )}
                              <QueueDecideBy value={approval.decide_by} className="text-xs" />
                            </span>
                          ) : null,

                          <RequesterCell
                            key="by"
                            inline
                            approval={approval}
                            currentUserId={currentUserId}
                          />,
                        ]}
                        actions={actionsCell(approval, 'compact')}
                      />
                    )}
                  />
                )}
              </PageStack>
            </TabsContent>
          </Tabs>
        </PageStack>
      </Main>

      {announcer.region}
      {decision.dialogs}
      {bulkDecide.dialogs}

      <ConfirmDialog
        open={remindTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRemindTarget(null)
        }}
        title={t('confirm.findingApproval.remindTitle', 'Remind the approvers?')}
        desc={t(
          'confirm.findingApproval.remindDesc',
          'Every approver who has not decided yet gets a notification now. Approvers can be reminded once an hour.'
        )}
        confirmText={t('confirm.findingApproval.remindButton', 'Send reminder')}
        handleConfirm={async () => {
          const target = remindTarget
          setRemindTarget(null)
          if (target) await handleRemind(target)
        }}
      />

      {/* Cancel Confirmation Dialog */}
      <ConfirmDialog
        open={cancelDialogOpen}
        onOpenChange={setCancelDialogOpen}
        title={t('confirm.findingApproval.cancelTitle', 'Cancel this approval request?')}
        desc={t(
          'confirm.findingApproval.cancelDesc',
          'The request is withdrawn and the finding keeps its current status. You can send a new request afterwards.'
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
