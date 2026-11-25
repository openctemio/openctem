'use client'

/**
 * Exceptions (/exceptions): the suppression rules that mark findings as false
 * positives, accepted risks or won't fix, with their approval step. The API
 * returns every rule of the organization in one read (GET /suppressions), so
 * the strip's counts, the filters and the search work on that one list; the
 * approve, reject, edit and delete actions stay gated by their permissions and
 * re-checked by the API.
 */

import { useState, useCallback, useMemo } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { Plus, MoreHorizontal, Check, X, Pencil, Trash2, Loader2, ShieldOff } from 'lucide-react'
import { toast } from 'sonner'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared/components/page-header'
import { CellText, DataTable, FilterSelect, PageStack, ToolbarAction } from '@/features/shared'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { EmptyState } from '@/features/shared/components/empty-state'
import { MetaLine } from '@/features/shared/components/text-layout'
import {
  ContextFilterChips,
  type ContextFilterChip,
} from '@/features/shared/components/context-filter-chips'
import { RefreshButton } from '@/components/list-page-parts'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
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
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useMyUserId } from '@/hooks/use-my-user-id'
import { confirmName } from '@/lib/confirm-name'
import { useUrlFilter } from '@/hooks/use-url-param'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { useOwnerNames } from '@/features/remediation-hub/api/use-owner-names'

import {
  useSuppressions,
  useApproveSuppression,
  useMarkSuppressionReviewed,
  useRejectSuppression,
  useDeleteSuppression,
  SuppressionApprovePreview,
  SuppressionFormDialog,
  SuppressionDetailSheet,
  SuppressionStatusBadge,
  SuppressionTypeBadge,
  suppressionScopeSummary,
  suppressionTypeLabel,
  suppressionStatusLabel,
  endsWithin,
  type SuppressionRule,
  type SuppressionStatus,
  type SuppressionType,
} from '@/features/exceptions'
import { useTranslation } from '@/context/i18n-provider'
import { formatRelative } from '@/lib/format-date'
import { SelfApproveDialog } from '@/features/shared/components/self-approve-dialog'
import { formatNumber } from '@/lib/app-locale'

function relative(iso: string | null | undefined, locale: string): string {
  return formatRelative(iso, '—', locale)
}

const STATUSES: SuppressionStatus[] = ['pending', 'approved', 'rejected', 'expired']
const TYPES: SuppressionType[] = ['false_positive', 'accepted_risk', 'wont_fix']
/** The "ends within" windows the strip links to (days). */
const ENDS_WINDOWS = ['7', '30'] as const
type EndsWindow = (typeof ENDS_WINDOWS)[number]

/**
 * Table frame widths (px) under which a column folds away; the name and the
 * state stay. Each is the sum of the columns still shown with it (name floor
 * 192, state 128, row menu 48, type 152, expires 140, approvers 160, created
 * 140, requested by 160) plus 40 of slack, so the row menu is never cut.
 */
const EXCEPTION_HIDE_BELOW = {
  type: 560,
  expires: 700,
  approvers: 860,
  created: 1000,
  requestedBy: 1160,
} as const

const DAY = 24 * 60 * 60 * 1000

export default function ExceptionsPage() {
  const { t, locale } = useTranslation()
  const { can } = usePermissions()
  const owners = useOwnerNames()
  // The filters live in the URL so a filtered view survives reload and can be
  // shared (e.g. a link straight to the pending-approval queue).
  const [statusParam, setStatusParam] = useUrlFilter('status', '')
  const [typeParam, setTypeParam] = useUrlFilter('type', '')
  const [endsParam, setEndsParam] = useUrlFilter('ends', '')
  const status = (STATUSES as string[]).includes(statusParam)
    ? (statusParam as SuppressionStatus)
    : ''
  const type = (TYPES as string[]).includes(typeParam) ? (typeParam as SuppressionType) : ''
  const ends = (ENDS_WINDOWS as readonly string[]).includes(endsParam)
    ? (endsParam as EndsWindow)
    : ''
  const [search, setSearch] = useState('')

  const { data, isLoading, error, mutate, isValidating } = useSuppressions()

  // Selection + dialog state
  const [selectedRule, setSelectedRule] = useState<SuppressionRule | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const [formOpen, setFormOpen] = useState(false)
  const [editRule, setEditRule] = useState<SuppressionRule | null>(null)
  const [approveOpen, setApproveOpen] = useState(false)
  const [selfApproveOpen, setSelfApproveOpen] = useState(false)
  const [selfReviewOpen, setSelfReviewOpen] = useState(false)
  const userId = useMyUserId()
  const [rejectOpen, setRejectOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [rejectionReason, setRejectionReason] = useState('')

  // Mutation hooks bound to the currently-selected rule
  const { trigger: triggerApprove, isMutating: isApproving } = useApproveSuppression(
    selectedRule?.id ?? ''
  )
  const { trigger: triggerReviewed } = useMarkSuppressionReviewed(selectedRule?.id ?? '')
  const { trigger: triggerReject, isMutating: isRejecting } = useRejectSuppression(
    selectedRule?.id ?? ''
  )
  const { trigger: triggerDelete, isMutating: isDeleting } = useDeleteSuppression(
    selectedRule?.id ?? ''
  )

  const allRules = useMemo(() => data?.data ?? [], [data?.data])

  // The moment the "ending in" windows are measured from: when the page opened.
  const [now] = useState(() => Date.now())
  const counts = useMemo(() => {
    const result = {
      all: 0,
      pending: 0,
      approved: 0,
      rejected: 0,
      expired: 0,
      ends7: 0,
      ends30: 0,
      oldestPendingDays: 0,
    }
    for (const r of allRules) {
      result.all++
      if (r.status in result) result[r.status as SuppressionStatus]++
      if (endsWithin(r, 7, now)) result.ends7++
      if (endsWithin(r, 30, now)) result.ends30++
      if (r.status === 'pending') {
        const age = Math.floor((now - Date.parse(r.requested_at)) / DAY)
        if (age > result.oldestPendingDays) result.oldestPendingDays = age
      }
    }
    return result
  }, [allRules, now])

  const filteredRules = useMemo(() => {
    const q = search.trim().toLowerCase()
    return allRules.filter(
      (r) =>
        (!status || r.status === status) &&
        (!type || r.suppression_type === type) &&
        (!ends || endsWithin(r, Number(ends), now)) &&
        (!q || r.name.toLowerCase().includes(q))
    )
  }, [allRules, status, type, ends, search, now])

  const isInitialLoading = isLoading && !data

  // ── Action openers ────────────────────────────────────────────────
  const openCreate = useCallback(() => {
    setEditRule(null)
    setFormOpen(true)
  }, [])

  const openEdit = useCallback((rule: SuppressionRule) => {
    setDetailOpen(false)
    setEditRule(rule)
    setFormOpen(true)
  }, [])

  // Your own rule: only an owner with no other approver may approve it, with
  // a reason and a fresh authenticator code (the API decides and audits).
  const openApprove = useCallback(
    (rule: SuppressionRule) => {
      setSelectedRule(rule)
      if (userId && rule.requested_by === userId) {
        setSelfApproveOpen(true)
      } else {
        setApproveOpen(true)
      }
    },
    [userId]
  )

  const confirmSelfApprove = async (reason: string, code: string) => {
    if (!selectedRule) return
    await triggerApprove({
      reviewed_updated_at: selectedRule.updated_at,
      self_approval_reason: reason,
      totp_code: code,
    })
    toast.success(t('confirm.suppression.approved', 'Rule approved.'))
    setDetailOpen(false)
    await mutate()
  }

  const openReject = useCallback((rule: SuppressionRule) => {
    setSelectedRule(rule)
    setRejectionReason('')
    setRejectOpen(true)
  }, [])

  const openDelete = useCallback((rule: SuppressionRule) => {
    setSelectedRule(rule)
    setDeleteOpen(true)
  }, [])

  const openDetail = useCallback((rule: SuppressionRule) => {
    setSelectedRule(rule)
    setDetailOpen(true)
  }, [])

  // ── Action confirmers ─────────────────────────────────────────────
  const confirmApprove = async () => {
    if (!selectedRule) return
    try {
      const approved = await triggerApprove({ reviewed_updated_at: selectedRule.updated_at })
      const closed = approved?.applied_findings ?? 0
      toast.success(
        closed > 0
          ? t(
              'confirm.suppression.approvedClosed',
              'Rule approved; {count} open findings closed.',
              {
                count: formatNumber(closed),
              }
            )
          : t('confirm.suppression.approved', 'Rule approved.')
      )
      setDetailOpen(false)
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('confirm.suppression.approveFailed', 'Failed to approve the rule'))
      )
    } finally {
      setApproveOpen(false)
    }
  }

  const markReviewed = async () => {
    if (!selectedRule) return
    // Reviewing one's own rule takes the sole-approver path (reason + code).
    if (userId && selectedRule.requested_by === userId) {
      setSelfReviewOpen(true)
      return
    }
    try {
      await triggerReviewed()
      toast.success(t('exceptions.page.reviewed', 'Marked as reviewed'))
      setDetailOpen(false)
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('exceptions.page.reviewFailed', 'Could not mark the rule as reviewed')
        )
      )
    }
  }

  const confirmSelfReview = async (reason: string, code: string) => {
    if (!selectedRule) return
    await triggerReviewed({ self_approval_reason: reason, totp_code: code })
    toast.success(t('exceptions.page.reviewed', 'Marked as reviewed'))
    setDetailOpen(false)
    await mutate()
  }

  const confirmReject = async () => {
    if (!selectedRule || !rejectionReason.trim()) return
    try {
      await triggerReject({ reason: rejectionReason.trim() })
      toast.success(t('exceptions.page.rejected', 'Suppression rule rejected'))
      setDetailOpen(false)
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err, t('exceptions.page.rejectFailed', 'Failed to reject rule')))
    } finally {
      setRejectOpen(false)
    }
  }

  const confirmDelete = async () => {
    if (!selectedRule) return
    try {
      await triggerDelete()
      toast.success(t('exceptions.page.deleted', 'Suppression rule deleted'))
      setDetailOpen(false)
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err, t('exceptions.page.deleteFailed', 'Failed to delete rule')))
    } finally {
      setDeleteOpen(false)
    }
  }

  const handleRefresh = async () => {
    await mutate()
    toast.success(t('exceptions.page.refreshed', 'Suppressions refreshed'))
  }

  const nameOf = useCallback(
    (id: string | null | undefined) =>
      id ? (owners.user(id) ?? t('exceptions.page.unknownPerson', 'Unknown person')) : '',
    [owners, t]
  )
  const requesterOf = useCallback(
    (rule: SuppressionRule) => rule.requested_by_actor || nameOf(rule.requested_by),
    [nameOf]
  )
  const approversOf = useCallback(
    (rule: SuppressionRule) => {
      if (rule.status === 'pending') return t('exceptions.page.waiting', 'Waiting for approval')
      if (rule.status === 'rejected' && rule.rejected_by)
        return t('exceptions.page.rejectedBy', 'Rejected by {name}', {
          name: nameOf(rule.rejected_by),
        })
      return rule.approved_by ? nameOf(rule.approved_by) : '—'
    },
    [nameOf, t]
  )

  // ── Columns ───────────────────────────────────────────────────────
  const columns: ColumnDef<SuppressionRule>[] = useMemo(
    () => [
      {
        accessorKey: 'name',
        header: t('exceptions.page.colName', 'Name'),
        // A floor: the name gives way to the other columns, so a long title is cut by its
        // ellipsis and the table never scrolls sideways at 1440.
        meta: { kind: 'name', minWidth: 192, label: t('exceptions.page.colName', 'Name') },
        cell: ({ row }) => (
          <div className="min-w-0">
            <p className="flex min-w-0 items-center gap-2">
              <span className="truncate font-medium" title={row.original.name}>
                {row.original.name}
              </span>
              {row.original.review_flagged_at && (
                <Badge variant="outline" className="shrink-0">
                  {t('exceptions.page.reviewBadge', 'Review')}
                </Badge>
              )}
            </p>
            <p className="text-muted-foreground truncate font-mono text-xs">
              {suppressionScopeSummary(row.original, t)}
            </p>
          </div>
        ),
      },
      {
        accessorKey: 'suppression_type',
        header: t('exceptions.page.colType', 'Type'),
        meta: {
          kind: 'text',
          label: t('exceptions.page.colType', 'Type'),
          width: 152,
          hideBelow: EXCEPTION_HIDE_BELOW.type,
        },
        cell: ({ row }) => <SuppressionTypeBadge type={row.original.suppression_type} />,
      },
      {
        accessorKey: 'status',
        header: t('exceptions.page.colStatus', 'State'),
        meta: { kind: 'status', label: t('exceptions.page.colStatus', 'State') },
        cell: ({ row }) => <SuppressionStatusBadge status={row.original.status} />,
      },
      {
        accessorKey: 'expires_at',
        header: t('exceptions.page.colExpires', 'Expires'),
        meta: {
          kind: 'due',
          label: t('exceptions.page.colExpires', 'Expires'),
          hideBelow: EXCEPTION_HIDE_BELOW.expires,
        },
        cell: ({ row }) => (
          <CellText>
            {row.original.expires_at
              ? relative(row.original.expires_at, locale)
              : t('exceptions.page.never', 'Never')}
          </CellText>
        ),
      },
      {
        accessorKey: 'created_at',
        header: t('exceptions.page.colCreated', 'Created'),
        meta: {
          kind: 'due',
          label: t('exceptions.page.colCreated', 'Created'),
          hideBelow: EXCEPTION_HIDE_BELOW.created,
        },
        cell: ({ row }) => <CellText>{relative(row.original.created_at, locale)}</CellText>,
      },
      {
        id: 'approvers',
        header: t('exceptions.page.colApprovers', 'Approved by'),
        meta: {
          kind: 'owner',
          label: t('exceptions.page.colApprovers', 'Approved by'),
          hideBelow: EXCEPTION_HIDE_BELOW.approvers,
        },
        enableSorting: false,
        cell: ({ row }) => <CellText>{approversOf(row.original)}</CellText>,
      },
      {
        id: 'requested_by',
        header: t('exceptions.page.colRequestedBy', 'Requested by'),
        meta: {
          kind: 'owner',
          label: t('exceptions.page.colRequestedBy', 'Requested by'),
          hideBelow: EXCEPTION_HIDE_BELOW.requestedBy,
        },
        enableSorting: false,
        cell: ({ row }) => <CellText>{requesterOf(row.original)}</CellText>,
      },
      {
        id: 'actions',
        enableHiding: false,
        meta: { kind: 'actions' },
        cell: ({ row }) => {
          const rule = row.original
          const label = t('common.actionMenu.label', 'Actions for {name}', { name: rule.name })
          const items: ActionMenuEntry[] = [
            ...(rule.status === 'pending' && can(Permission.SuppressionsApprove)
              ? [
                  {
                    id: 'approve',
                    section: 'review',
                    label: t('exceptions.page.approve', 'Approve'),
                    icon: Check,
                    onSelect: () => openApprove(rule),
                  },
                  {
                    id: 'reject',
                    section: 'review',
                    label: t('exceptions.page.reject', 'Reject'),
                    icon: X,
                    onSelect: () => openReject(rule),
                  },
                ]
              : []),
            ...(can(Permission.SuppressionsWrite)
              ? [
                  {
                    id: 'edit',
                    label: t('exceptions.page.edit', 'Edit'),
                    icon: Pencil,
                    onSelect: () => openEdit(rule),
                  },
                ]
              : []),
            ...(can(Permission.SuppressionsDelete)
              ? [
                  {
                    id: 'delete',
                    label: t('exceptions.page.delete', 'Delete'),
                    icon: Trash2,
                    destructive: true,
                    onSelect: () => openDelete(rule),
                  },
                ]
              : []),
          ]
          if (items.length === 0) return null
          return (
            <ActionMenu
              title={rule.name}
              label={label}
              items={items}
              trigger={
                <Button size="icon" variant="ghost" aria-label={label}>
                  <MoreHorizontal aria-hidden />
                </Button>
              }
            />
          )
        },
      },
    ],
    [openApprove, openReject, openEdit, openDelete, can, t, locale, approversOf, requesterOf]
  )

  const pickStatus = (next: SuppressionStatus | '') => {
    setEndsParam('')
    setStatusParam(status === next ? '' : next)
  }
  const pickEnds = (next: EndsWindow) => {
    setStatusParam('')
    setEndsParam(ends === next ? '' : next)
  }
  const metrics: MetricStripItem[] = [
    {
      key: 'pending',
      label: t('exceptions.page.metricPending', 'Pending approval'),
      value: counts.pending,
      hint:
        counts.oldestPendingDays > 0
          ? t('exceptions.page.oldestDays', 'oldest {count, plural, one {# day} other {# days}}', {
              count: counts.oldestPendingDays,
            })
          : undefined,
      tone: 'warning',
      onClick: () => pickStatus('pending'),
      active: status === 'pending' && !ends,
    },
    {
      key: 'ends7',
      label: t('exceptions.page.metricEnds7', 'Ending in 7 days'),
      value: counts.ends7,
      tone: 'warning',
      onClick: () => pickEnds('7'),
      active: ends === '7',
    },
    {
      key: 'ends30',
      label: t('exceptions.page.metricEnds30', 'Ending in 30 days'),
      value: counts.ends30,
      onClick: () => pickEnds('30'),
      active: ends === '30',
    },
    {
      key: 'approved',
      label: t('exceptions.page.metricApproved', 'Approved'),
      value: counts.approved,
      onClick: () => pickStatus('approved'),
      active: status === 'approved' && !ends,
    },
    {
      key: 'expired',
      label: t('exceptions.page.metricExpired', 'Expired'),
      value: counts.expired,
      onClick: () => pickStatus('expired'),
      active: status === 'expired' && !ends,
    },
  ]

  const filtered = !!status || !!type || !!ends || search.trim() !== ''
  const clearFilters = () => {
    setStatusParam('')
    setTypeParam('')
    setEndsParam('')
    setSearch('')
  }
  const chips: ContextFilterChip[] = ends
    ? [
        {
          param: 'ends',
          kind: t('exceptions.page.chipEnds', 'Ends'),
          label: t(
            'exceptions.page.chipEndsValue',
            'within {count, plural, one {# day} other {# days}}',
            {
              count: Number(ends),
            }
          ),
        },
      ]
    : []
  const canWrite = can(Permission.SuppressionsWrite)

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader
            title={t('exceptions.page.title', 'Exceptions')}
            description={t(
              'exceptions.page.description',
              'Suppression rules that hide false positives and accepted risks, with an approval step.'
            )}
          />

          <MetricStrip loading={isInitialLoading} items={metrics} listFirst />

          <DataTable
            columns={columns}
            data={filteredRules}
            // When the table still scrolls sideways the row menu stays in view.
            pinActions
            search={{
              value: search,
              onChange: setSearch,
              placeholder: t('exceptions.page.search', 'Search by name…'),
            }}
            toolbarStart={
              <>
                <FilterSelect<SuppressionType>
                  label={t('exceptions.page.colType', 'Type')}
                  value={type}
                  foldLabel
                  options={TYPES.map((v) => ({ value: v, label: suppressionTypeLabel(v, t) }))}
                  onChange={(v) => setTypeParam(v)}
                />
                <FilterSelect<SuppressionStatus>
                  label={t('exceptions.page.colStatus', 'State')}
                  value={status}
                  foldLabel
                  allCount={counts.all}
                  options={STATUSES.map((v) => ({
                    value: v,
                    label: suppressionStatusLabel(v, t),
                    count: counts[v],
                  }))}
                  onChange={(v) => {
                    setEndsParam('')
                    setStatusParam(v)
                  }}
                />
              </>
            }
            toolbarEnd={
              <>
                <RefreshButton
                  onClick={handleRefresh}
                  loading={isValidating}
                  label={t('exceptions.page.refresh', 'Refresh')}
                />
                {canWrite && (
                  <ToolbarAction
                    icon={Plus}
                    label={t('exceptions.page.newRule', 'New exception')}
                    onClick={openCreate}
                  />
                )}
              </>
            }
            toolbarBelow={
              chips.length > 0 ? (
                <ContextFilterChips chips={chips} onRemove={() => setEndsParam('')} />
              ) : undefined
            }
            isLoading={isInitialLoading}
            error={error && !data ? error : undefined}
            onRetry={() => void mutate()}
            errorTitle={t('exceptions.page.errorTitle', 'suppression rules')}
            isFiltered={filtered}
            onClearFilters={clearFilters}
            emptyState={{
              nothingYet: (
                <EmptyState
                  icon={ShieldOff}
                  title={t('exceptions.page.emptyTitle', 'No exceptions')}
                  description={t(
                    'exceptions.page.emptyAll',
                    'False positives and accepted risks appear here with who approved them and when they end.'
                  )}
                  action={
                    canWrite ? (
                      <Button onClick={openCreate}>
                        <Plus aria-hidden />
                        {t('exceptions.page.newRule', 'New exception')}
                      </Button>
                    ) : undefined
                  }
                  card
                />
              ),
              noMatch: {
                title: t('exceptions.page.emptyFiltered', 'No exceptions match these filters'),
                hint: t(
                  'exceptions.page.emptyFilteredHint',
                  'Clear the filters to see every rule.'
                ),
              },
            }}
            paginationNoun={t('exceptions.page.noun', 'rules')}
            getRowId={(r) => r.id}
            onRowClick={openDetail}
            mobileRow={(r) => (
              <div data-slot="exception-card" className="flex min-w-0 flex-col gap-1 px-3 py-3">
                <div className="flex min-w-0 items-center justify-between gap-3">
                  <span data-cut-tooltip className="min-w-0 truncate font-medium" title={r.name}>
                    {r.name}
                  </span>
                  <span className="shrink-0">
                    <SuppressionStatusBadge status={r.status} />
                  </span>
                </div>
                <p className="text-meta font-mono [overflow-wrap:anywhere]">
                  {suppressionScopeSummary(r, t)}
                </p>
                <MetaLine
                  items={[
                    suppressionTypeLabel(r.suppression_type, t),
                    r.expires_at
                      ? t('exceptions.page.endsWhen', 'Ends {when}', {
                          when: relative(r.expires_at, locale),
                        })
                      : t('exceptions.page.neverEnds', 'Never ends'),
                    // The table's "—" for nobody is noise on a card: leave the item out.
                    approversOf(r) === '—' ? null : approversOf(r),
                  ]}
                />
              </div>
            )}
          />
        </PageStack>
      </Main>

      {/* Detail sheet */}
      <SuppressionDetailSheet
        rule={selectedRule}
        open={detailOpen}
        onOpenChange={setDetailOpen}
        onEdit={openEdit}
        onApprove={openApprove}
        onReviewed={markReviewed}
        onReject={openReject}
        onDelete={openDelete}
      />

      {/* Create / edit dialog */}
      <SuppressionFormDialog
        open={formOpen}
        onOpenChange={setFormOpen}
        rule={editRule}
        onSuccess={() => mutate()}
      />

      {/* Approve confirm */}
      <ConfirmDialog
        open={approveOpen}
        onOpenChange={setApproveOpen}
        title={t('confirm.suppression.approveTitle', 'Approve the suppression rule "{name}"?', {
          name: selectedRule?.name ?? '',
        })}
        desc={t(
          'confirm.suppression.approveDesc',
          'Matching findings are suppressed while this rule is active.'
        )}
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
        handleConfirm={confirmApprove}
      >
        <SuppressionApprovePreview ruleId={approveOpen ? selectedRule?.id : undefined} />
      </ConfirmDialog>

      <SelfApproveDialog
        open={selfApproveOpen}
        onOpenChange={setSelfApproveOpen}
        subject={selectedRule?.name ?? ''}
        onSubmit={confirmSelfApprove}
      />
      <SelfApproveDialog
        open={selfReviewOpen}
        onOpenChange={setSelfReviewOpen}
        subject={selectedRule?.name ?? ''}
        onSubmit={confirmSelfReview}
      />

      {/* Reject dialog */}
      <Dialog open={rejectOpen} onOpenChange={setRejectOpen}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>{t('exceptions.page.rejectTitle', 'Reject suppression rule')}</DialogTitle>
            <DialogDescription>
              {t('exceptions.page.rejectDescription', 'Provide a reason for rejecting this rule.')}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4">
            {selectedRule && (
              <div className="rounded-lg border bg-muted/50 p-3">
                <p className="text-sm font-medium">{selectedRule.name}</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {suppressionScopeSummary(selectedRule, t)}
                </p>
              </div>
            )}
            <div className="grid gap-2">
              <Textarea
                placeholder={t('exceptions.page.rejectPlaceholder', 'Reason for rejection...')}
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
            <Button variant="outline" onClick={() => setRejectOpen(false)} disabled={isRejecting}>
              {t('exceptions.page.cancel', 'Cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={confirmReject}
              disabled={isRejecting || !rejectionReason.trim()}
            >
              {isRejecting ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  {t('exceptions.page.rejecting', 'Rejecting...')}
                </>
              ) : (
                t('exceptions.page.reject', 'Reject')
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={t('confirm.suppression.deleteTitle', 'Delete the suppression rule "{name}"?', {
          name: selectedRule?.name ?? '',
        })}
        desc={t(
          'confirm.suppression.deleteDesc',
          'Findings it suppressed are no longer suppressed by it and return to the open queues. The rule is removed for good.'
        )}
        typeToConfirm={selectedRule ? confirmName(selectedRule.name, selectedRule.id) : undefined}
        destructive
        cancelBtnText={t('confirm.suppression.keep', 'Keep rule')}
        confirmText={
          isDeleting ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.deleting', 'Deleting…')}
            </>
          ) : (
            t('confirm.suppression.deleteButton', 'Delete rule')
          )
        }
        isLoading={isDeleting}
        handleConfirm={confirmDelete}
      />
    </>
  )
}
