'use client'

/**
 * Scans > Approvals: the scan approval requests of the organization
 * (RFC-073), as a queue. Approvers see what each scan will do (targets,
 * intensity, tools, schedule, the rule that caught it and what changed since
 * the last approval) and approve or reject it; requesters remind or withdraw.
 * The backend decides who may act: these controls only follow `can_approve`
 * and `self_approval_available`.
 */

import { useCallback, useMemo, useState } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'

import Link from '@/components/link'
import { StepUpDialog } from '@/components/security'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { type ActionMenuEntry } from '@/components/ui/action-menu'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { RefreshButton } from '@/components/list-page-parts'
import { useTranslation } from '@/context/i18n-provider'
import { ApprovalStatusLozenge } from '@/features/shared/components/approval-status-lozenge'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import type { DataTableColumnMeta } from '@/features/shared/components/data-table/column-meta'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { PageStack } from '@/features/shared/components/page-stack'
import {
  QueueCard,
  QueueDecideBy,
  QueueDecisionActions,
  QueueEmpty,
  decideByState,
  useQueueAnnouncer,
} from '@/features/shared/components/queue'
import { useListParams } from '@/hooks/use-list-params'
import { useMyUserId } from '@/hooks/use-my-user-id'
import { accessStateOf } from '@/lib/api/access-state'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatAbsoluteTime, formatRelativeTime } from '@/lib/format-metric'
import { Permission } from '@/lib/permissions'
import {
  approveScanRequest,
  cancelScanRequest,
  refreshScanApprovals,
  rejectScanRequest,
  remindScanApprovers,
  selfApproveScanRequest,
  useScanApprovals,
  type ScanApprovalRequest,
  type ScanApprovalStatus,
} from '@/lib/api/scan-approval-hooks'
import type { ScanIntensity } from '@/lib/api/scan-types'
import { toDisplayText } from '@/lib/untrusted-text'
import { IntensityBadge } from '../intensity-badge'
import { approversText } from './approval-requirement'

type Action = 'approve' | 'reject' | 'self'

const PREVIEW_TARGETS = 10

const STATUSES: ScanApprovalStatus[] = [
  'pending',
  'approved',
  'rejected',
  'expired',
  'superseded',
  'canceled',
]
type Lens = ScanApprovalStatus | 'all'

const STATUS_LABEL: Record<ScanApprovalStatus, [string, string]> = {
  pending: ['scans.approval.statusPending', 'Awaiting approval'],
  approved: ['scans.approval.statusApproved', 'Approved'],
  rejected: ['scans.approval.statusRejected', 'Rejected'],
  expired: ['scans.approval.statusExpired', 'Expired'],
  superseded: ['scans.approval.statusSuperseded', 'Superseded'],
  canceled: ['scans.approval.statusCanceled', 'Withdrawn'],
}

/** Widths in px: the longest en and vi value whole, plus the cell padding. */
const WIDTH = {
  scanMin: 192,
  // "Awaiting approval" / "Đang chờ phê duyệt" as a lozenge.
  status: 168,
  requester: 140,
  // "Overdue, 15 Nov" / "Quá hạn, 15 thg 11" whole.
  decideBy: 148,
  // Approve + Reject (or "Your request") + More in en and vi.
  actions: 236,
} as const
/**
 * Frame widths below which a column leaves the table (Display > Columns brings
 * it back), so the table fits its frame and the page never scrolls sideways:
 * 1024 with the sidebar open leaves a 698 px frame. The scan, its status, the
 * decide-by date and the decision stay at every width; the phone card and the
 * Details dialog show every field. Run and Requested by leave first; with the
 * Status column (every lens but Pending) they leave 168 px earlier, and Decide
 * by, empty on every decided row, leaves too.
 */
const HIDE_BELOW = { rule: 1120, requested: 1260, left: 1360, run: 920, requester: 760 } as const
const HIDE_BELOW_WITH_STATUS = { run: 1088, requester: 928, decideBy: 760 } as const

function formatValue(v: unknown): string {
  if (v === null || v === undefined || v === '') return '—'
  if (Array.isArray(v)) return v.length === 0 ? '—' : v.join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

const scanName = (req: ScanApprovalRequest) => toDisplayText(req.scan_name || req.scan_id, 120)
const ruleNames = (req: ScanApprovalRequest) =>
  (req.evaluation.matched ?? []).map((r) => r.name).join(', ')

function RequestDetails({ req }: { req: ScanApprovalRequest }) {
  const { t } = useTranslation()
  const targets = req.definition.targets ?? []
  const groups = req.definition.asset_group_ids ?? []
  return (
    <div className="grid gap-4 text-sm md:grid-cols-2">
      <div className="space-y-1">
        <p className="font-medium">{t('scans.approval.targets', 'Targets')}</p>
        <p className="text-muted-foreground">
          {t('scans.approval.targetsCount', '{targets} targets, {groups} asset groups', {
            targets: targets.length,
            groups: groups.length,
          })}
        </p>
        <ul className="font-mono text-xs">
          {targets.slice(0, PREVIEW_TARGETS).map((x) => (
            <li key={x}>{x}</li>
          ))}
          {targets.length > PREVIEW_TARGETS && (
            <li className="text-muted-foreground">
              {t('scans.approval.moreTargets', '+{count} more', {
                count: targets.length - PREVIEW_TARGETS,
              })}
            </li>
          )}
        </ul>
      </div>
      <div className="space-y-1">
        <p className="font-medium">{t('scans.approval.what', 'What runs')}</p>
        <p className="text-muted-foreground">
          {req.definition.scanner_name ||
            (req.definition.workflow_steps ?? []).join(', ') ||
            req.definition.scan_type}
          {', '}
          {t('scans.approval.schedule', 'schedule: {value}', {
            value: req.definition.schedule_type ?? '—',
          })}
        </p>
        {req.justification && (
          <p>
            <span className="font-medium">
              {t('scans.approval.justification', 'Justification')}:
            </span>{' '}
            {req.justification}
          </p>
        )}
        {req.ticket && (
          <p>
            <span className="font-medium">{t('scans.approval.ticket', 'Change ticket')}:</span>{' '}
            {req.ticket}
          </p>
        )}
        {req.decision_note && (
          <p>
            <span className="font-medium">{t('scans.approval.decisionNote', 'Note')}:</span>{' '}
            {req.decision_note}
          </p>
        )}
      </div>
      {req.changes.length > 0 && (
        <div className="space-y-1 md:col-span-2">
          <p className="font-medium">
            {t('scans.approval.changes', 'Changed since the last approval')}
          </p>
          <ul className="space-y-1 text-xs">
            {req.changes.map((c) => (
              <li key={c.field} className="grid gap-1 sm:grid-cols-[10rem_1fr]">
                <span className="font-mono">{c.field}</span>
                <span>
                  <span className="text-muted-foreground line-through">
                    {formatValue(c.before)}
                  </span>
                  {' → '}
                  <span>{formatValue(c.after)}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: ScanApprovalStatus }) {
  const { t } = useTranslation()
  const [key, fallback] = STATUS_LABEL[status]
  return <ApprovalStatusLozenge status={status} label={t(key, fallback)} />
}

const INTENSITIES: readonly string[] = ['passive', 'active', 'intrusive'] satisfies ScanIntensity[]
/** The request's intensity when it is one the console names, else undefined. */
const knownIntensity = (req: ScanApprovalRequest): ScanIntensity | undefined =>
  INTENSITIES.includes(req.definition.intensity ?? '')
    ? (req.definition.intensity as ScanIntensity)
    : undefined

/** Emergency run and intensity: the marks a reviewer weighs first. */
function RunMarks({ req }: { req: ScanApprovalRequest }) {
  const { t } = useTranslation()
  return (
    <>
      {req.emergency && (
        <Badge variant="destructive">{t('scans.approval.emergency', 'Emergency run')}</Badge>
      )}
      {/* The scans' own intensity mark: translated, the same on every scan page. */}
      {knownIntensity(req) && <IntensityBadge intensity={knownIntensity(req)} />}
    </>
  )
}

export function ScanApprovalsInbox() {
  const { t, locale } = useTranslation()
  const me = useMyUserId()
  const list = useListParams({ filters: { status: '' } })
  const lens: Lens =
    list.filters.status === 'all'
      ? 'all'
      : (STATUSES as string[]).includes(list.filters.status) && list.filters.status !== ''
        ? (list.filters.status as ScanApprovalStatus)
        : 'pending'
  const { data, error, isLoading, isValidating, mutate } = useScanApprovals(
    lens === 'all' ? '' : lens,
    list.page,
    list.perPage
  )
  const announcer = useQueueAnnouncer()
  const [action, setAction] = useState<{ kind: Action; req: ScanApprovalRequest } | null>(null)
  const [details, setDetails] = useState<ScanApprovalRequest | null>(null)
  const [withdraw, setWithdraw] = useState<ScanApprovalRequest | null>(null)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const { announce } = announcer

  const { setFilter } = list
  const changeLens = useCallback(
    (next: Lens) => setFilter('status', next === 'pending' ? '' : next),
    [setFilter]
  )

  const run = useCallback(
    async (fn: () => Promise<unknown>, ok: string) => {
      setBusy(true)
      try {
        await fn()
        toast.success(ok)
        announce(ok)
        setAction(null)
        setWithdraw(null)
        setNote('')
        await refreshScanApprovals()
      } catch (e) {
        const msg = getErrorMessage(e, t('scans.approval.actionFailed', 'The action failed'))
        toast.error(msg)
        announce(msg)
      } finally {
        setBusy(false)
      }
    },
    [announce, t]
  )

  const confirm = () => {
    if (!action) return
    const { kind, req } = action
    if (kind === 'approve') {
      void run(
        () => approveScanRequest(req.id, note),
        t('scans.approval.approvedToast', 'Approval recorded')
      )
    } else if (kind === 'reject') {
      void run(
        () => rejectScanRequest(req.id, note),
        t('scans.approval.rejectedToast', 'Request rejected')
      )
    }
  }

  const selfApprove = async (code: string) => {
    if (action?.kind !== 'self') return
    await selfApproveScanRequest(action.req.id, note.trim(), code)
    const ok = t('scans.approval.selfApprovedToast', 'Approved with your authenticator code')
    toast.success(ok)
    announce(ok)
    setAction(null)
    setNote('')
    await refreshScanApprovals()
  }

  // The row's controls; the table cell and the phone card share them.
  const actionsCell = useCallback(
    (req: ScanApprovalRequest, layout: 'row' | 'compact' = 'row') => {
      const pending = req.status === 'pending'
      const mine = req.requested_by?.id === me
      const menu: ActionMenuEntry[] = [
        {
          id: 'details',
          label: t('scans.approval.details', 'Details'),
          onSelect: () => setDetails(req),
        },
      ]
      if (pending && req.self_approval_available)
        menu.push({
          id: 'self',
          label: t('scans.approval.selfApprove', 'Approve my own scan'),
          onSelect: () => setAction({ kind: 'self', req }),
        })
      if (pending && mine) {
        menu.push({
          id: 'remind',
          label: t('scans.approval.remind', 'Remind'),
          disabledReason: busy ? t('scans.approval.busy', 'Saving') : undefined,
          onSelect: () =>
            void run(
              () => remindScanApprovers(req.id),
              t('scans.approval.remindedToast', 'Approvers reminded')
            ),
        })
        menu.push({
          id: 'withdraw',
          label: t('scans.approval.withdraw', 'Withdraw'),
          destructive: true,
          onSelect: () => setWithdraw(req),
        })
      }
      return (
        <QueueDecisionActions
          name={scanName(req)}
          itemId={req.id}
          canDecide={pending && (req.can_approve || mine)}
          own={pending && mine && !req.can_approve}
          ownReason={t(
            'scans.approval.ownReason',
            'Another approver decides a scan you asked for.'
          )}
          busy={busy}
          approveLabel={t('scans.approval.approve', 'Approve')}
          rejectLabel={t('scans.approval.reject', 'Reject')}
          onApprove={() => setAction({ kind: 'approve', req })}
          onReject={() => setAction({ kind: 'reject', req })}
          menu={menu}
          layout={layout}
        />
      )
    },
    [busy, me, run, t]
  )

  const showStatus = lens !== 'pending'
  const columns = useMemo<ColumnDef<ScanApprovalRequest>[]>(() => {
    const label = {
      scan: t('scans.approval.col.scan', 'Scan'),
      status: t('scans.approval.col.status', 'Status'),
      run: t('scans.approval.col.run', 'Run'),
      requester: t('scans.approval.col.requester', 'Requested by'),
      rule: t('scans.approval.col.rule', 'Rule'),
      left: t('scans.approval.col.left', 'Approvals left'),
      decideBy: t('scans.approval.col.decideBy', 'Decide by'),
      requested: t('scans.approval.col.requested', 'Requested'),
      actions: t('scans.approval.col.actions', 'Decision'),
    }
    const meta = (m: DataTableColumnMeta) => m
    const narrow = showStatus ? HIDE_BELOW_WITH_STATUS : HIDE_BELOW
    const cols: ColumnDef<ScanApprovalRequest>[] = [
      {
        id: 'scan',
        meta: meta({ kind: 'name', pin: 'start', minWidth: WIDTH.scanMin, label: label.scan }),
        header: label.scan,
        enableHiding: false,
        enableSorting: false,
        cell: ({ row }) => (
          <div className="w-0 min-w-full">
            <Link
              href={`/scans/${encodeURIComponent(row.original.scan_id)}`}
              className="block truncate font-medium hover:underline"
              title={scanName(row.original)}
            >
              {scanName(row.original)}
            </Link>
          </div>
        ),
      },
      ...(showStatus
        ? [
            {
              id: 'status',
              meta: meta({ kind: 'status', width: WIDTH.status, label: label.status }),
              header: label.status,
              enableSorting: false,
              cell: ({ row }) => <StatusBadge status={row.original.status} />,
            } satisfies ColumnDef<ScanApprovalRequest>,
          ]
        : []),
      {
        id: 'run',
        meta: meta({ kind: 'text', label: label.run, maxWidth: 220, hideBelow: narrow.run }),
        header: label.run,
        enableSorting: false,
        cell: ({ row }) =>
          row.original.emergency || knownIntensity(row.original) ? (
            <span className="flex items-center gap-1.5">
              <RunMarks req={row.original} />
            </span>
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        id: 'requester',
        meta: meta({
          kind: 'owner',
          width: WIDTH.requester,
          hideBelow: narrow.requester,
          label: label.requester,
        }),
        header: label.requester,
        enableSorting: false,
        cell: ({ row }) => (
          <span className="block truncate">
            {row.original.requested_by?.id === me
              ? t('scans.approval.you', 'You')
              : (row.original.requested_by?.name ?? '-')}
          </span>
        ),
      },
      {
        id: 'rule',
        meta: meta({ kind: 'text', hideBelow: HIDE_BELOW.rule, maxWidth: 240, label: label.rule }),
        header: label.rule,
        enableSorting: false,
        cell: ({ row }) => (
          <span className="block truncate text-muted-foreground" title={ruleNames(row.original)}>
            {ruleNames(row.original) || '-'}
          </span>
        ),
      },
      {
        id: 'left',
        meta: meta({ kind: 'text', hideBelow: HIDE_BELOW.left, maxWidth: 240, label: label.left }),
        header: label.left,
        enableSorting: false,
        cell: ({ row }) =>
          row.original.status === 'pending' ? (
            <span
              className="block truncate text-muted-foreground"
              title={approversText(t, row.original.evaluation)}
            >
              {t('scans.approval.remaining', '{count} approval(s) left, {who}', {
                count: row.original.remaining,
                who: approversText(t, row.original.evaluation),
              })}
            </span>
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        id: 'decideBy',
        meta: meta({
          kind: 'due',
          width: WIDTH.decideBy,
          hideBelow: showStatus ? HIDE_BELOW_WITH_STATUS.decideBy : undefined,
          label: label.decideBy,
        }),
        header: label.decideBy,
        enableSorting: false,
        cell: ({ row }) => (
          <QueueDecideBy
            value={row.original.status === 'pending' ? row.original.expires_at : undefined}
          />
        ),
      },
      {
        id: 'requested',
        meta: meta({
          kind: 'datetime-recent',
          hideBelow: HIDE_BELOW.requested,
          label: label.requested,
        }),
        header: label.requested,
        enableSorting: false,
        cell: ({ row }) => (
          <time
            dateTime={row.original.requested_at}
            title={formatAbsoluteTime(row.original.requested_at, locale)}
            className="whitespace-nowrap text-muted-foreground"
          >
            {formatRelativeTime(row.original.requested_at, locale)}
          </time>
        ),
      },
      {
        id: 'actions',
        meta: meta({ kind: 'actions', width: WIDTH.actions, label: label.actions }),
        header: () => <span className="sr-only">{label.actions}</span>,
        enableHiding: false,
        enableSorting: false,
        cell: ({ row }) => actionsCell(row.original),
      },
    ]
    return cols
  }, [actionsCell, locale, me, showStatus, t])

  const statusLens = (
    <FilterSelect<ScanApprovalStatus>
      label={t('scans.approval.col.status', 'Status')}
      value={lens === 'all' ? '' : lens}
      onChange={(next) => changeLens(next === '' ? 'all' : next)}
      allLabel={t('scans.approval.filterAll', 'All requests')}
      options={STATUSES.map((value) => ({
        value,
        label: t(STATUS_LABEL[value][0], STATUS_LABEL[value][1]),
      }))}
    />
  )

  const noAccess = !data && accessStateOf(error) === 'no_access'
  const total = data?.total ?? 0
  const viewTitle =
    lens === 'all'
      ? t('scans.approval.viewName.all', 'All scan requests')
      : t(`scans.approval.viewName.${lens}`, 'Scan requests')
  const showAll = (
    <Button variant="outline" size="sm" onClick={() => changeLens('all')}>
      {t('scans.approval.showAll', 'Show all requests')}
    </Button>
  )
  const emptyHint = t(
    'scans.approval.emptyDesc',
    'Scans the organization’s approval rules catch appear here when someone submits them.'
  )
  const emptyState =
    lens === 'pending' ? (
      <QueueEmpty
        kind="nothing-waiting"
        title={t('scans.approval.emptyTitle', 'No scan waits for approval')}
        hint={emptyHint}
        action={showAll}
      />
    ) : lens === 'all' ? (
      <QueueEmpty
        kind="first-run"
        title={t('scans.approval.emptyAll', 'No scan approval requests')}
        hint={emptyHint}
      />
    ) : (
      <QueueEmpty
        kind="no-match"
        title={t('scans.approval.emptyStatus', 'No requests with the status {status}.', {
          status: t(STATUS_LABEL[lens][0], STATUS_LABEL[lens][1]),
        })}
        action={showAll}
      />
    )

  return (
    <>
      <PageStack>
        <ListTitleRow
          title={viewTitle}
          count={
            <ListCount
              total={total}
              loading={(isLoading && !data) || noAccess}
              label={t(
                'scans.approval.total',
                '{count, plural, one {# request} other {# requests}}',
                { count: total }
              )}
            />
          }
        >
          <RefreshButton
            onClick={() => void mutate()}
            loading={isValidating}
            label={t('scans.approval.refresh', 'Refresh')}
          />
        </ListTitleRow>
        {noAccess ? (
          <NoAccessState
            title={t('scans.approval.errorTitle', 'scan approvals')}
            permission={Permission.ScansRead}
          />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            caption={viewTitle}
            isLoading={isLoading && !data}
            isRefreshing={isValidating && !!data}
            refreshingLabel={t('scans.approval.refreshing', 'Refreshing requests')}
            error={data ? undefined : error}
            onRetry={() => void mutate()}
            errorTitle={t('scans.approval.errorTitle', 'scan approvals')}
            manualPagination
            showSearch={false}
            pageCount={data ? Math.max(1, Math.ceil(total / list.perPage)) : 1}
            rowCount={total}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
            paginationNoun={t('scans.approval.paginationNoun', 'requests')}
            getRowId={(r) => r.id}
            pinActions
            toolbarStart={statusLens}
            emptyState={emptyState}
            mobileRow={(req) => (
              <QueueCard
                data-testid="scan-approval-card"
                href={`/scans/${encodeURIComponent(req.scan_id)}`}
                title={
                  <Link
                    href={`/scans/${encodeURIComponent(req.scan_id)}`}
                    className="font-medium hover:underline"
                  >
                    {scanName(req)}
                  </Link>
                }
                // The state; under Pending (every card is pending) the run's
                // marks take its place.
                state={
                  showStatus ? (
                    <StatusBadge status={req.status} />
                  ) : req.emergency || knownIntensity(req) ? (
                    <RunMarks req={req} />
                  ) : undefined
                }
                reason={
                  <span className="text-xs text-muted-foreground">
                    {ruleNames(req)}
                    {req.status === 'pending' && (
                      <>
                        {ruleNames(req) ? '. ' : ''}
                        {t('scans.approval.remaining', '{count} approval(s) left, {who}', {
                          count: req.remaining,
                          who: approversText(t, req.evaluation),
                        })}
                      </>
                    )}
                  </span>
                }
                // The run's marks, by when, then who asked (cut first).
                meta={[
                  showStatus && (req.emergency || knownIntensity(req)) ? (
                    <span key="marks" className="flex items-center gap-1.5">
                      <RunMarks req={req} />
                    </span>
                  ) : null,
                  req.status === 'pending' ? (
                    <span key="due">
                      {decideByState(req.expires_at) !== 'overdue' && (
                        <>{t('scans.approval.col.decideBy', 'Decide by')} </>
                      )}
                      <QueueDecideBy value={req.expires_at} className="text-xs" />
                    </span>
                  ) : null,
                  <span key="by">
                    {t('scans.approval.requestedBy', 'Requested by {name} {when}', {
                      name:
                        req.requested_by?.id === me
                          ? t('scans.approval.you', 'You')
                          : (req.requested_by?.name ?? '—'),
                      when: formatRelativeTime(req.requested_at, locale),
                    })}
                  </span>,
                ]}
                actions={actionsCell(req, 'compact')}
              />
            )}
          />
        )}
      </PageStack>
      {announcer.region}

      <Dialog open={!!details} onOpenChange={(o) => !o && setDetails(null)}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{details ? scanName(details) : ''}</DialogTitle>
            <DialogDescription>
              {details && (
                <>
                  <StatusBadge status={details.status} />{' '}
                  {t('scans.approval.requestedBy', 'Requested by {name} {when}', {
                    name: details.requested_by?.name ?? '—',
                    when: formatRelativeTime(details.requested_at, locale),
                  })}
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>{details && <RequestDetails req={details} />}</DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDetails(null)}>
              {t('scans.approval.close', 'Close')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!withdraw}
        onOpenChange={(o) => !busy && !o && setWithdraw(null)}
        title={t('scans.approval.withdrawTitle', 'Withdraw this request?')}
        desc={t(
          'scans.approval.withdrawDesc',
          'The scan does not run. To run it later, submit it for approval again.'
        )}
        cancelBtnText={t('scans.approval.keepRequest', 'Keep request')}
        confirmText={t('scans.approval.withdraw', 'Withdraw')}
        destructive
        isLoading={busy}
        handleConfirm={() => {
          const req = withdraw
          if (!req) return
          void run(
            () => cancelScanRequest(req.id),
            t('scans.approval.canceledToast', 'Request withdrawn')
          )
        }}
      />

      <StepUpDialog
        open={action?.kind === 'self'}
        onOpenChange={(o) => !o && setAction(null)}
        title={t('scans.approval.selfTitle', 'Approve your own scan?')}
        description={t(
          'scans.approval.selfDesc',
          'No other approver can approve it. Confirm with a code from your authenticator and say why; every administrator is told.'
        )}
        ready={!!note.trim()}
        submitLabel={t('scans.approval.approve', 'Approve')}
        onSubmit={async (proof) => {
          if (proof.kind === 'totp') await selfApprove(proof.code)
        }}
        errorMessage={(e) =>
          getErrorMessage(e, t('scans.approval.actionFailed', 'The action failed'))
        }
      >
        <div className="space-y-2">
          <Label htmlFor="approval-reason">{t('scans.approval.reason', 'Reason')}</Label>
          <Textarea
            id="approval-reason"
            rows={2}
            maxLength={1000}
            autoFocus
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </div>
      </StepUpDialog>

      <Dialog
        open={!!action && action.kind !== 'self'}
        onOpenChange={(o) => !busy && !o && setAction(null)}
      >
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>
              {action?.kind === 'reject'
                ? t('scans.approval.rejectTitle', 'Reject this scan?')
                : t('scans.approval.approveTitle', 'Approve this scan?')}
            </DialogTitle>
            <DialogDescription>{action ? scanName(action.req) : ''}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="approval-note">
                {t('scans.approval.noteOptional', 'Note (optional)')}
              </Label>
              <Textarea
                id="approval-note"
                rows={2}
                maxLength={1000}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAction(null)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={confirm}
              disabled={busy}
              variant={action?.kind === 'reject' ? 'destructive' : 'default'}
            >
              {action?.kind === 'reject'
                ? t('scans.approval.reject', 'Reject')
                : t('scans.approval.approve', 'Approve')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
