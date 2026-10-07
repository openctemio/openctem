'use client'

/**
 * Scoping › Boundaries › Targets: the scope entries (RFC-054 §6.1).
 *
 * Each row says what the entry covers (`*.x` is x and every name below it),
 * whether it authorizes probes now (active, pending approval, expired,
 * inactive, rejected), when it expires, why it exists and how deep a probe
 * may go. Approvers approve or reject pending entries in place; the API asks
 * for step-up re-authentication on every widening action, and the shared
 * client opens that dialog and retries.
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  CalendarClock,
  Check,
  Pencil,
  Power,
  PowerOff,
  Search as SearchIcon,
  Trash2,
  X,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable, DataTableRowActions, TonePill, type RowAction } from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'
import { useUser } from '@/stores/auth-store'
import {
  approveScopeTarget,
  invalidateScopeCache,
  rejectScopeTarget,
  setScopeTargetActive,
  updateScopeTarget,
  useDeleteScopeTargetApi,
  useScopeSettingsApi,
  useScopeTargetsApi,
} from '../api/use-scope-api'
import type { ApiScopeTarget } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import {
  approvalsMissing,
  canApproveEntry,
  coversText,
  entryStatus,
  expiryText,
  SCOPE_ENTRY_STATUSES,
  SCOPE_ENTRY_STATUS_HINT,
  SCOPE_ENTRY_STATUS_LABEL,
  SCOPE_ENTRY_STATUS_TONE,
  TIER_LABEL,
} from '../lib/scope-entry'
import { ScopeEntryEditDialog } from './scope-entry-edit-dialog'
import {
  SCOPE_TARGET_TYPE_ICON,
  ScopeTargetTypeSelect,
  scopeTargetTypeLabel,
} from './scope-target-type'

const PAGE_SIZES = [10, 20, 30, 50, 100]

export interface ScopeTargetsQuery {
  search: string
  type: string
  status: string
  page: number
  perPage: number
}

interface ScopeTargetsPanelProps {
  query: ScopeTargetsQuery
  searchInput: string
  onSearchInput: (v: string) => void
  onTypeChange: (v: string) => void
  onStatusChange: (v: string) => void
  onPagination: (p: { pageIndex: number; pageSize: number }) => void
}

export function ScopeTargetsPanel({
  query,
  searchInput,
  onSearchInput,
  onTypeChange,
  onStatusChange,
  onPagination,
}: ScopeTargetsPanelProps) {
  const { t } = useTranslation()
  const user = useUser()
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const canApprove = useHasPermission(Permission.ScopeApprove)
  const { data: settings } = useScopeSettingsApi()
  const renewDays = settings?.one_off_max_days ?? 7

  const { data, isLoading } = useScopeTargetsApi({
    search: query.search || undefined,
    target_type: query.type !== 'all' ? query.type : undefined,
    status: query.status !== 'all' ? query.status : undefined,
    page: query.page,
    per_page: query.perPage,
  })
  const targets = useMemo(() => data?.data ?? [], [data?.data])

  const [editEntry, setEditEntry] = useState<ApiScopeTarget | null>(null)
  const [deleteEntry, setDeleteEntry] = useState<ApiScopeTarget | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const { trigger: removeTarget, isMutating: removing } = useDeleteScopeTargetApi(
    deleteEntry?.id ?? ''
  )

  const act = async (id: string, fn: () => Promise<unknown>, done: string, fail: string) => {
    setBusy(id)
    try {
      await fn()
      await invalidateScopeCache()
      toast.success(done)
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, fail))
    } finally {
      setBusy(null)
    }
  }

  const columns: ColumnDef<ApiScopeTarget>[] = [
    {
      accessorKey: 'pattern',
      header: 'Entry',
      enableHiding: false,
      cell: ({ row }) => {
        const e = row.original
        return (
          <div className="min-w-0 space-y-0.5">
            <code className="break-all rounded bg-muted px-1.5 py-0.5 text-sm">{e.pattern}</code>
            <p className="text-xs text-muted-foreground">Covers {coversText(e)}</p>
          </div>
        )
      },
    },
    {
      accessorKey: 'target_type',
      header: 'Type',
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-muted-foreground">
          {SCOPE_TARGET_TYPE_ICON[row.original.target_type ?? '']}
          <span className="text-sm text-foreground">
            {scopeTargetTypeLabel(row.original.target_type ?? '')}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => {
        const e = row.original
        const st = entryStatus(e)
        const missing = approvalsMissing(e)
        const detail =
          st === 'pending'
            ? `${e.approvals?.length ?? 0} of ${e.approvals_required ?? 0} approvals`
            : st === 'active' || st === 'expired'
              ? expiryText(e.expires_at)
              : undefined
        return (
          <div className="space-y-1">
            <TonePill
              tone={SCOPE_ENTRY_STATUS_TONE[st]}
              label={SCOPE_ENTRY_STATUS_LABEL[st]}
              title={SCOPE_ENTRY_STATUS_HINT[st]}
              detail={detail}
              state={st}
            />
            {st === 'pending' && missing > 0 && !canApproveEntry(e, user?.id) && canApprove && (
              <p className="text-xs text-muted-foreground">
                {e.created_by === user?.id
                  ? 'You requested it: another approver must approve.'
                  : 'You approved it; waiting for another approver.'}
              </p>
            )}
          </div>
        )
      },
    },
    {
      id: 'expiry',
      header: 'Expires',
      cell: ({ row }) => {
        const e = row.original
        if (!e.expires_at) return <span className="text-sm text-muted-foreground">Permanent</span>
        return (
          <span className="inline-flex items-center gap-1 text-sm">
            <CalendarClock className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
            {expiryText(e.expires_at)}
          </span>
        )
      },
    },
    {
      accessorKey: 'max_tier',
      header: 'Deepest probe',
      cell: ({ row }) => (
        <span className="text-sm">{TIER_LABEL[row.original.max_tier ?? 't1'] ?? '-'}</span>
      ),
    },
    {
      accessorKey: 'reason',
      header: 'Reason',
      cell: ({ row }) => {
        const text = row.original.reason || row.original.description
        return text ? (
          <span className="line-clamp-2 text-sm text-muted-foreground" title={text}>
            {text}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground">-</span>
        )
      },
    },
    {
      id: 'decide',
      header: '',
      enableHiding: false,
      cell: ({ row }) => {
        const e = row.original
        if (!canApprove || !canApproveEntry(e, user?.id) || !e.id) return null
        const id = e.id
        return (
          <div className="flex items-center gap-1.5">
            <Button
              size="sm"
              className="h-7 px-2 text-xs"
              disabled={busy !== null}
              onClick={() =>
                void act(id, () => approveScopeTarget(id), 'Approval recorded', 'Approval failed')
              }
            >
              <Check className="me-1 h-3.5 w-3.5" />
              Approve
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 text-xs"
              disabled={busy !== null}
              onClick={() =>
                void act(id, () => rejectScopeTarget(id), 'Entry rejected', 'Reject failed')
              }
            >
              <X className="me-1 h-3.5 w-3.5" />
              Reject
            </Button>
          </div>
        )
      },
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => {
        const e = row.original
        const id = e.id ?? ''
        const st = entryStatus(e)
        const actions: RowAction[] = [
          {
            label: 'Edit',
            icon: Pencil,
            onClick: () => setEditEntry(e),
            permission: Permission.ScopeWrite,
          },
        ]
        if (st === 'active') {
          actions.push({
            label: 'Deactivate',
            icon: PowerOff,
            onClick: () =>
              void act(id, () => setScopeTargetActive(id, false), 'Entry deactivated', 'Failed'),
            permission: Permission.ScopeWrite,
          })
        }
        if (st === 'inactive') {
          actions.push({
            label: 'Activate',
            icon: Power,
            onClick: () =>
              void act(id, () => setScopeTargetActive(id, true), 'Entry activated', 'Failed'),
            disabled: !canApprove,
            disabledReason: 'Activating widens scope: it needs a scope approver.',
          })
        }
        if (st === 'expired' || (st === 'active' && e.expires_at)) {
          actions.push({
            label: `Renew for ${renewDays} days`,
            icon: CalendarClock,
            onClick: () =>
              void act(
                id,
                () => updateScopeTarget(id, { expires_in_days: renewDays }),
                'Entry renewed',
                'Renew failed'
              ),
            disabled: !canApprove,
            disabledReason: 'A later expiry widens scope: it needs a scope approver.',
          })
        }
        actions.push({
          label: 'Remove',
          icon: Trash2,
          onClick: () => setDeleteEntry(e),
          destructive: true,
          separatorBefore: true,
          permission: Permission.ScopeDelete,
        })
        return <DataTableRowActions actions={actions} />
      },
    },
  ]

  const filtersActive = !!query.search || query.type !== 'all' || query.status !== 'all'

  const toolbarStart = (
    <>
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <SearchIcon className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search entries…"
          aria-label="Search scope entries"
          value={searchInput}
          onChange={(e) => onSearchInput(e.target.value)}
          className="h-9 ps-9"
        />
      </div>
      <ScopeTargetTypeSelect
        value={query.type}
        onValueChange={onTypeChange}
        withAll
        className="h-9 w-auto min-w-36"
        aria-label="Filter by type"
      />
      <Select value={query.status} onValueChange={onStatusChange}>
        <SelectTrigger className="h-9 w-auto min-w-36" aria-label="Filter by status">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All statuses</SelectItem>
          {SCOPE_ENTRY_STATUSES.map((s) => (
            <SelectItem key={s} value={s}>
              {SCOPE_ENTRY_STATUS_LABEL[s]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </>
  )

  return (
    <>
      {isLoading && !data ? (
        <div className="space-y-2 rounded-xl border p-3">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={targets}
          getRowId={(r) => r.id ?? r.pattern ?? ''}
          showSearch={false}
          toolbarStart={toolbarStart}
          manualPagination
          rowCount={data?.total ?? 0}
          pagination={{ pageIndex: query.page - 1, pageSize: query.perPage }}
          onPaginationChange={onPagination}
          pageSizeOptions={PAGE_SIZES}
          emptyMessage={filtersActive ? 'No entries match' : 'Nothing is in scope yet'}
          emptyDescription={
            filtersActive
              ? 'Try another search, type or status.'
              : canWrite
                ? 'Add what your organization may probe. Scans refuse every target no entry, seed or verified domain covers.'
                : 'A scope approver adds what your organization may probe.'
          }
        />
      )}

      <ScopeEntryEditDialog entry={editEntry} onOpenChange={(o) => !o && setEditEntry(null)} />

      <ConfirmDialog
        open={!!deleteEntry}
        onOpenChange={(open) => !open && setDeleteEntry(null)}
        title="Remove scope entry?"
        desc={
          <>
            Scans stop reaching what only &quot;{deleteEntry?.pattern}&quot; covers. Assets and
            findings under it stay in the inventory, flagged as out of scope.
          </>
        }
        confirmText="Remove"
        destructive
        isLoading={removing}
        handleConfirm={async () => {
          try {
            await removeTarget()
            await invalidateScopeCache()
            toast.success('Scope entry removed')
            setDeleteEntry(null)
          } catch (err) {
            toast.error(scopeErrorMessage(t, err, 'Could not remove the entry.'))
          }
        }}
      />
    </>
  )
}

export { PAGE_SIZES as SCOPE_PAGE_SIZES }
