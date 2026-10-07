'use client'

/**
 * Scope › Out of scope: the exclusions (RFC-054 §6.2). An exclusion always
 * wins over an entry. Lifting one (deactivate, remove) widens scope, so it
 * needs the exclusion-approve permission and step-up, and the menu says so;
 * putting one back narrows and applies at once. Pending exclusions are
 * decided on the Approvals tab.
 */

import { useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Ban, Power, PowerOff, Search as SearchIcon, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import {
  ActorChip,
  DataTable,
  DataTableRowActions,
  TonePill,
  type PillTone,
  type RowAction,
} from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  deleteScopeExclusion,
  invalidateScopeCache,
  setScopeExclusionActive,
  useScopeExclusionsApi,
} from '../api/use-scope-api'
import type { ApiScopeExclusion } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import { coversText, expiryText } from '../lib/scope-entry'
import {
  scopeKindIcon,
  scopeKindOf,
  ScopeTargetTypeSelect,
  scopeTargetTypeLabel,
  storedTypesFor,
  EXCLUSION_KINDS,
} from './scope-target-type'
import { SCOPE_PAGE_SIZES, type ScopeListQuery } from './scope-entries-table'

const EXCLUSION_STATUS: Record<string, { label: string; tone: PillTone; hint: string }> = {
  active: { label: 'Excluded', tone: 'success', hint: 'Scans skip it.' },
  pending: {
    label: 'Pending approval',
    tone: 'warning',
    hint: 'Scans still reach it until another approver approves the exclusion.',
  },
  inactive: { label: 'Lifted', tone: 'muted', hint: 'Not in effect: scans may reach it.' },
  rejected: { label: 'Rejected', tone: 'destructive', hint: 'Declined: never took effect.' },
  expired: { label: 'Ended', tone: 'muted', hint: 'Its end date passed: scans may reach it.' },
}

/** Statuses the Out of scope tab lists (pending: Approvals; the API takes at most three). */
const OUT_STATUSES = ['active', 'inactive', 'expired']

interface ScopeExclusionsTableProps {
  query: ScopeListQuery
  searchInput: string
  onSearchInput: (v: string) => void
  onKindChange: (v: string) => void
  onPagination: (p: { pageIndex: number; pageSize: number }) => void
}

export function ScopeExclusionsTable({
  query,
  searchInput,
  onSearchInput,
  onKindChange,
  onPagination,
}: ScopeExclusionsTableProps) {
  const { t } = useTranslation()
  const canLift = useHasPermission(Permission.ScopeExclusionsApprove)
  const kind = scopeKindOf(query.kind)
  const { data, isLoading } = useScopeExclusionsApi({
    search: query.search || undefined,
    exclusion_type: kind ? storedTypesFor(kind, 'exclusions') : undefined,
    status: OUT_STATUSES.join(','),
    page: query.page,
    per_page: query.perPage,
  })
  const rows = data?.data ?? []
  const [removing, setRemoving] = useState<ApiScopeExclusion | null>(null)
  const [busy, setBusy] = useState(false)

  const act = async (fn: () => Promise<unknown>, done: string) => {
    try {
      await fn()
      await invalidateScopeCache()
      toast.success(done)
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, 'The change was not saved.'))
    }
  }

  const actionsFor = (x: ApiScopeExclusion): RowAction[] => {
    const id = x.id ?? ''
    const out: RowAction[] = []
    if (x.status === 'active') {
      out.push({
        label: 'Lift (scans may reach it)',
        icon: PowerOff,
        onClick: () => void act(() => setScopeExclusionActive(id, false), `${x.pattern} lifted`),
        disabled: !canLift,
        disabledReason:
          'Lifting an exclusion widens scope: it needs the exclusion approve permission.',
      })
    } else if (x.status === 'inactive') {
      out.push({
        label: 'Put back in effect',
        icon: Power,
        onClick: () =>
          void act(() => setScopeExclusionActive(id, true), `${x.pattern} excluded again`),
        permission: Permission.ScopeWrite,
      })
    }
    out.push({
      label: 'Remove',
      icon: Trash2,
      onClick: () => setRemoving(x),
      destructive: true,
      separatorBefore: out.length > 0,
      permission: Permission.ScopeDelete,
      disabled: x.status === 'active' && !canLift,
      disabledReason:
        'Removing an exclusion in effect widens scope: it needs the exclusion approve permission.',
    })
    return out
  }

  const columns: ColumnDef<ApiScopeExclusion>[] = [
    {
      accessorKey: 'pattern',
      header: 'Out of scope',
      enableHiding: false,
      cell: ({ row }) => (
        <div className="min-w-0 space-y-0.5">
          <code className="break-all rounded bg-muted px-1.5 py-0.5 text-sm">
            {row.original.pattern}
          </code>
          <p className="text-xs text-muted-foreground">
            Covers{' '}
            {coversText({
              pattern: row.original.pattern,
              target_type: row.original.exclusion_type,
            })}
          </p>
        </div>
      ),
    },
    {
      accessorKey: 'exclusion_type',
      header: 'Kind',
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-muted-foreground">
          {scopeKindIcon(row.original.exclusion_type) ?? <Ban className="h-4 w-4" />}
          <span className="text-sm text-foreground">
            {scopeTargetTypeLabel(row.original.exclusion_type ?? '')}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => {
        const s = EXCLUSION_STATUS[row.original.status ?? ''] ?? EXCLUSION_STATUS.inactive
        return (
          <TonePill
            tone={s.tone}
            label={s.label}
            title={s.hint}
            detail={row.original.expires_at ? expiryText(row.original.expires_at) : undefined}
            state={row.original.status}
          />
        )
      },
    },
    {
      accessorKey: 'reason',
      header: 'Reason',
      cell: ({ row }) => (
        <span className="line-clamp-2 text-sm text-muted-foreground" title={row.original.reason}>
          {row.original.reason || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'created_by',
      header: 'Added by',
      cell: ({ row }) => <ActorChip actor={row.original.created_by} at={row.original.created_at} />,
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => (
        <DataTableRowActions
          label={`Actions for ${row.original.pattern}`}
          actions={actionsFor(row.original)}
        />
      ),
    },
  ]

  const filtersActive = !!query.search || query.kind !== 'all'

  return (
    <>
      {isLoading && !data ? (
        <div className="space-y-2 rounded-xl border p-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={rows}
          getRowId={(r) => r.id ?? r.pattern ?? ''}
          showSearch={false}
          toolbarStart={
            <>
              <div className="relative min-w-0 flex-1 sm:max-w-sm">
                <SearchIcon className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search exclusions…"
                  aria-label="Search exclusions"
                  value={searchInput}
                  onChange={(e) => onSearchInput(e.target.value)}
                  className="h-9 ps-9"
                />
              </div>
              <ScopeTargetTypeSelect
                value={kind ?? 'all'}
                onValueChange={onKindChange}
                withAll
                only={EXCLUSION_KINDS}
                className="h-9 w-auto min-w-36"
                aria-label="Filter by kind"
              />
            </>
          }
          manualPagination
          rowCount={data?.total ?? 0}
          pagination={{ pageIndex: query.page - 1, pageSize: query.perPage }}
          onPaginationChange={onPagination}
          pageSizeOptions={SCOPE_PAGE_SIZES}
          emptyMessage={filtersActive ? 'No exclusions match' : 'Nothing is excluded'}
          emptyDescription={
            filtersActive
              ? 'Try another search or kind.'
              : 'Add systems scans must never touch: fragile production hosts, partners’ systems, payment gateways.'
          }
        />
      )}
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title="Remove this exclusion?"
        desc={
          removing?.status === 'active'
            ? `Scans may reach ${removing?.pattern} again once it is removed. You may be asked to confirm your identity.`
            : `The record of ${removing?.pattern} is removed.`
        }
        confirmText="Remove"
        destructive
        isLoading={busy}
        handleConfirm={async () => {
          if (!removing?.id) return
          setBusy(true)
          await act(() => deleteScopeExclusion(removing.id!), `${removing.pattern} removed`)
          setBusy(false)
          setRemoving(null)
        }}
      />
    </>
  )
}
