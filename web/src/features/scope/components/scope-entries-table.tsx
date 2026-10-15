'use client'

/**
 * Scope › In scope: the scope entries (RFC-054 §6.1, research/53 §4.2).
 *
 * Each row says what the entry covers, whether it authorizes probes now
 * (pill: Active, Pending n of m, Expires in…, Expired, Inactive, Rejected),
 * the deepest probe it allows, why it exists and who added it. There is no
 * inline toggle (SC5): status changes are labelled actions in the row menu,
 * and a widening action says it may need approval. Pending entries are
 * listed with their pill and decided on the Approvals tab; where approvals
 * are no longer required a leftover pending entry can be put in effect.
 */

import { useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { useRouter } from 'next/navigation'
import {
  CalendarClock,
  GitBranch,
  Inbox,
  KeyRound,
  Pencil,
  Power,
  PowerOff,
  Search as SearchIcon,
  Trash2,
} from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'

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
import {
  ActorChip,
  DataTable,
  DataTableRowActions,
  TonePill,
  type RowAction,
} from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  invalidateScopeCache,
  setScopeTargetActive,
  updateScopeTarget,
  useDeleteScopeTargetApi,
  useScopeSettingsApi,
  useScopeTargetsApi,
} from '../api/use-scope-api'
import type { ApiScopeTarget } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import {
  coversText,
  entryStatus,
  expiryText,
  SCOPE_ENTRY_STATUS_HINT,
  SCOPE_ENTRY_STATUS_LABEL,
  SCOPE_ENTRY_STATUS_TONE,
  TIER_LABEL,
  type ScopeEntryStatus,
} from '../lib/scope-entry'
import { ScopeEntryEditDialog } from './scope-entry-edit-dialog'
import {
  scopeKindIcon,
  scopeKindOf,
  ScopeTargetTypeSelect,
  scopeTargetTypeLabel,
  storedTypesFor,
} from './scope-target-type'

export const SCOPE_PAGE_SIZES = [10, 20, 30, 50, 100]

/** Where scan approval governance (Off, On, Strict) is set. */
const SCAN_APPROVAL_HREF = '/settings/scanning/scan-approval'

const PER_SCAN_HINT =
  'Scan intensity is chosen on each scan. Entry ceilings apply only in Strict governance.'

/**
 * Statuses the In scope tab lists. Every live entry is listed, pending ones
 * too (with their pill), so an entry is never invisible; they are decided on
 * the Approvals tab. Rejected requests are reached through the status filter.
 */
export const IN_SCOPE_DEFAULT: ScopeEntryStatus[] = ['active', 'pending', 'expired', 'inactive']
export const IN_SCOPE_STATUSES: ScopeEntryStatus[] = [
  'active',
  'pending',
  'expired',
  'inactive',
  'rejected',
]

export interface ScopeListQuery {
  search: string
  kind: string
  status: string
  page: number
  perPage: number
}

interface ScopeEntriesTableProps {
  query: ScopeListQuery
  searchInput: string
  onSearchInput: (v: string) => void
  onKindChange: (v: string) => void
  onStatusChange: (v: string) => void
  onPagination: (p: { pageIndex: number; pageSize: number }) => void
  /** Shown when nothing is in scope yet (onboarding). */
  emptyAction?: React.ReactNode
}

export function ScopeEntriesTable({
  query,
  searchInput,
  onSearchInput,
  onKindChange,
  onStatusChange,
  onPagination,
  emptyAction,
}: ScopeEntriesTableProps) {
  const { t } = useTranslation()
  const canApprove = useHasPermission(Permission.ScopeApprove)
  const router = useRouter()
  const { data: settings } = useScopeSettingsApi()
  const renewDays = settings?.one_off_max_days ?? 7
  // Unknown (still loading) counts as Strict.
  const needsApproval = settings?.approval_policy?.entries_need_approval ?? true
  // Entry tier ceilings limit probes only under Strict scan approval;
  // elsewhere each scan picks its intensity. Unknown counts as Strict.
  const tierCeilings = settings?.approval_policy?.tier_ceilings ?? true
  const kind = scopeKindOf(query.kind)

  const { data, isLoading } = useScopeTargetsApi({
    search: query.search || undefined,
    target_type: kind ? storedTypesFor(kind) : undefined,
    status: query.status !== 'all' ? query.status : IN_SCOPE_DEFAULT.join(','),
    page: query.page,
    per_page: query.perPage,
  })
  const entries = data?.data ?? []

  const [editEntry, setEditEntry] = useState<ApiScopeTarget | null>(null)
  const [deleteEntry, setDeleteEntry] = useState<ApiScopeTarget | null>(null)
  const { trigger: removeTarget, isMutating: removing } = useDeleteScopeTargetApi(
    deleteEntry?.id ?? ''
  )

  const act = async (fn: () => Promise<unknown>, done: string, fail: string) => {
    try {
      await fn()
      await invalidateScopeCache()
      toast.success(done)
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, fail))
    }
  }

  const ciTrustPage = '/ci-cd?tab=setup&section=trust'

  const actionsFor = (e: ApiScopeTarget): RowAction[] => {
    const id = e.id ?? ''
    const st = entryStatus(e)
    if (ciTrustManaged(e)) {
      // A CI trust keeps this entry: it changes through the trust, and an
      // exclusion keeps one repository out.
      return [
        {
          label: t('scope.ciTrust.openTrust', 'Open the CI trust'),
          icon: KeyRound,
          onClick: () => router.push(ciTrustPage),
        },
      ]
    }
    const out: RowAction[] = [
      {
        label: 'Edit',
        icon: Pencil,
        onClick: () => setEditEntry(e),
        permission: Permission.ScopeWrite,
      },
    ]
    if (st === 'active') {
      out.push({
        label: 'Deactivate',
        icon: PowerOff,
        onClick: () =>
          void act(() => setScopeTargetActive(id, false), `${e.pattern} deactivated`, 'Failed'),
        permission: Permission.ScopeWrite,
      })
    }
    if (st === 'pending' && needsApproval) {
      out.push({
        label: t('scope.existing.openApprovals', 'Open approvals'),
        icon: Inbox,
        onClick: () => router.push('/scope?tab=approvals'),
      })
    }
    if (st === 'pending' && !needsApproval) {
      out.push({
        label: t('scope.existing.putInEffect', 'Put in effect'),
        icon: Power,
        onClick: () =>
          void act(
            () => setScopeTargetActive(id, true),
            t('scope.existing.done', '{pattern} updated', { pattern: e.pattern ?? '' }),
            t('scope.existing.failed', 'The change was not saved.')
          ),
        permission: Permission.ScopeWrite,
      })
    }
    if (st === 'inactive') {
      out.push({
        label: 'Activate (may need approval)',
        icon: Power,
        onClick: () =>
          void act(() => setScopeTargetActive(id, true), `${e.pattern} activated`, 'Failed'),
        disabled: !canApprove,
        disabledReason: 'Activating widens scope: only a scope approver can do it.',
      })
    }
    if (st === 'expired' || (st === 'active' && e.expires_at)) {
      out.push({
        label: `Extend by ${renewDays} days (may need approval)`,
        icon: CalendarClock,
        onClick: () =>
          void act(
            () => updateScopeTarget(id, { expires_in_days: renewDays }),
            `${e.pattern} extended`,
            'Extend failed'
          ),
        disabled: !canApprove,
        disabledReason: 'A later expiry widens scope: only a scope approver can do it.',
      })
    }
    if (e.target_type === 'repository') {
      out.push({
        label: t('scope.ciTrust.setUp', 'Set up CI for these repositories'),
        icon: GitBranch,
        onClick: () => router.push(ciTrustPage),
        permission: Permission.CIWrite,
      })
    }
    out.push({
      label: 'Remove',
      icon: Trash2,
      onClick: () => setDeleteEntry(e),
      destructive: true,
      separatorBefore: true,
      permission: Permission.ScopeDelete,
    })
    return out
  }

  const columns: ColumnDef<ApiScopeTarget>[] = [
    {
      accessorKey: 'pattern',
      header: 'Entry',
      enableHiding: false,
      cell: ({ row }) => (
        <div className="min-w-0 space-y-0.5">
          <code className="break-all rounded bg-muted px-1.5 py-0.5 text-sm">
            {row.original.pattern}
          </code>
          <p className="text-xs text-muted-foreground">Covers {coversText(row.original)}</p>
          <ManagedByCITrust entry={row.original} />
        </div>
      ),
    },
    {
      accessorKey: 'target_type',
      header: 'Kind',
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-muted-foreground">
          {scopeKindIcon(row.original.target_type)}
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
        return (
          <TonePill
            tone={SCOPE_ENTRY_STATUS_TONE[st]}
            label={SCOPE_ENTRY_STATUS_LABEL[st]}
            title={SCOPE_ENTRY_STATUS_HINT[st]}
            detail={e.expires_at ? expiryText(e.expires_at) : undefined}
            state={st}
          />
        )
      },
    },
    {
      accessorKey: 'max_tier',
      header: t('scope.entries.deepestProbe', 'Deepest probe'),
      cell: ({ row }) =>
        tierCeilings ? (
          <span className="text-sm">
            {t(
              `scope.tier.label.${row.original.max_tier ?? 't1'}`,
              TIER_LABEL[row.original.max_tier ?? 't1'] ?? '-'
            )}
          </span>
        ) : (
          <span
            className="text-sm text-muted-foreground"
            title={t('scope.entries.perScanHint', PER_SCAN_HINT)}
          >
            {t('scope.entries.perScan', 'Set per scan')}
          </span>
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

  const filtersActive = !!query.search || query.kind !== 'all' || query.status !== 'all'

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
        value={kind ?? 'all'}
        onValueChange={onKindChange}
        withAll
        className="h-9 w-auto min-w-36"
        aria-label="Filter by kind"
      />
      <Select value={query.status} onValueChange={onStatusChange}>
        <SelectTrigger className="h-9 w-auto min-w-36" aria-label="Filter by status">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All statuses</SelectItem>
          {IN_SCOPE_STATUSES.map((s) => (
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
      ) : !filtersActive && entries.length === 0 && emptyAction ? (
        emptyAction
      ) : (
        <div className="space-y-2">
          {!tierCeilings && (
            <p className="text-xs text-muted-foreground" data-testid="scope-tier-per-scan-note">
              {t('scope.entries.perScanHint', PER_SCAN_HINT)}{' '}
              <Link href={SCAN_APPROVAL_HREF} className="text-primary hover:underline">
                {t('scope.entries.governanceLink', 'Scan approval settings')}
              </Link>
            </p>
          )}
          <DataTable
            columns={columns}
            data={entries}
            getRowId={(r) => r.id ?? r.pattern ?? ''}
            showSearch={false}
            toolbarStart={toolbarStart}
            manualPagination
            rowCount={data?.total ?? 0}
            pagination={{ pageIndex: query.page - 1, pageSize: query.perPage }}
            onPaginationChange={onPagination}
            pageSizeOptions={SCOPE_PAGE_SIZES}
            emptyMessage={filtersActive ? 'No entries match' : 'Nothing is in scope yet'}
            emptyDescription={
              filtersActive
                ? 'Try another search, kind or status.'
                : 'Scans refuse every internet target no entry covers.'
            }
          />
        </div>
      )}

      <ScopeEntryEditDialog entry={editEntry} onOpenChange={(o) => !o && setEditEntry(null)} />

      <ConfirmDialog
        open={!!deleteEntry}
        onOpenChange={(open) => !open && setDeleteEntry(null)}
        title={t('confirm.scopeEntry.removeTitle', 'Remove {pattern} from scope?', {
          pattern: deleteEntry?.pattern ?? '',
        })}
        desc={t(
          'confirm.scopeEntry.removeDesc',
          'Scans stop reaching what only this entry covers. Assets under it and their findings and history stay, flagged as out of scope. Adding it back needs approval.'
        )}
        confirmText={t('confirm.remove', 'Remove')}
        destructive
        isLoading={removing}
        handleConfirm={async () => {
          try {
            await removeTarget()
            await invalidateScopeCache()
            toast.success(`${deleteEntry?.pattern} removed from scope`)
            setDeleteEntry(null)
          } catch (err) {
            toast.error(scopeErrorMessage(t, err, 'Could not remove the entry.'))
          }
        }}
      />
    </>
  )
}

/** A CI trust still manages the entry (it changes through the trust). */
export function ciTrustManaged(e: ApiScopeTarget): boolean {
  return e.origin === 'ci_trust' && (e.managed_by?.length ?? 0) > 0
}

/** The CI trusts that claim the entry, with the verified-run evidence. */
function ManagedByCITrust({ entry }: { entry: ApiScopeTarget }) {
  const { t } = useTranslation()
  const trusts = entry.managed_by ?? []
  if (trusts.length === 0) return null
  return (
    <p className="text-xs text-muted-foreground" data-testid="scope-managed-by">
      {trusts.map((m, i) => (
        <span key={m.trust_config_id ?? i}>
          {i > 0 && ' · '}
          {t('scope.ciTrust.managedBy', 'Managed by the CI trust {name}', {
            name: m.trust_name ?? '',
          })}
          {m.seen_at
            ? ` (${t('scope.ciTrust.seen', 'seen in a verified pipeline')})`
            : ` (${t('scope.ciTrust.notSeen', 'no verified pipeline yet')})`}
        </span>
      ))}
    </p>
  )
}
