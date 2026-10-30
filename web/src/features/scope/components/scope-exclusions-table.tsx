'use client'

/**
 * Scope › Out of scope: the exclusions (RFC-054 §6.2). An exclusion always
 * wins over an entry. Lifting one (deactivate, remove) widens scope, so it
 * needs step-up and, in the Strict scan approval mode, the exclusion-approve
 * permission (in Off and On scope:write is enough, RFC-073 §6); the menu
 * says so;
 * putting one back narrows and applies at once. Pending exclusions are
 * decided on the Approvals tab.
 *
 * A path exclusion (RFC-056 §5) also shows its testing mode; "Testing
 * mode…" opens the two-step dialog (exclusion approvers only, step-up).
 */

import { useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { useRouter } from 'next/navigation'
import { Ban, FlaskConical, Inbox, Power, PowerOff, Route, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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
  useScopeSettingsApi,
} from '../api/use-scope-api'
import type { ApiScopeExclusion } from '../api/scope-api.types'
import { scopeExclusionKindLabel } from '../lib/exclusion-kind'
import { scopeErrorMessage } from '../lib/scope-codes'
import { coversText, expiryText } from '../lib/scope-entry'
import {
  effectiveTesting,
  isPathExclusion,
  methodsText,
  pathRuleLabel,
  TESTING_HINT,
  TESTING_LABEL,
  TESTING_TONE,
  type PathExclusion,
} from '../lib/path-exclusion'
import { ExclusionTestingDialog } from './exclusion-testing-dialog'
import {
  scopeKindIcon,
  scopeKindOf,
  ScopeTargetTypeSelect,
  scopeTargetTypeLabel,
  storedTypesFor,
  EXCLUSION_KINDS,
} from './scope-target-type'
import { SCOPE_PAGE_SIZES, type ScopeListQuery } from './scope-entries-table'

/** Labels and hints are English fallbacks; the keys are scope.exclusion.status.<status>.label/hint. */
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

/**
 * Statuses the Out of scope tab lists: every exclusion, pending and rejected
 * ones too (with their pill), so one is never invisible; pending ones are
 * decided on the Approvals tab.
 */
const OUT_STATUSES = ['active', 'pending', 'inactive', 'expired', 'rejected']

interface ScopeExclusionsTableProps {
  query: ScopeListQuery
  searchInput: string
  onSearchInput: (v: string) => void
  onKindChange: (v: string) => void
  onStatusChange: (v: string) => void
  onPagination: (p: { pageIndex: number; pageSize: number }) => void
  /** Controls the page puts first in the toolbar (which scope list is shown). */
  leading?: React.ReactNode
}

export function ScopeExclusionsTable({
  query,
  searchInput,
  onSearchInput,
  onKindChange,
  onStatusChange,
  onPagination,
  leading,
}: ScopeExclusionsTableProps) {
  const { t } = useTranslation()
  const canApproveExclusions = useHasPermission(Permission.ScopeExclusionsApprove)
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const router = useRouter()
  const { data: settings } = useScopeSettingsApi()
  // Lifting needs the approval permission only in Strict (unknown: Strict).
  const needsReview = settings?.approval_policy?.entries_need_approval ?? true
  const canLift = canApproveExclusions || (!needsReview && canWrite)
  const kind = scopeKindOf(query.kind)
  const { data, isLoading } = useScopeExclusionsApi({
    search: query.search || undefined,
    exclusion_type: kind ? storedTypesFor(kind, 'exclusions') : undefined,
    // The strip's "Exclusions in effect" opens this list with status=active.
    status: query.status && query.status !== 'all' ? query.status : OUT_STATUSES.join(','),
    page: query.page,
    per_page: query.perPage,
  })
  const rows = data?.data ?? []
  const [removing, setRemoving] = useState<ApiScopeExclusion | null>(null)
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState<PathExclusion | null>(null)

  const statusLabel = (s: string) =>
    t(`scope.exclusion.status.${s}.label`, EXCLUSION_STATUS[s]?.label ?? s)

  const act = async (fn: () => Promise<unknown>, done: string) => {
    try {
      await fn()
      await invalidateScopeCache()
      toast.success(done)
    } catch (err) {
      toast.error(
        scopeErrorMessage(t, err, t('scope.existing.failed', 'The change was not saved.'))
      )
    }
  }

  const actionsFor = (x: ApiScopeExclusion): RowAction[] => {
    const id = x.id ?? ''
    const out: RowAction[] = []
    if (isPathExclusion(x) && x.status === 'active') {
      out.push({
        label: t('scope.exclusion.act.testing', 'Testing mode…'),
        icon: FlaskConical,
        onClick: () => setTesting(x as PathExclusion),
        disabled: !canApproveExclusions,
        disabledReason: t(
          'scope.exclusion.testingNeedsApprover',
          'Changing how a path may be tested needs the exclusion approve permission.'
        ),
      })
    }
    if (x.status === 'active') {
      out.push({
        label: t('scope.exclusion.act.lift', 'Lift (scans may reach it)'),
        icon: PowerOff,
        onClick: () =>
          void act(
            () => setScopeExclusionActive(id, false),
            t('scope.exclusion.toast.lifted', '{pattern} lifted.', { pattern: x.pattern ?? '' })
          ),
        disabled: !canLift,
        disabledReason: needsReview
          ? t(
              'scope.exclusion.liftNeedsApprover',
              'Lifting an exclusion widens scope: it needs the exclusion approve permission.'
            )
          : t(
              'scope.exclusion.liftNeedsWrite',
              'Lifting an exclusion needs the scope write permission.'
            ),
      })
    } else if (x.status === 'pending' && needsReview) {
      out.push({
        label: t('scope.existing.openApprovals', 'Open approvals'),
        icon: Inbox,
        onClick: () => router.push('/scope?tab=approvals'),
      })
    } else if (x.status === 'pending') {
      out.push({
        label: t('scope.existing.putInEffect', 'Put in effect'),
        icon: Power,
        onClick: () =>
          void act(
            () => setScopeExclusionActive(id, true),
            t('scope.existing.done', '{pattern} updated', { pattern: x.pattern ?? '' })
          ),
        permission: Permission.ScopeWrite,
      })
    } else if (x.status === 'inactive') {
      out.push({
        label: t('scope.exclusion.act.putBack', 'Put back in effect'),
        icon: Power,
        onClick: () =>
          void act(
            () => setScopeExclusionActive(id, true),
            t('scope.exclusion.toast.excludedAgain', '{pattern} excluded again.', {
              pattern: x.pattern ?? '',
            })
          ),
        permission: Permission.ScopeWrite,
      })
    }
    out.push({
      label: t('confirm.remove', 'Remove'),
      icon: Trash2,
      onClick: () => setRemoving(x),
      destructive: true,
      separatorBefore: out.length > 0,
      permission: Permission.ScopeDelete,
      disabled: x.status === 'active' && needsReview && !canApproveExclusions,
      disabledReason: t(
        'scope.exclusion.removeNeedsApprover',
        'Removing an exclusion in effect widens scope: it needs the exclusion approve permission.'
      ),
    })
    return out
  }

  const columns: ColumnDef<ApiScopeExclusion>[] = [
    {
      accessorKey: 'pattern',
      header: t('scope.col.outOfScope', 'Out of scope'),
      enableHiding: false,
      cell: ({ row }) => {
        const x = row.original as PathExclusion
        if (isPathExclusion(x))
          return (
            <div className="min-w-0 space-y-0.5">
              <code className="break-all rounded bg-muted px-1.5 py-0.5 text-sm">
                {pathRuleLabel(x)}
              </code>
              <p className="text-xs text-muted-foreground">
                {t(
                  'scope.exclusion.blocks',
                  'Blocks {methods} under this path. The rest of the host stays in scope.',
                  {
                    methods: x.methods?.length
                      ? methodsText(x.methods)
                      : t('scope.exclusion.everyMethod', 'every method'),
                  }
                )}
              </p>
            </div>
          )
        return (
          <div className="min-w-0 space-y-0.5">
            <code className="break-all rounded bg-muted px-1.5 py-0.5 text-sm">{x.pattern}</code>
            <p className="text-xs text-muted-foreground">
              {t('scope.col.covers', 'Covers {what}', {
                what: coversText({ pattern: x.pattern, target_type: x.exclusion_type }),
              })}
            </p>
          </div>
        )
      },
    },
    {
      accessorKey: 'exclusion_type',
      header: t('scope.col.kind', 'Kind'),
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-muted-foreground">
          {isPathExclusion(row.original) ? (
            <Route className="h-4 w-4" />
          ) : (
            (scopeKindIcon(row.original.exclusion_type) ?? <Ban className="h-4 w-4" />)
          )}
          <span className="text-sm text-foreground">
            {isPathExclusion(row.original)
              ? t('scope.exclusion.webPath', 'Web path')
              : scopeTargetTypeLabel(row.original.exclusion_type ?? '')}
          </span>
        </div>
      ),
    },
    {
      id: 'why',
      header: t('scope.col.why', 'Why'),
      cell: ({ row }) => (
        <span className="text-sm" data-testid="exclusion-why">
          {scopeExclusionKindLabel(t, (row.original as { kind?: string }).kind)}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: t('scope.col.status', 'Status'),
      cell: ({ row }) => {
        const x = row.original as PathExclusion
        const s = EXCLUSION_STATUS[x.status ?? ''] ?? EXCLUSION_STATUS.inactive
        const mode = effectiveTesting(x)
        return (
          <div className="flex flex-col items-start gap-1">
            <TonePill
              tone={s.tone}
              label={statusLabel(x.status ?? 'inactive')}
              title={t(`scope.exclusion.status.${x.status ?? 'inactive'}.hint`, s.hint)}
              detail={x.expires_at ? expiryText(x.expires_at) : undefined}
              state={x.status}
            />
            {isPathExclusion(x) && x.status === 'active' && (
              <TonePill
                tone={TESTING_TONE[mode]}
                label={t('scope.exclusion.testingPill', 'Testing: {mode}', {
                  mode: t(`scope.testing.label.${mode}`, TESTING_LABEL[mode]).toLowerCase(),
                })}
                title={t(`scope.testing.hint.${mode}`, TESTING_HINT[mode])}
                detail={
                  mode !== 'blocked' && x.testing_until
                    ? expiryText(x.testing_until).replace('Expires in', 'Blocked again in')
                    : undefined
                }
                state={`testing-${mode}`}
              />
            )}
          </div>
        )
      },
    },
    {
      accessorKey: 'reason',
      header: t('scope.col.reason', 'Reason'),
      cell: ({ row }) => (
        <span className="line-clamp-2 text-sm text-muted-foreground" title={row.original.reason}>
          {row.original.reason || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'created_by',
      header: t('scope.col.addedBy', 'Added by'),
      cell: ({ row }) => <ActorChip actor={row.original.created_by} at={row.original.created_at} />,
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => (
        <DataTableRowActions
          label={t('scope.col.actionsFor', 'Actions for {pattern}', {
            pattern: row.original.pattern ?? '',
          })}
          actions={actionsFor(row.original)}
        />
      ),
    },
  ]

  // The strip's "Exclusions in effect" sets status=active, so status counts here.
  const filtersActive = !!query.search || query.kind !== 'all' || query.status !== 'all'

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
          search={{
            value: searchInput,
            onChange: onSearchInput,
            placeholder: t('scope.exclusion.search', 'Search exclusions…'),
            label: t('scope.exclusion.searchLabel', 'Search exclusions'),
          }}
          toolbarStart={
            <>
              {leading}
              <ScopeTargetTypeSelect
                value={kind ?? 'all'}
                onValueChange={onKindChange}
                withAll
                only={EXCLUSION_KINDS}
                className="h-9 w-auto min-w-36"
                aria-label={t('scope.filter.kind', 'Filter by kind')}
              />
              <Select value={query.status} onValueChange={onStatusChange}>
                <SelectTrigger
                  className="h-9 w-auto min-w-36"
                  aria-label={t('scope.filter.status', 'Filter by status')}
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">
                    {t('scope.filter.allStatuses', 'All statuses')}
                  </SelectItem>
                  {OUT_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {statusLabel(s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </>
          }
          manualPagination
          rowCount={data?.total ?? 0}
          pagination={{ pageIndex: query.page - 1, pageSize: query.perPage }}
          onPaginationChange={onPagination}
          pageSizeOptions={SCOPE_PAGE_SIZES}
          emptyMessage={
            filtersActive
              ? t('scope.exclusion.noMatch', 'No exclusions match')
              : t('scope.exclusion.emptyTitle', 'Nothing is excluded')
          }
          emptyDescription={
            filtersActive
              ? t('scope.filter.tryAnother', 'Try another search, kind or status.')
              : t(
                  'scope.exclusion.emptyDescription',
                  'Add systems scans must never touch: fragile production hosts, partners’ systems, payment gateways.'
                )
          }
        />
      )}
      <ExclusionTestingDialog exclusion={testing} onOpenChange={(o) => !o && setTesting(null)} />
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t('confirm.scopeExclusion.removeTitle', 'Remove the exclusion {pattern}?', {
          pattern: removing?.pattern ?? '',
        })}
        desc={
          removing?.status === 'active'
            ? t(
                'confirm.scopeExclusion.removeActiveDesc',
                'Scans may reach {pattern} again once it is removed. You may be asked to confirm your identity.',
                { pattern: removing?.pattern ?? '' }
              )
            : t('confirm.scopeExclusion.removeRecordDesc', 'The record of {pattern} is removed.', {
                pattern: removing?.pattern ?? '',
              })
        }
        confirmText={t('confirm.remove', 'Remove')}
        destructive
        isLoading={busy}
        handleConfirm={async () => {
          if (!removing?.id) return
          setBusy(true)
          await act(
            () => deleteScopeExclusion(removing.id!),
            t('scope.exclusion.toast.removed', '{pattern} removed.', {
              pattern: removing.pattern ?? '',
            })
          )
          setBusy(false)
          setRemoving(null)
        }}
      />
    </>
  )
}
