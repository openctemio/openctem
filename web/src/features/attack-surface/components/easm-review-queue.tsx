'use client'

/**
 * The attribution review queue (RFC-036 §6.4): names the platform found
 * (Certificate Transparency, recon) but could not prove are the
 * organisation's. A reviewer confirms them (scans may then reach them),
 * marks them as someone else's, or keeps them passive, one by one or in bulk.
 *
 * Every row and count comes from GET /api/v1/easm/candidates, which the
 * server narrows to the viewer's data scope. Decisions go through
 * POST /api/v1/easm/candidates/decisions (assets:write), are audited per
 * asset, and an asset the viewer may not act on comes back as not found.
 */

import { useMemo, useState } from 'react'
import { useUrlFilter } from '@/hooks/use-url-param'
import type { ColumnDef } from '@tanstack/react-table'
import { Ban, Check, Eye, Loader2, Network } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { DataTable, ErrorState, FilterSelect, RelativeTime } from '@/features/shared'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useListParams } from '@/hooks/use-list-params'
import type { EASMConfirmScopeResult, EASMReviewItem } from '@/lib/api/generated'
import { del } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { UNDO_TOAST_MS } from '@/lib/undo-toast'
import { invalidateScopeCache } from '@/features/scope/api/use-scope-api'
import { usePermissions, Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import {
  ATTRIBUTION_STATE_CLASS,
  attributionStateLabel,
  describeEvidence,
  reviewHintText,
  reviewNetworkText,
  type AttributionDecision,
  type AttributionEvidence,
  type AttributionState,
} from '@/features/assets/lib/attribution'
import { AssetPeekLink } from '@/features/assets/components/asset-peek'
import { useDecideReviewBatch, useEASMReviewQueue } from '../hooks/use-easm-review'
import { useEASMSummary } from '../hooks/use-easm-summary'
import { reviewReasonLabel } from '../lib/review-reasons'
import { ScopeEntryDialog, ScopeFixButtons, type ScopeEntryDraft } from '@/features/scope'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The queue views: what is waiting, and what was rejected (for undo). A
 * State filter at the start of the toolbar (research/249 R21), never a tab
 * row; `?tab=rejected` keeps old links working.
 */
export const REVIEW_VIEWS: { id: string; label: string; states: AttributionState[] }[] = [
  { id: 'review', label: 'Awaiting a decision', states: ['needs_review', 'candidate'] },
  { id: 'rejected', label: 'Not ours', states: ['rejected'] },
]

const DECISIONS: { state: AttributionDecision; label: string; icon: React.ElementType }[] = [
  { state: 'confirmed', label: 'Ours: add to scope', icon: Check },
  { state: 'rejected', label: 'Not ours', icon: Ban },
  { state: 'dependency', label: 'Dependency', icon: Network },
  { state: 'monitor_only', label: 'Monitor only', icon: Eye },
]

type TFn = ReturnType<typeof useTranslation>['t']

/** "+ 3 services, 2 certificates": the children that follow a host. */
export function childrenText(t: TFn, children: Record<string, number> | undefined): string {
  const parts = Object.entries(children ?? {})
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([type, n]) =>
      n === 1
        ? t(`attackSurface.queue.child.${type}.one`, `1 ${type.replace(/_/g, ' ')}`, { count: n })
        : t(`attackSurface.queue.child.${type}.other`, `{count} ${type.replace(/_/g, ' ')}`, {
            count: n,
          })
    )
  return parts.length > 0 ? `+ ${parts.join(', ')}` : ''
}

/**
 * What a confirmation did to scope, as one toast; the entries it added can be
 * removed again from the toast (Undo deletes exactly those entries).
 */
export function reportConfirmScope(
  t: TFn,
  scope: EASMConfirmScopeResult | undefined,
  onUndone?: () => void,
  /** The caller may delete scope entries (the Undo calls DELETE /scope/targets). */
  canUndo = true
) {
  if (!scope) return
  if (scope.skipped === 'needs_scope_write') {
    toast.info(
      t(
        'attackSurface.queue.scopeSkipped.needs_scope_write',
        'Recorded as yours. Adding them to scope needs permission to edit scope.'
      )
    )
    return
  }
  const added = (scope.entries ?? []).filter((e) => e.outcome === 'added' && e.target_id)
  const refused = (scope.entries ?? []).filter((e) => e.outcome === 'refused')
  if (refused.length > 0) {
    toast.warning(
      t(
        'attackSurface.queue.scopeRefused',
        '{count} could not be added to scope ({first}: {code})',
        {
          count: refused.length,
          first: refused[0].pattern ?? refused[0].name ?? '',
          code: refused[0].code ?? '',
        }
      )
    )
  }
  if (added.length === 0) return
  const ids = added.map((e) => e.target_id as string)
  toast.success(
    added.length === 1
      ? t('attackSurface.queue.scopeAdded.one', 'Added {pattern} to scope', {
          pattern: added[0].pattern ?? '',
        })
      : t('attackSurface.queue.scopeAdded.other', 'Added {count} entries to scope', {
          count: added.length,
        }),
    {
      duration: UNDO_TOAST_MS,
      action: !canUndo
        ? undefined
        : {
            label: t('attackSurface.queue.undo', 'Undo'),
            onClick: () => {
              void (async () => {
                try {
                  await Promise.all(
                    ids.map((id) => del<void>(`/api/v1/scope/targets/${encodeURIComponent(id)}`))
                  )
                  await invalidateScopeCache()
                  toast.success(t('attackSurface.queue.undone', 'Removed the scope entries again'))
                  onUndone?.()
                } catch (e) {
                  toast.error(
                    getErrorMessage(
                      e,
                      t('attackSurface.queue.undoFailed', 'Could not remove the entries')
                    )
                  )
                }
              })()
            },
          },
    }
  )
}

const PAGE_SIZE = 50

function stateOf(item: EASMReviewItem): AttributionState {
  return (item.state ?? 'candidate') as AttributionState
}

export function EASMReviewQueue() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canDecide = can(Permission.AssetsWrite)
  const canAddScope = can(Permission.ScopeWrite)
  // The tab is in the URL (?tab=rejected) so a view can be linked to.
  const [tabParam, setTabParam] = useUrlFilter('tab', REVIEW_VIEWS[0].id)
  const view = REVIEW_VIEWS.some((v) => v.id === tabParam) ? tabParam : REVIEW_VIEWS[0].id
  // The Review page opens this list for ?all=1, ?tab= or ?reason=: going
  // back to the default state clears ?tab=, so the list keeps itself open.
  const [, setAllParam] = useUrlFilter('all', '0')
  const setView = (v: string) => {
    setAllParam('1')
    setTabParam(v)
  }
  const [searchInput, setSearchInput] = useUrlFilter('q', '')
  const search = useSearchQuery(searchInput).term
  const { pagination, setPagination, setPage } = useListParams({ defaultPageSize: PAGE_SIZE })
  const [selected, setSelected] = useState<EASMReviewItem[]>([])
  const [resetKey, setResetKey] = useState(0)
  // Filter by the rule that queued the names (RFC-054 §6.6), in the URL.
  const [reasonParam, setReasonParam] = useUrlFilter('reason', 'all')
  const reason = reasonParam === 'all' ? undefined : reasonParam
  const { summary } = useEASMSummary()
  const reasons = Object.entries(summary?.attribution?.review_by_reason ?? {}).filter(
    ([, n]) => n > 0
  )
  const [addDraft, setAddDraft] = useState<ScopeEntryDraft | null>(null)

  const states = REVIEW_VIEWS.find((v) => v.id === view)?.states ?? REVIEW_VIEWS[0].states
  const { page, error, isLoading, mutate } = useEASMReviewQueue({
    states,
    search: search.trim() || undefined,
    reason: view === 'review' ? reason : undefined,
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  })
  const { decide, saving } = useDecideReviewBatch()

  const clearSelection = () => {
    setSelected([])
    setResetKey((k) => k + 1)
  }

  const apply = async (state: AttributionDecision) => {
    const ids = selected.map((s) => s.asset_id).filter((id): id is string => !!id)
    if (ids.length === 0) return
    try {
      const res = await decide(ids, state)
      const done = res.decided?.length ?? 0
      const missed = res.not_found?.length ?? 0
      const label = attributionStateLabel(t, state)
      if (done > 0)
        toast.success(
          done === 1
            ? t('attackSurface.queue.decided.one', '1 asset set to {state}', { state: label })
            : t('attackSurface.queue.decided.other', '{count} assets set to {state}', {
                count: done,
                state: label,
              })
        )
      if (missed > 0)
        toast.warning(
          t('attackSurface.queue.notFound', '{count} not changed: no longer available to you', {
            count: missed,
          })
        )
      reportConfirmScope(t, res.scope, () => void mutate(), can(Permission.ScopeDelete))
      clearSelection()
      void mutate()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('attackSurface.queue.decideFailed', 'Could not save the decision'))
      )
    }
  }

  const columns = useMemo<ColumnDef<EASMReviewItem>[]>(() => {
    const cols: ColumnDef<EASMReviewItem>[] = []
    if (canDecide) {
      cols.push({
        id: 'select',
        header: ({ table }) => (
          <Checkbox
            checked={
              table.getIsAllPageRowsSelected() ||
              (table.getIsSomePageRowsSelected() && 'indeterminate')
            }
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label={t('attackSurface.queue.selectAll', 'Select all')}
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label={t('attackSurface.queue.selectRow', 'Select {name}', {
              name: row.original.name ?? '',
            })}
          />
        ),
        enableSorting: false,
        enableHiding: false,
      })
    }
    cols.push(
      {
        id: 'name',
        header: t('attackSurface.queue.col.name', 'Name'),
        cell: ({ row }) => {
          const kids = childrenText(t, row.original.children)
          return (
            <div className="min-w-0">
              <AssetPeekLink assetId={row.original.asset_id} className="font-medium">
                {row.original.name}
              </AssetPeekLink>
              {kids && <p className="text-xs text-muted-foreground">{kids}</p>}
            </div>
          )
        },
      },
      {
        id: 'state',
        header: t('attackSurface.queue.col.state', 'State'),
        cell: ({ row }) => {
          const st = stateOf(row.original)
          return (
            <Badge variant="outline" className={cn('border-0', ATTRIBUTION_STATE_CLASS[st])}>
              {attributionStateLabel(t, st)}
            </Badge>
          )
        },
      },
      {
        id: 'confidence',
        header: t('attackSurface.queue.col.confidence', 'Confidence'),
        cell: ({ row }) => <span className="tabular-nums">{row.original.confidence ?? 0}</span>,
      },
      {
        id: 'evidence',
        header: t('attackSurface.queue.col.evidence', 'Why it may be yours'),
        cell: ({ row }) => {
          const ev = row.original.evidence ?? []
          if (ev.length === 0)
            return (
              <span className="text-muted-foreground">
                {t('attackSurface.queue.noEvidence', 'No evidence')}
              </span>
            )
          return (
            <ul className="space-y-0.5 text-sm">
              {ev.slice(0, 2).map((e, i) => (
                <li key={i} className="text-muted-foreground">
                  {describeEvidence(t, e as AttributionEvidence)}
                </li>
              ))}
              {ev.length > 2 && (
                <li className="text-xs text-muted-foreground">
                  {t('attackSurface.queue.moreEvidence', '+{count} more', { count: ev.length - 2 })}
                </li>
              )}
            </ul>
          )
        },
      },
      {
        id: 'covered',
        header: t('attackSurface.queue.col.covered', 'Covered by'),
        cell: ({ row }) => {
          const c = row.original.covered_by
          if (c?.pattern) {
            return (
              <span className="text-sm">
                <code className="break-all">{c.pattern}</code>
                {c.proof === 'verified' && (
                  <span className="ms-1 text-xs text-success">
                    {t('attackSurface.queue.verified', 'verified')}
                  </span>
                )}
              </span>
            )
          }
          // An address: names that resolve to it never grant it (RFC-054
          // §4.3). The server explains why and offers the fixes this caller
          // may take; shared provider space gets none.
          if (row.original.hint) {
            const net = reviewNetworkText(t, row.original.network)
            const from = row.original.resolved_from ?? []
            return (
              <div className="max-w-sm space-y-1 text-xs text-muted-foreground">
                <p>
                  {t('attackSurface.queue.notInScope', 'Not in scope.')}{' '}
                  {reviewHintText(t, row.original.hint)}
                </p>
                {from.length > 0 && (
                  <p>
                    {t('attackSurface.queue.resolvedFrom', 'Resolved from {names}', {
                      names: from.join(', '),
                    })}
                  </p>
                )}
                {net && <p>{net}</p>}
                <ScopeFixButtons fixes={row.original.fixes ?? []} onApplied={() => void mutate()} />
              </div>
            )
          }
          // Nothing covers it: confirming adds its exact entry (where the
          // organization's setting allows); the entry can also be added alone.
          return (
            <span className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
              {t('attackSurface.queue.notInScopeShort', 'Not in scope')}
              {canAddScope && row.original.name && (
                <Button
                  size="sm"
                  variant="link"
                  className="h-auto p-0 text-xs"
                  onClick={() =>
                    setAddDraft({
                      pattern: row.original.name,
                      target_type: row.original.type === 'ip_address' ? 'ip_address' : 'domain',
                    })
                  }
                >
                  {t('attackSurface.queue.addToScope', 'Add to scope')}
                </Button>
              )}
            </span>
          )
        },
      },
      {
        id: 'since',
        header: t('attackSurface.queue.col.since', 'In queue since'),
        cell: ({ row }) =>
          row.original.in_queue_since ? <RelativeTime date={row.original.in_queue_since} /> : null,
      }
    )
    return cols
  }, [canDecide, canAddScope, setAddDraft, mutate, t])

  if (error) {
    return (
      <ErrorState
        title={t('attackSurface.queue.errorTitle', 'the attack surface items')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  return (
    <div className="space-y-4">
      {canDecide && selected.length > 0 && (
        <div
          role="toolbar"
          aria-label={t('attackSurface.queue.toolbar', 'Decide selected assets')}
          className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 p-2"
        >
          <span className="text-sm">
            {t('attackSurface.queue.selected', '{count} selected', { count: selected.length })}
          </span>
          {view === 'review' && selected.some((s) => !s.covered_by) && (
            <span className="text-xs text-muted-foreground">
              {t(
                'attackSurface.queue.confirmHint',
                'Confirming a domain or address as yours adds its exact scope entry, unless your organization turned this off or uses Strict scan approval.'
              )}
            </span>
          )}
          {DECISIONS.filter((d) => !states.includes(d.state as AttributionState)).map((d) => {
            const Icon = d.icon
            return (
              <Button
                key={d.state}
                size="sm"
                variant={d.state === 'confirmed' ? 'default' : 'outline'}
                disabled={saving}
                onClick={() => void apply(d.state)}
              >
                {saving ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                ) : (
                  <Icon className="h-4 w-4" aria-hidden />
                )}
                {t(`attackSurface.queue.decision.${d.state}`, d.label)}
              </Button>
            )
          })}
          <Button size="sm" variant="ghost" onClick={clearSelection} disabled={saving}>
            {t('attackSurface.queue.clear', 'Clear')}
          </Button>
        </div>
      )}

      <DataTable
        columns={columns}
        data={page?.data ?? []}
        getRowId={(r) => r.asset_id ?? r.name ?? ''}
        manualPagination
        rowCount={page?.total ?? 0}
        pageCount={Math.max(1, Math.ceil((page?.total ?? 0) / pagination.pageSize))}
        pagination={pagination}
        onPaginationChange={setPagination}
        onSelectionChange={setSelected}
        resetSelectionKey={`${view}:${search}:${reason}:${pagination.pageIndex}:${resetKey}`}
        showSearch={false}
        search={{
          value: searchInput,
          onChange: (v) => {
            setSearchInput(v)
            setPage(1)
          },
          placeholder: t('attackSurface.queue.search', 'Search names…'),
        }}
        isLoading={isLoading}
        toolbarStart={
          <>
            <FilterSelect
              label={t('attackSurface.queue.stateFilter', 'State')}
              clearable={false}
              value={view}
              options={REVIEW_VIEWS.map((v) => ({
                value: v.id,
                label: t(`attackSurface.queue.view.${v.id}`, v.label),
                count:
                  v.id === 'review'
                    ? summary
                      ? (summary.attribution?.needs_review ?? 0) +
                        (summary.attribution?.candidate ?? 0)
                      : undefined
                    : summary?.attribution?.rejected,
              }))}
              onChange={(v) => {
                setView(v || REVIEW_VIEWS[0].id)
                setPage(1)
                clearSelection()
              }}
            />
            {view === 'review' && reasons.length > 0 && (
              <Select
                value={reason ?? 'all'}
                onValueChange={(v) => {
                  setReasonParam(v)
                  setPage(1)
                }}
              >
                <SelectTrigger
                  className="h-9 w-auto min-w-44"
                  aria-label={t('attackSurface.queue.reasonFilter', 'Filter by reason')}
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">
                    {t('attackSurface.queue.everyReason', 'Every reason')}
                  </SelectItem>
                  {reasons.map(([r, n]) => (
                    <SelectItem key={r} value={r}>
                      {reviewReasonLabel(t, r)} ({n})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </>
        }
        emptyMessage={
          view === 'review'
            ? t('attackSurface.queue.emptyReview', 'Nothing waits for a decision')
            : t('attackSurface.queue.emptyRejected', 'No rejected assets')
        }
        emptyDescription={
          view === 'review'
            ? t(
                'attackSurface.queue.emptyReviewDescription',
                'Every discovered name has a decision, or none has been found yet.'
              )
            : undefined
        }
      />
      <ScopeEntryDialog
        open={addDraft !== null}
        draft={addDraft ?? undefined}
        onOpenChange={(o) => !o && setAddDraft(null)}
        onCreated={() => void mutate()}
      />
      {!canDecide && (page?.total ?? 0) > 0 && (
        <p className="text-sm text-muted-foreground">
          {t(
            'scope.review.readOnly',
            'You can view these items. Deciding ownership needs permission to edit assets.'
          )}
        </p>
      )}
    </div>
  )
}
