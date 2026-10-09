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
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Ban, Check, Eye, Loader2, Network, Search as SearchIcon } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DataTable, ErrorState, RelativeTime } from '@/features/shared'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import type { EASMReviewItem } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import {
  ATTRIBUTION_STATE_CLASS,
  ATTRIBUTION_STATE_LABEL,
  describeEvidence,
  REVIEW_HINT_TEXT,
  reviewNetworkText,
  type AttributionDecision,
  type AttributionEvidence,
  type AttributionState,
} from '@/features/assets/lib/attribution'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import { useDecideReviewBatch, useEASMReviewQueue } from '../hooks/use-easm-review'
import { useEASMSummary } from '../hooks/use-easm-summary'
import { EASMRuleSuggestions } from './easm-rule-suggestions'
import { reviewReasonLabel } from '../lib/review-reasons'
import { ScopeEntryDialog, ScopeFixButtons, type ScopeEntryDraft } from '@/features/scope'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

/** The queue views: what is waiting, and what was rejected (for undo). */
export const REVIEW_VIEWS: { id: string; label: string; states: AttributionState[] }[] = [
  { id: 'review', label: 'Awaiting review', states: ['needs_review', 'candidate'] },
  { id: 'rejected', label: 'Not ours', states: ['rejected'] },
]

const DECISIONS: { state: AttributionDecision; label: string; icon: React.ElementType }[] = [
  { state: 'confirmed', label: 'Confirm', icon: Check },
  { state: 'rejected', label: 'Not ours', icon: Ban },
  { state: 'dependency', label: 'Dependency', icon: Network },
  { state: 'monitor_only', label: 'Monitor only', icon: Eye },
]

const PAGE_SIZE = 50

function stateOf(item: EASMReviewItem): AttributionState {
  return (item.state ?? 'candidate') as AttributionState
}

export function EASMReviewQueue() {
  const { can } = usePermissions()
  const canDecide = can(Permission.AssetsWrite)
  const canAddScope = can(Permission.ScopeWrite)
  // The tab is in the URL (?tab=rejected) so a view can be linked to.
  const [tabParam, setTabParam] = useUrlFilter('tab', REVIEW_VIEWS[0].id)
  const view = REVIEW_VIEWS.some((v) => v.id === tabParam) ? tabParam : REVIEW_VIEWS[0].id
  const setView = setTabParam
  const [searchInput, setSearchInput] = useState('')
  const search = useDebounce(searchInput, 300)
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
      const label = ATTRIBUTION_STATE_LABEL[state].toLowerCase()
      if (done > 0) toast.success(`${done} ${done === 1 ? 'asset' : 'assets'} set to ${label}`)
      if (missed > 0)
        toast.warning(
          `${missed} ${missed === 1 ? 'asset was' : 'assets were'} not changed: no longer available to you`
        )
      clearSelection()
      void mutate()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not save the decision')
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
            aria-label="Select all"
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label={`Select ${row.original.name ?? 'asset'}`}
          />
        ),
        enableSorting: false,
        enableHiding: false,
      })
    }
    cols.push(
      {
        id: 'name',
        header: 'Name',
        cell: ({ row }) =>
          row.original.asset_id ? (
            <Link
              href={assetDetailHref(row.original.asset_id)}
              className="font-medium hover:underline"
            >
              {row.original.name}
            </Link>
          ) : (
            <span className="font-medium">{row.original.name}</span>
          ),
      },
      {
        id: 'state',
        header: 'State',
        cell: ({ row }) => {
          const st = stateOf(row.original)
          return (
            <Badge variant="outline" className={cn('border-0', ATTRIBUTION_STATE_CLASS[st])}>
              {ATTRIBUTION_STATE_LABEL[st]}
            </Badge>
          )
        },
      },
      {
        id: 'confidence',
        header: 'Confidence',
        cell: ({ row }) => <span className="tabular-nums">{row.original.confidence ?? 0}</span>,
      },
      {
        id: 'evidence',
        header: 'Why it may be yours',
        cell: ({ row }) => {
          const ev = row.original.evidence ?? []
          if (ev.length === 0) return <span className="text-muted-foreground">No evidence</span>
          return (
            <ul className="space-y-0.5 text-sm">
              {ev.slice(0, 2).map((e, i) => (
                <li key={i} className="text-muted-foreground">
                  {describeEvidence(e as AttributionEvidence)}
                </li>
              ))}
              {ev.length > 2 && (
                <li className="text-xs text-muted-foreground">+{ev.length - 2} more</li>
              )}
            </ul>
          )
        },
      },
      {
        id: 'covered',
        header: 'Covered by',
        cell: ({ row }) => {
          const c = row.original.covered_by
          if (c?.pattern) {
            return (
              <span className="text-sm">
                <code className="break-all">{c.pattern}</code>
                {c.proof === 'verified' && (
                  <span className="ms-1 text-xs text-success">verified</span>
                )}
              </span>
            )
          }
          // An address: names that resolve to it never grant it (RFC-054
          // §4.3). The server explains why and offers the fixes this caller
          // may take; shared provider space gets none.
          if (row.original.hint) {
            const net = reviewNetworkText(row.original.network)
            const from = row.original.resolved_from ?? []
            return (
              <div className="max-w-sm space-y-1 text-xs text-muted-foreground">
                <p>Not in scope. {REVIEW_HINT_TEXT[row.original.hint] ?? ''}</p>
                {from.length > 0 && (
                  <p>
                    Resolved from{' '}
                    {from.map((n, i) => (
                      <span key={n}>
                        {i > 0 && ', '}
                        <code className="break-all">{n}</code>
                      </span>
                    ))}
                  </p>
                )}
                {net && <p>{net}</p>}
                <ScopeFixButtons fixes={row.original.fixes ?? []} onApplied={() => void mutate()} />
              </div>
            )
          }
          // Nothing covers it: confirming records ownership, but scans still
          // need a scope entry (RFC-054 §4.2), so offer that first.
          return (
            <span className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
              Not in scope
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
                  Add to scope
                </Button>
              )}
            </span>
          )
        },
      },
      {
        id: 'since',
        header: 'In queue since',
        cell: ({ row }) =>
          row.original.in_queue_since ? <RelativeTime date={row.original.in_queue_since} /> : null,
      }
    )
    return cols
  }, [canDecide, canAddScope, setAddDraft, mutate])

  if (error) {
    return <ErrorState title="the review queue" error={error} onRetry={() => void mutate()} />
  }

  return (
    <div className="space-y-4">
      <Tabs
        value={view}
        onValueChange={(v) => {
          setView(v)
          setPage(1)
          clearSelection()
        }}
      >
        <TabsList>
          {REVIEW_VIEWS.map((v) => (
            <TabsTrigger key={v.id} value={v.id}>
              {v.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {view === 'review' && <EASMRuleSuggestions onApplied={() => void mutate()} />}

      {canDecide && selected.length > 0 && (
        <div
          role="toolbar"
          aria-label="Decide selected assets"
          className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 p-2"
        >
          <span className="text-sm">{selected.length} selected</span>
          {view === 'review' && selected.some((s) => !s.covered_by) && (
            <span className="text-xs text-muted-foreground">
              Confirming records ownership only; names no scope entry covers stay out of scans.
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
                {d.label}
              </Button>
            )
          })}
          <Button size="sm" variant="ghost" onClick={clearSelection} disabled={saving}>
            Clear
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
        toolbarStart={
          <div className="flex w-full flex-wrap items-center gap-2">
            <div className="relative w-full max-w-sm">
              <SearchIcon
                className="absolute start-2.5 top-2.5 h-4 w-4 text-muted-foreground"
                aria-hidden
              />
              <Input
                value={searchInput}
                onChange={(e) => {
                  setSearchInput(e.target.value)
                  setPage(1)
                }}
                placeholder="Search names"
                aria-label="Search names"
                className="ps-8"
              />
            </div>
            {view === 'review' && reasons.length > 0 && (
              <Select
                value={reason ?? 'all'}
                onValueChange={(v) => {
                  setReasonParam(v)
                  setPage(1)
                }}
              >
                <SelectTrigger className="h-9 w-auto min-w-44" aria-label="Filter by reason">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Every reason</SelectItem>
                  {reasons.map(([r, n]) => (
                    <SelectItem key={r} value={r}>
                      {reviewReasonLabel(r)} ({n})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>
        }
        emptyMessage={
          isLoading ? 'Loading…' : view === 'review' ? 'Nothing to review' : 'No rejected assets'
        }
        emptyDescription={
          isLoading
            ? undefined
            : view === 'review'
              ? 'Every discovered name has a decision, or none has been found yet.'
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
          You can view this queue. Deciding ownership needs the assets:write permission.
        </p>
      )}
    </div>
  )
}
