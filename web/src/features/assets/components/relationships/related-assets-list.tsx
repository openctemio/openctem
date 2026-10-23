'use client'

/**
 * Related assets of one asset, as a grouped, readable list.
 *
 * One group per relationship type and direction seen from the asset, named
 * with a plain verb ("Resolves to", "Names that resolve here", "Runs on",
 * "Hosts") and its count. Rows lead with the related asset (one click opens
 * it), its state (criticality, internet exposure, lifecycle) and the edge's
 * own facts: who recorded it (scanner, import, person, inference) and when it
 * was last seen. Large groups show their most critical rows first and page
 * through the rest with a name search, so a fan-out of thousands stays usable.
 *
 * Related assets outside the viewer's data scope never reach the browser: the
 * API returns only their number, shown as one muted line.
 */

import * as React from 'react'
import { ChevronDown, ChevronRight, Lock, MoreHorizontal, Network, Search } from 'lucide-react'
import { mutate as globalMutate } from 'swr'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { AssetStatusBadge } from '@/features/asset-lifecycle/components/asset-status-badge'
import { endpoints } from '@/lib/api/endpoints'
import { cn } from '@/lib/utils'
import { AssetTypeIcon, getAssetTypeLabel } from '../../lib/asset-type-icon'
import {
  STALE_EDGE_DAYS,
  edgeSource,
  relationGroupRank,
  relationVerbFallback,
  relationVerbKey,
} from '../../lib/relationship-verbs'
import {
  useRelatedAssets,
  type RelatedAssetGroup,
  type RelatedAssetItem,
} from '../../hooks/use-related-assets'
import { CriticalityBadge } from '../classification-badges'
import type { Criticality } from '../../types'

const PAGE_SIZE = 25
/** Rows per group before "Show all" in the full view. */
export const RELATED_PREVIEW_ROWS = 5
/** Names per group in the overview summary. */
const SUMMARY_NAMES = 3
const DAY_MS = 86_400_000

/** Revalidates every grouped view of one asset (after add, edit or remove). */
export function revalidateRelatedAssets(assetId: string) {
  const prefix = endpoints.assets.relationshipGroups(assetId)
  return globalMutate((key) => typeof key === 'string' && key.startsWith(prefix))
}

export interface RelatedAssetsListProps {
  assetId: string
  /** `full`: the Relations tab. `summary`: one line per group, for the overview. */
  variant?: 'full' | 'summary'
  /** Opens a related asset (the sheet keeps a back trail). */
  onNavigateToAsset?: (assetId: string, name: string) => void
  /** Summary only: opens the Relations tab. */
  onViewAll?: () => void
  /** Full only: row actions, shown only when given (permission-gated by the caller). */
  onEdit?: (item: RelatedAssetItem) => void
  onRemove?: (item: RelatedAssetItem) => void
  /** Full only: the Add button (or nothing), placed in the empty state. */
  addAction?: React.ReactNode
}

export function RelatedAssetsList({
  assetId,
  variant = 'full',
  onNavigateToAsset,
  onViewAll,
  onEdit,
  onRemove,
  addAction,
}: RelatedAssetsListProps) {
  const { t } = useTranslation()
  // One request (and one cache entry) serves the overview, the tab and the
  // tab count: the summary shows fewer names of the same rows.
  const { groups, total, hiddenCount, isLoading, error, mutate, data } = useRelatedAssets(assetId, {
    limit: RELATED_PREVIEW_ROWS,
  })

  const sorted = React.useMemo(
    () =>
      [...groups].sort(
        (a, b) => relationGroupRank(a.type, a.direction) - relationGroupRank(b.type, b.direction)
      ),
    [groups]
  )

  if (isLoading && !data) {
    return (
      <div className="space-y-2" aria-busy="true">
        <span className="sr-only">{t('assets.related.loading', 'Loading related assets')}</span>
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <ErrorState
        title={t('assets.related.error', 'related assets')}
        error={error}
        onRetry={() => mutate()}
      />
    )
  }

  if (total === 0 && hiddenCount === 0) {
    if (variant === 'summary') {
      return (
        <p className="text-sm text-muted-foreground">
          {t('assets.related.none', 'No related assets recorded.')}
        </p>
      )
    }
    return (
      <EmptyState
        icon={Network}
        title={t('assets.related.emptyTitle', 'No related assets yet')}
        description={t(
          'assets.related.emptyHint',
          'Scans link names, addresses, services and certificates as they find them. You can also add a relationship by hand.'
        )}
        action={addAction}
      />
    )
  }

  if (variant === 'summary') {
    return (
      <div className="space-y-2">
        <dl className="space-y-1.5">
          {sorted.map((g) => (
            <SummaryRow
              key={`${g.type}|${g.direction}`}
              group={g}
              onNavigateToAsset={onNavigateToAsset}
              onViewAll={onViewAll}
            />
          ))}
        </dl>
        <HiddenNote count={hiddenCount} />
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground" aria-live="polite">
        {t('assets.related.summary', '{count} related assets in {groups} groups', {
          count: total,
          groups: sorted.length,
        })}
      </p>
      <div className="space-y-2">
        {sorted.map((g) => (
          <GroupBlock
            key={`${g.type}|${g.direction}`}
            assetId={assetId}
            group={g}
            onNavigateToAsset={onNavigateToAsset}
            onEdit={onEdit}
            onRemove={onRemove}
          />
        ))}
      </div>
      <HiddenNote count={hiddenCount} />
    </div>
  )
}

// ============================================
// Overview summary: one line per group
// ============================================

function SummaryRow({
  group,
  onNavigateToAsset,
  onViewAll,
}: {
  group: RelatedAssetGroup
  onNavigateToAsset?: (id: string, name: string) => void
  onViewAll?: () => void
}) {
  const { t } = useTranslation()
  const shown = group.items.slice(0, SUMMARY_NAMES)
  const rest = group.total - shown.length
  return (
    <div className="grid grid-cols-1 gap-x-3 gap-y-0.5 sm:grid-cols-[11rem_1fr]">
      <dt className="text-xs text-muted-foreground sm:pt-0.5">
        <GroupVerb group={group} />
      </dt>
      <dd className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        {shown.map((it, i) => (
          <React.Fragment key={it.relationship_id}>
            <AssetName item={it} onNavigateToAsset={onNavigateToAsset} />
            {i < shown.length - 1 && <span className="text-muted-foreground">·</span>}
          </React.Fragment>
        ))}
        {rest > 0 &&
          (onViewAll ? (
            <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={onViewAll}>
              {t('assets.related.more', '+{count} more', { count: rest })}
            </Button>
          ) : (
            <span className="text-xs text-muted-foreground">
              {t('assets.related.more', '+{count} more', { count: rest })}
            </span>
          ))}
      </dd>
    </div>
  )
}

// ============================================
// Full view: one block per group
// ============================================

function GroupBlock({
  assetId,
  group,
  onNavigateToAsset,
  onEdit,
  onRemove,
}: {
  assetId: string
  group: RelatedAssetGroup
  onNavigateToAsset?: (id: string, name: string) => void
  onEdit?: (item: RelatedAssetItem) => void
  onRemove?: (item: RelatedAssetItem) => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = React.useState(true)
  const [showAll, setShowAll] = React.useState(false)
  const bodyId = React.useId()
  const more = group.total > group.items.length

  return (
    <section className="rounded-md border">
      <h4 className="m-0">
        <button
          type="button"
          className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm font-medium hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => setOpen((v) => !v)}
        >
          {open ? (
            <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          ) : (
            <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          )}
          <GroupVerb group={group} />
          <Badge variant="secondary" className="ml-auto tabular-nums">
            {group.total}
          </Badge>
        </button>
      </h4>
      {open && (
        <div id={bodyId} className="border-t">
          {showAll ? (
            <GroupPager
              assetId={assetId}
              group={group}
              onNavigateToAsset={onNavigateToAsset}
              onEdit={onEdit}
              onRemove={onRemove}
            />
          ) : (
            <>
              <RowList
                items={group.items}
                onNavigateToAsset={onNavigateToAsset}
                onEdit={onEdit}
                onRemove={onRemove}
              />
              {more && (
                <div className="border-t px-3 py-1.5">
                  <Button
                    variant="link"
                    size="sm"
                    className="h-auto p-0"
                    onClick={() => setShowAll(true)}
                  >
                    {t('assets.related.showAll', 'Show all {count}', { count: group.total })}
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </section>
  )
}

/** Every row of one group, a page at a time, with a name search. */
function GroupPager({
  assetId,
  group,
  onNavigateToAsset,
  onEdit,
  onRemove,
}: {
  assetId: string
  group: RelatedAssetGroup
  onNavigateToAsset?: (id: string, name: string) => void
  onEdit?: (item: RelatedAssetItem) => void
  onRemove?: (item: RelatedAssetItem) => void
}) {
  const { t } = useTranslation()
  const [query, setQuery] = React.useState('')
  const [debounced, setDebounced] = React.useState('')
  const [page, setPage] = React.useState(0)
  // A new search starts at its first page; the initial (empty) query does
  // not reset a page the reader has already moved to.
  React.useEffect(() => {
    if (query === debounced) return
    const id = setTimeout(() => {
      setDebounced(query)
      setPage(0)
    }, 250)
    return () => clearTimeout(id)
  }, [query, debounced])

  const { groups, isLoading, error, mutate } = useRelatedAssets(assetId, {
    type: group.type,
    direction: group.direction,
    q: debounced,
    offset: page * PAGE_SIZE,
    limit: PAGE_SIZE,
  })
  const current = groups[0]
  const total = current?.total ?? (debounced ? 0 : group.total)
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const verb = t(
    relationVerbKey(group.type, group.direction),
    relationVerbFallback(group.type, group.direction)
  )

  return (
    <div>
      {group.total > PAGE_SIZE && (
        <div className="relative border-b px-3 py-2">
          <Search
            className="pointer-events-none absolute left-5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('assets.related.search', 'Search by name')}
            aria-label={t('assets.related.searchIn', 'Search {verb}', { verb })}
            className="h-8 pl-8"
          />
        </div>
      )}
      {error ? (
        <div className="p-3">
          <ErrorState
            title={t('assets.related.error', 'related assets')}
            error={error}
            onRetry={() => mutate()}
          />
        </div>
      ) : isLoading && !current ? (
        <div className="space-y-1 p-3">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </div>
      ) : current && current.items.length > 0 ? (
        <RowList
          items={current.items}
          onNavigateToAsset={onNavigateToAsset}
          onEdit={onEdit}
          onRemove={onRemove}
        />
      ) : (
        <p className="px-3 py-2 text-sm text-muted-foreground">
          {t('assets.related.noMatch', 'No related asset matches "{query}".', { query: debounced })}
        </p>
      )}
      {pages > 1 && (
        <div className="flex items-center justify-between gap-2 border-t px-3 py-1.5 text-xs text-muted-foreground">
          <span aria-live="polite">
            {t('assets.related.range', '{from}–{to} of {total}', {
              from: page * PAGE_SIZE + 1,
              to: Math.min(total, (page + 1) * PAGE_SIZE),
              total,
            })}
          </span>
          <span className="flex gap-1">
            <Button
              variant="outline"
              size="sm"
              className="h-7"
              disabled={page === 0}
              onClick={() => setPage((p) => p - 1)}
            >
              {t('assets.related.prev', 'Previous')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7"
              disabled={page >= pages - 1}
              onClick={() => setPage((p) => p + 1)}
            >
              {t('assets.related.next', 'Next')}
            </Button>
          </span>
        </div>
      )}
    </div>
  )
}

function RowList({
  items,
  onNavigateToAsset,
  onEdit,
  onRemove,
}: {
  items: RelatedAssetItem[]
  onNavigateToAsset?: (id: string, name: string) => void
  onEdit?: (item: RelatedAssetItem) => void
  onRemove?: (item: RelatedAssetItem) => void
}) {
  return (
    <ul className="divide-y">
      {items.map((it) => (
        <RelatedRow
          key={it.relationship_id}
          item={it}
          onNavigateToAsset={onNavigateToAsset}
          onEdit={onEdit}
          onRemove={onRemove}
        />
      ))}
    </ul>
  )
}

function RelatedRow({
  item,
  onNavigateToAsset,
  onEdit,
  onRemove,
}: {
  item: RelatedAssetItem
  onNavigateToAsset?: (id: string, name: string) => void
  onEdit?: (item: RelatedAssetItem) => void
  onRemove?: (item: RelatedAssetItem) => void
}) {
  const { t } = useTranslation()
  const a = item.asset
  const crit = a.criticality as Criticality | undefined
  const showCrit = crit === 'critical' || crit === 'high'
  const lifecycle = a.status && a.status !== 'active' ? a.status : undefined

  return (
    <li className="flex items-start gap-3 px-3 py-2">
      <AssetTypeIcon type={a.type} className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <AssetName item={item} onNavigateToAsset={onNavigateToAsset} className="font-medium" />
          <span className="text-xs text-muted-foreground">{getAssetTypeLabel(a.type)}</span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {showCrit && <CriticalityBadge criticality={crit} size="sm" />}
          {a.exposure === 'public' && (
            <Badge variant="outline" className="h-5 px-1.5 text-meta font-normal">
              {t('assets.related.internet', 'Internet-facing')}
            </Badge>
          )}
          {lifecycle && <AssetStatusBadge status={lifecycle} className="h-5 px-1.5 text-meta" />}
          {item.is_control_plane && (
            <Badge variant="outline" className="h-5 px-1.5 text-meta font-normal">
              {t('assets.related.controlPlane', 'Control plane')}
            </Badge>
          )}
          <EdgeFacts item={item} />
        </div>
      </div>
      {(onEdit || onRemove) && (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0"
              aria-label={t('assets.related.actions', 'Actions for {name}', { name: a.name })}
            >
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {onEdit && (
              <DropdownMenuItem onClick={() => onEdit(item)}>
                {t('assets.related.edit', 'Edit relationship')}
              </DropdownMenuItem>
            )}
            {onRemove && (
              <DropdownMenuItem className="text-destructive" onClick={() => onRemove(item)}>
                {t('assets.related.remove', 'Remove relationship')}
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
    </li>
  )
}

/** Who recorded the edge, how sure, and when it was last seen. */
function EdgeFacts({ item }: { item: RelatedAssetItem }) {
  const { t } = useTranslation()
  // The age is read once per mount; a list is short-lived enough for a day count.
  const [now] = React.useState(() => Date.now())
  const source = edgeSource(item.discovery_method)
  const seen = item.last_verified ? new Date(item.last_verified) : null
  const added = new Date(item.created_at)
  const days = seen ? Math.floor((now - seen.getTime()) / DAY_MS) : null
  const stale = days !== null && days >= STALE_EDGE_DAYS

  let when: string
  if (seen && stale)
    when = t('assets.related.notSeenFor', 'not seen for {days} days', { days: days ?? 0 })
  else if (seen)
    when = t('assets.related.seen', 'seen {when}', { when: relativeDays(days ?? 0, t) })
  else
    when = t('assets.related.added', 'added {when}', {
      when: relativeDays(Math.floor((now - added.getTime()) / DAY_MS), t),
    })

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className={cn(
            'inline-flex items-center gap-1 rounded text-meta text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            stale && 'text-warning'
          )}
        >
          {t(`assets.related.source.${source}`, sourceFallback[source])}
          {item.confidence === 'low' && (
            <> · {t('assets.related.lowConfidence', 'low confidence')}</>
          )}
          <> · {when}</>
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs">
        <p>{t(`assets.related.source.${source}.hint`, sourceHintFallback[source])}</p>
        <p className="mt-1 text-muted-foreground">
          {seen
            ? t('assets.related.lastSeenAt', 'Last reported {date}', {
                date: seen.toLocaleString(),
              })
            : t('assets.related.addedAt', 'Added {date}; not reported by a scan since', {
                date: added.toLocaleString(),
              })}
        </p>
      </TooltipContent>
    </Tooltip>
  )
}

const sourceFallback = {
  scanner: 'Scanner',
  import: 'Import',
  manual: 'Added by hand',
  inferred: 'Inferred',
} as const
const sourceHintFallback = {
  scanner: 'Recorded by a scan; refreshed each time a scan reports it again.',
  import: 'Recorded by an import or a connector.',
  manual: 'Added by a person.',
  inferred: 'Derived by the platform from other facts; not observed directly.',
} as const

function relativeDays(days: number, t: ReturnType<typeof useTranslation>['t']): string {
  if (days <= 0) return t('assets.related.today', 'today')
  if (days === 1) return t('assets.related.yesterday', 'yesterday')
  return t('assets.related.daysAgo', '{days} days ago', { days })
}

function GroupVerb({ group }: { group: Pick<RelatedAssetGroup, 'type' | 'direction'> }) {
  const { t } = useTranslation()
  return (
    <span className="truncate">
      {t(
        relationVerbKey(group.type, group.direction),
        relationVerbFallback(group.type, group.direction)
      )}
    </span>
  )
}

function AssetName({
  item,
  onNavigateToAsset,
  className,
}: {
  item: RelatedAssetItem
  onNavigateToAsset?: (id: string, name: string) => void
  className?: string
}) {
  const { t } = useTranslation()
  const a = item.asset
  if (!onNavigateToAsset)
    return <span className={cn('min-w-0 break-all', className)}>{a.name}</span>
  return (
    <button
      type="button"
      className={cn(
        'min-w-0 break-all rounded text-left underline decoration-muted-foreground/40 underline-offset-2 hover:decoration-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        className
      )}
      onClick={() => onNavigateToAsset(a.id, a.name)}
      aria-label={t('assets.related.open', 'Open {name}', { name: a.name })}
    >
      {a.name}
    </button>
  )
}

/** "1 related asset you can't access": a number, never a name. */
function HiddenNote({ count }: { count: number }) {
  const { t } = useTranslation()
  if (count <= 0) return null
  return (
    <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
      <Lock className="h-3.5 w-3.5 shrink-0" aria-hidden />
      {count === 1
        ? t('assets.related.hiddenOne', '1 related asset you can’t access')
        : t('assets.related.hiddenMany', '{count} related assets you can’t access', { count })}
    </p>
  )
}
