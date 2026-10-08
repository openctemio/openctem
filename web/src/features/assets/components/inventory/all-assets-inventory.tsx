'use client'

/**
 * Unified All-Assets inventory: ONE server-paginated table across every asset
 * type, composed like the Findings list (the reference list page — see
 * docs/ui-style-contract.md): metric strip, then a single toolbar row above the
 * table, a floating filter panel beside it and a floating bulk-action bar.
 *
 * State model: the URL query string is the single source of truth. Filters are
 * parsed from it on every render and written back with router.replace, so a
 * reload or a shared link restores the exact view (deep-linkable, scoped to the
 * viewer's own tenant). Saved / named views are intentionally deferred to v2.
 *
 * One page for every asset type (research/77): `?types=host` (and
 * `&sub_type=` for a registry alias such as IAM users) switches it to typed
 * mode, all from the type registry: the type's name in the header, its
 * columns, attribute facets and yes/no counts, an "Add <type>" form built
 * from its attributes, row actions, and an empty state that says how to find
 * the type. Create, edit, delete and CSV export work for every type here.
 * `?lens=` narrows it to one registry lens (every type of it, aliases
 * included), picked from the lens pills above the table.
 */

import { AssetsSectionTabs } from '../assets-section-tabs'
import { useCallback, useEffect, useEffectEvent, useMemo, useState, type ReactNode } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Download, Lock, RefreshCw, Search } from 'lucide-react'
import { toast } from 'sonner'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'
import { inSentence, typeViewOf, type TypeView } from '@/features/asset-types/lib/type-view'
import { propertyLabel } from '@/features/asset-types/lib/property-schema'
import { exportInventory } from '../../lib/inventory-export'
import { useInventoryAssetForms } from './inventory-asset-forms'
import { InventoryAddButton } from './inventory-add-button'
import { Main } from '@/components/layout'
import { PageHeader, EmptyState, FilterPanelToggle, FilterSheet } from '@/features/shared'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { usePermissions, Permission } from '@/lib/permissions'
import { useDebounce } from '@/hooks/use-debounce'
import { useAssets, useAssetStats, type AssetSearchFilters } from '../../hooks/use-assets'
import type { Asset } from '../../types/asset.types'
import { useBusinessUnits } from '@/features/business-units/api/use-business-units'
import { buildFacetGroups, deactivatePreset, type QuickPreset } from '../../lib/inventory-facets'
import {
  parseInventoryFilters,
  attributionQuery,
  ATTRIBUTION_FILTER_VALUES,
  serializeInventoryFilters,
  countActiveFilters,
  isInventoryFilterEmpty,
  DEFAULT_PAGE_SIZE,
  type InventoryFilters,
} from '../../lib/inventory-url'
import { InventoryViewsMenu } from './inventory-views-menu'
import { InventoryStatStrip } from './inventory-stat-strip'
import { InventoryBulkBar } from './inventory-bulk-bar'
import { InventoryFacetPanel } from './inventory-facet-panel'
import { InventoryTable } from './inventory-table'
import { InventoryLensBar, inventoryLenses } from './inventory-lens-bar'

const FILTERS_OPEN_KEY = 'openctem:assets-filters-open'

/** Translate the inventory filter model into the useAssets query shape. */
function toSearchFilters(f: InventoryFilters): AssetSearchFilters {
  return {
    search: f.search,
    types: f.types,
    lenses: f.lens ? [f.lens] : undefined,
    subType: f.subType,
    minRiskScore: f.minRiskScore,
    propertiesFilter: f.propertiesFilter,
    criticalities: f.criticalities,
    statuses: f.statuses,
    scopes: f.scopes,
    exposures: f.exposures,
    tags: f.tags,
    dataClassifications: f.dataClassifications,
    environments: f.environments,
    providers: f.providers,
    businessUnitIds: f.businessUnitIds,
    hasOwner: f.hasOwner,
    isControlPlane: f.isControlPlane,
    isInternetAccessible: f.isInternetAccessible,
    isCrownJewel: f.isCrownJewel,
    hasFindings: f.hasFindings,
    lastSeenBefore: f.lastSeenBefore,
    lastSeenAfter: f.lastSeenAfter,
    attribution: attributionQuery(f),
    sort: f.sort,
    page: f.page ?? 1,
    pageSize: f.pageSize ?? DEFAULT_PAGE_SIZE,
  }
}

/**
 * useAssets without flicker: while the next page / filter loads, keep showing
 * the rows already on screen instead of an empty table. useAssets is shared
 * with other pages, so the previous result is held here rather than changing
 * the hook's SWR options.
 */
function useAssetsKeepingPrevious(filters: AssetSearchFilters) {
  const result = useAssets(filters)
  // "Storing information from previous renders": update during render when a
  // settled result arrives (React re-renders immediately, no effect needed).
  const [settled, setSettled] = useState<{ assets: Asset[]; total: number } | null>(null)
  const isSettled = !result.isLoading && !result.isError
  if (isSettled && (settled?.assets !== result.assets || settled.total !== result.total)) {
    setSettled({ assets: result.assets, total: result.total })
  }
  const shown = result.isLoading && settled ? settled : result
  return {
    ...result,
    assets: shown.assets,
    total: shown.total,
    /** True only before anything has ever loaded. */
    isFirstLoad: result.isLoading && !settled,
  }
}

/** How a type's assets get into the inventory, for its empty list. */
function emptyHint(view: TypeView): string {
  if (view.type === 'repository') {
    return 'Connect a source-code integration in Settings to import repositories, or add one.'
  }
  if (view.type === 'cloud_account') {
    return 'Connect a cloud integration in Settings to import accounts, or add one.'
  }
  return view.scannable
    ? `Add one, or run a discovery scan to find ${inSentence(view.plural)}.`
    : `Add one, or import ${inSentence(view.plural)} from a connected source.`
}

/** First-load placeholder shaped like the toolbar + table it stands in for. */
function InventoryTableSkeleton() {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Skeleton className="h-9 w-9" />
        <Skeleton className="h-9 w-72" />
        <Skeleton className="ms-auto h-9 w-36" />
        <Skeleton className="h-9 w-9" />
        <Skeleton className="h-9 w-24" />
      </div>
      <div className="space-y-2 rounded-md border p-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    </div>
  )
}

export function AllAssetsInventory({ viewSwitcher }: { viewSwitcher?: ReactNode } = {}) {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const { can } = usePermissions()
  const canRead = can(Permission.AssetsRead)
  const canWrite = can(Permission.AssetsWrite)

  // URL is the source of truth for all filter state.
  const filters = useMemo(
    () => parseInventoryFilters(new URLSearchParams(searchParams.toString())),
    [searchParams]
  )

  const setFilters = useCallback(
    (next: InventoryFilters) => {
      const qs = serializeInventoryFilters(next).toString()
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false })
    },
    [router, pathname]
  )

  // Local search input, debounced into the URL so we don't replace() per keystroke.
  const [searchInput, setSearchInput] = useState(filters.search ?? '')
  const debouncedSearch = useDebounce(searchInput, 300)
  // Keep the box in sync when search is cleared elsewhere (clear-all, a metric).
  useEffect(() => {
    setSearchInput(filters.search ?? '')
  }, [filters.search])
  // Only the debounced input triggers a URL write. The other filters are read as
  // an effect event (latest value, not a dependency): changing one of them must
  // not push a stale debounced search back into the URL.
  const commitSearch = useEffectEvent((next: string) => {
    const current = filters.search ?? ''
    if (next !== current) {
      setFilters({ ...filters, search: next || undefined, page: 1 })
    }
  })
  useEffect(() => {
    commitSearch(debouncedSearch)
  }, [debouncedSearch])

  // Filter panel: closed by default so the table gets the width; the viewer's
  // choice is remembered (a per-browser convenience, safe to lose).
  const [filtersOpen, setFiltersOpenState] = useState(false)
  useEffect(() => {
    try {
      if (window.localStorage.getItem(FILTERS_OPEN_KEY) === '1') setFiltersOpenState(true)
    } catch {
      // storage unavailable — stay closed
    }
  }, [])
  const setFiltersOpen = useCallback((next: boolean | ((open: boolean) => boolean)) => {
    setFiltersOpenState((prev) => {
      const value = typeof next === 'function' ? next(prev) : next
      try {
        window.localStorage.setItem(FILTERS_OPEN_KEY, value ? '1' : '0')
      } catch {
        // best-effort
      }
      return value
    })
  }, [])
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)

  // Data. The headline numbers come from the tenant-wide stats endpoint.
  const searchFilters = useMemo(() => toSearchFilters(filters), [filters])
  const { assets, total, isFirstLoad, isLoading, isError, error, mutate } =
    useAssetsKeepingPrevious(searchFilters)
  const { stats, isLoading: statsLoading, mutate: statsMutate } = useAssetStats()
  const { data: buData } = useBusinessUnits()

  // Typed mode: the list is one type (and maybe one sub-type).
  const { registry } = useAssetTypeRegistry()
  const typeView = useMemo(
    () => typeViewOf(registry, filters.types, filters.subType),
    [registry, filters.types, filters.subType]
  )
  const facetKeys = useMemo(() => typeView?.facets.map((f) => f.key) ?? [], [typeView])
  // The lens's label when the list is one lens (and not one type).
  const lensLabel = useMemo(
    () =>
      !typeView && filters.lens
        ? inventoryLenses(registry).find((l) => l.id === filters.lens)?.label
        : undefined,
    [registry, typeView, filters.lens]
  )
  // The type's (or lens's) own counts. Without either this is the same
  // request as the tenant-wide stats above (SWR shares it).
  const {
    stats: typeStats,
    isLoading: typeStatsLoading,
    mutate: typeStatsMutate,
  } = useAssetStats({
    types: typeView ? [typeView.type] : undefined,
    lenses: !typeView && filters.lens ? [filters.lens] : undefined,
    subType: typeView?.subType,
    countBy: facetKeys.length > 0 ? facetKeys : undefined,
  })
  const scopeLabel = typeView?.plural ?? lensLabel
  const attributeFacets = useMemo(
    () =>
      (typeView?.facets ?? []).map((attribute) => ({
        attribute,
        label: propertyLabel(attribute.key),
        counts: typeStats.metadataCounts?.[attribute.key] ?? {},
      })),
    [typeView, typeStats]
  )
  const boolFacets = useMemo(
    () =>
      (typeView?.facets ?? [])
        .filter((f) => f.kind === 'bool')
        .slice(0, 3)
        .map((f) => ({ key: f.key, label: propertyLabel(f.key) })),
    [typeView]
  )

  const businessUnitLabels = useMemo(() => {
    const map: Record<string, string> = {}
    for (const bu of buData?.data ?? []) map[bu.id] = bu.name
    return map
  }, [buData])

  const facetGroups = useMemo(() => buildFacetGroups(businessUnitLabels), [businessUnitLabels])

  const togglePreset = useCallback(
    (preset: QuickPreset) => {
      if (preset.isActive(filters)) {
        // Turn it off: remove only the values this preset contributed, keeping
        // any the user selected manually (e.g. extra criticalities).
        setFilters({ ...deactivatePreset(filters, preset), page: 1 })
      } else {
        setFilters({ ...filters, ...preset.apply, page: 1 })
      }
    },
    [filters, setFilters]
  )

  // Search has its own box in the toolbar, so the filter button counts the rest.
  const activeCount = countActiveFilters(filters) - (filters.search ? 1 : 0)
  const clearAll = useCallback(
    () => setFilters({ sort: filters.sort, pageSize: filters.pageSize }),
    [setFilters, filters.sort, filters.pageSize]
  )

  // Row selection: the table owns the checkboxes; bumping the epoch clears
  // them. It is bumped whenever the query changes, so the bulk bar only ever
  // acts on rows of the current view, and after a bulk action.
  const [selectedAssets, setSelectedAssets] = useState<Asset[]>([])
  const [selectionEpoch, setSelectionEpoch] = useState(0)
  const clearSelection = useCallback(() => {
    setSelectionEpoch((n) => n + 1)
    setSelectedAssets([])
  }, [])
  const queryKey = searchParams.toString()
  useEffect(() => {
    clearSelection()
  }, [queryKey, clearSelection])

  const refresh = useCallback(() => {
    void mutate()
    void statsMutate()
    void typeStatsMutate()
  }, [mutate, statsMutate, typeStatsMutate])

  const forms = useInventoryAssetForms(registry, refresh)
  const [exporting, setExporting] = useState(false)
  const handleExport = useCallback(async () => {
    if (exporting) return
    setExporting(true)
    try {
      await exportInventory(searchFilters, typeView)
    } catch {
      toast.error('Failed to export assets')
    } finally {
      setExporting(false)
    }
  }, [exporting, searchFilters, typeView])

  if (!canRead) {
    return (
      <Main>
        <PageHeader title="Assets" />
        <EmptyState
          className="mt-8 border-dashed"
          icon={Lock}
          title="You don't have access to assets"
          description="Ask an administrator for the assets:read permission to view the inventory."
        />
      </Main>
    )
  }

  const facetPanel = (
    <InventoryFacetPanel
      groups={facetGroups}
      filters={filters}
      stats={stats}
      onChange={setFilters}
      attributeFacets={attributeFacets}
      activeCount={activeCount}
      onClearAll={clearAll}
    />
  )

  const filterButtons = (
    <FilterPanelToggle
      open={filtersOpen}
      onToggle={() => setFiltersOpen((o) => !o)}
      onOpenSheet={() => setFilterSheetOpen(true)}
      activeCount={activeCount}
      controlsId="asset-filters"
    />
  )

  const searchBox = (
    <div className="relative min-w-0 flex-1 sm:max-w-sm">
      <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={searchInput}
        onChange={(e) => setSearchInput(e.target.value)}
        placeholder="Search name, description or alias…"
        aria-label="Search assets"
        className="h-9 ps-9"
      />
    </div>
  )

  const refreshButton = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          className="h-9 w-9"
          onClick={refresh}
          disabled={isLoading || statsLoading}
          aria-label="Refresh"
        >
          <RefreshCw className={cn('h-4 w-4', (isLoading || statsLoading) && 'animate-spin')} />
        </Button>
      </TooltipTrigger>
      <TooltipContent>Refresh</TooltipContent>
    </Tooltip>
  )

  const page = filters.page ?? 1
  const pageSize = filters.pageSize ?? DEFAULT_PAGE_SIZE

  return (
    <Main>
      <PageHeader title={scopeLabel ?? 'Assets'}>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void handleExport()}
          disabled={exporting}
        >
          <Download className="me-2 h-4 w-4" />
          {exporting ? 'Exporting…' : 'Export'}
        </Button>
        {canWrite && (
          <InventoryAddButton registry={registry} view={typeView} onAdd={forms.openCreate} />
        )}
        {viewSwitcher}
      </PageHeader>
      <AssetsSectionTabs />

      {!typeView && (
        <InventoryLensBar
          className="mt-5"
          registry={registry}
          value={filters.lens}
          onChange={(lens) =>
            // A lens replaces the type picks: a type outside it would match nothing.
            setFilters({ ...filters, lens, types: undefined, subType: undefined, page: 1 })
          }
        />
      )}

      <InventoryStatStrip
        className={typeView ? 'mt-5' : 'mt-4'}
        stats={scopeLabel ? typeStats : stats}
        filters={filters}
        isLoading={scopeLabel ? typeStatsLoading : statsLoading}
        onChange={setFilters}
        typeLabel={scopeLabel}
        boolFacets={boolFacets}
      />

      <div className="mt-5 flex items-start">
        {/* Always mounted so opening and closing can animate: the slot's width
            (and the gap after it) eases between 0 and the card's width while
            the card fades, and the table beside it resizes in step. The card
            keeps its own width, so its contents never reflow mid-animation. */}
        <div
          inert={!filtersOpen}
          className={cn(
            'sticky top-4 hidden shrink-0 overflow-hidden transition-[width,margin-inline-end,opacity] duration-300 ease-in-out motion-reduce:transition-none lg:block',
            filtersOpen ? 'me-5 w-64 opacity-100' : 'me-0 w-0 opacity-0'
          )}
        >
          <aside
            id="asset-filters"
            aria-label="Asset filters"
            // A self-contained floating card, as tall as the viewport and pinned
            // while the page scrolls; long filter lists scroll inside it.
            className="flex h-[calc(100svh-7.5rem)] w-64 flex-col rounded-xl border bg-card p-4 shadow-sm"
          >
            <div className="flex min-h-0 flex-1 flex-col">{facetPanel}</div>
          </aside>
        </div>

        <div className="min-w-0 flex-1">
          {!filters.attribution?.length && (
            <p className="mb-2 text-sm text-muted-foreground" data-slot="attribution-default">
              Showing assets that are yours. Names awaiting ownership review and names marked as not
              yours are hidden.{' '}
              <button
                type="button"
                className="font-medium text-foreground underline underline-offset-2"
                onClick={() =>
                  setFilters({ ...filters, attribution: [...ATTRIBUTION_FILTER_VALUES], page: 1 })
                }
              >
                Show all
              </button>
            </p>
          )}
          {isError ? (
            <Alert variant="destructive">
              <AlertTitle>Failed to load assets</AlertTitle>
              <AlertDescription>
                <p>{error?.message || 'An unexpected error occurred.'}</p>
                <Button variant="outline" size="sm" className="mt-2" onClick={refresh}>
                  <RefreshCw className="me-2 h-4 w-4" />
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          ) : isFirstLoad ? (
            <InventoryTableSkeleton />
          ) : (
            <InventoryTable
              onAssetUpdated={() => void mutate()}
              assets={assets}
              total={total}
              page={page}
              pageSize={pageSize}
              sort={filters.sort}
              onPageChange={(nextPage, nextSize) =>
                setFilters({
                  ...filters,
                  pageSize: nextSize,
                  // A new page size starts from the first page.
                  page: nextSize !== pageSize ? 1 : nextPage,
                })
              }
              onSortChange={(sort) => setFilters({ ...filters, sort, page: 1 })}
              onSelectionChange={setSelectedAssets}
              resetSelectionKey={selectionEpoch}
              toolbarStart={
                <>
                  {filterButtons}
                  {searchBox}
                </>
              }
              toolbarEnd={
                <>
                  <InventoryViewsMenu filters={filters} onToggle={togglePreset} />
                  {refreshButton}
                </>
              }
              hasFilters={!isInventoryFilterEmpty(filters)}
              typeView={typeView}
              onEditAsset={forms.openEdit}
              onDeleteAsset={forms.openDelete}
              {...(typeView &&
              isInventoryFilterEmpty({ ...filters, types: undefined, subType: undefined })
                ? {
                    emptyMessage: `No ${inSentence(typeView.plural)} yet`,
                    emptyDescription: emptyHint(typeView),
                  }
                : {})}
            />
          )}
        </div>
      </div>

      <InventoryBulkBar
        selected={selectedAssets}
        canWrite={canWrite}
        onClear={clearSelection}
        onDone={() => {
          clearSelection()
          refresh()
        }}
      />

      {forms.dialogs}

      <FilterSheet
        open={filterSheetOpen}
        onOpenChange={setFilterSheetOpen}
        title="Asset filters"
        resultLabel={`Show ${total.toLocaleString()} ${total === 1 ? 'asset' : 'assets'}`}
      >
        {facetPanel}
      </FilterSheet>
    </Main>
  )
}
