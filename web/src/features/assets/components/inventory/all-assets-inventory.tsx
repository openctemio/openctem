'use client'

/**
 * Unified All-Assets inventory: ONE server-paginated table across every asset
 * type, composed like the Findings list (the reference list page — see
 * docs/ui-style-contract.md): the open view's name and count, then a single
 * toolbar row above the table, a filter panel beside it and a floating
 * bulk-action bar. The views themselves (All assets and the registry's lenses,
 * with counts) are listed in the sidebar under Assets (research/242 D5).
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
 * included), picked from the sidebar's quick views; a type is a filter.
 */

import { AssetsSectionTabs } from '../assets-section-tabs'
import { useCallback, useEffect, useEffectEvent, useMemo, useState, type ReactNode } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Download, Lock, RefreshCw, Search } from 'lucide-react'
import { toast } from 'sonner'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'
import {
  inSentence,
  typeViewOf,
  viewHasExpiry,
  type TypeView,
} from '@/features/asset-types/lib/type-view'
import { propertyLabel } from '@/features/asset-types/lib/property-schema'
import { exportInventory } from '../../lib/inventory-export'
import { useInventoryAssetForms } from './inventory-asset-forms'
import { InventoryAddButton } from './inventory-add-button'
import { Main } from '@/components/layout'
import { PageHeader, EmptyState, FilterButton, FilterSheet } from '@/features/shared'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { usePermissions, Permission } from '@/lib/permissions'
import { useDebounce } from '@/hooks/use-debounce'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useLastVisit } from '../../hooks/use-last-visit'
import { useAssets, useAssetStats, type AssetSearchFilters } from '../../hooks/use-assets'
import type { Asset } from '../../types/asset.types'
import { useBusinessUnits } from '@/features/business-units/api/use-business-units'
import {
  buildFacetGroups,
  deactivatePreset,
  expiryPresets,
  triagePresets,
  type QuickPreset,
} from '../../lib/inventory-facets'
import {
  parseInventoryFilters,
  attributionQuery,
  ATTRIBUTION_FILTER_VALUES,
  serializeInventoryFilters,
  countActiveFilters,
  isInventoryFilterEmpty,
  toggleIncludedTag,
  DEFAULT_PAGE_SIZE,
  type InventoryFilters,
} from '../../lib/inventory-url'
import { InventoryViewsMenu } from './inventory-views-menu'
import { InventoryBulkBar } from './inventory-bulk-bar'
import { InventoryFacetPanel } from './inventory-facet-panel'
import { InventoryTable } from './inventory-table'
import { InventoryHiddenChip } from './inventory-hidden-chip'
import { InventoryFilterBar } from './inventory-filter-bar'
import { inventoryChips } from '../../lib/inventory-chips'
import { propertyLabel as attributeLabel } from '@/features/asset-types/lib/property-schema'
import { inventoryLenses, lensCounts } from '../../lib/inventory-lenses'

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
    tagsMode: f.tagsMode,
    excludeTags: f.excludeTags,
    dataClassifications: f.dataClassifications,
    environments: f.environments,
    providers: f.providers,
    businessUnitIds: f.businessUnitIds,
    hasOwner: f.hasOwner,
    isControlPlane: f.isControlPlane,
    isInternetFacing: f.isInternetFacing,
    isCrownJewel: f.isCrownJewel,
    programAssets: f.programAssets,
    freshness: f.freshness,
    coverage: f.coverage,
    technologies: f.technologies,
    technologyCategories: f.technologyCategories,
    hasFindings: f.hasFindings,
    lastSeenBefore: f.lastSeenBefore,
    lastSeenAfter: f.lastSeenAfter,
    expiresAfter: f.expiresAfter,
    expiresBefore: f.expiresBefore,
    attribution: attributionQuery(f),
    scopeStatus: f.scopeStatus,
    discoveredBy: f.discoveredBy,
    firstSeenAfter: f.firstSeenAfter,
    // Each row's attribution and the scan gate's answer (the scope badge).
    withTriage: true,
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
    /** True only before anything has ever loaded: also while the request
     * has not started yet (tenant or permissions still loading), so the
     * table shows a skeleton, never "No assets yet", until an answer came. */
    isFirstLoad: !settled && !result.isError && (result.isLoading || !result.hasLoaded),
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
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  // The viewer's previous visit, for "New since last visit" (research/124).
  const lastVisit = useLastVisit('inventory', currentTenant?.id)

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
  // A tag chip in a row or the detail sheet adds that tag to the filter, or
  // removes it when it is already there.
  const toggleTagFilter = useCallback(
    (tag: string) => setFilters(toggleIncludedTag(filters, tag)),
    [filters, setFilters]
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

  const [filterSheetOpen, setFilterSheetOpen] = useState(false)

  // Data. The headline numbers come from the tenant-wide stats endpoint.
  const searchFilters = useMemo(() => toSearchFilters(filters), [filters])
  const { assets, total, isFirstLoad, isLoading, isError, error, mutate } =
    useAssetsKeepingPrevious(searchFilters)
  const { stats, isLoading: statsLoading, mutate: statsMutate } = useAssetStats()
  // Business unit names label the Business unit facet and chip: asked for only
  // once something shows them (a chip, the filter sheet or the filter picker).
  const [facetsWanted, setFacetsWanted] = useState(false)
  const { data: buData } = useBusinessUnits(
    undefined,
    facetsWanted || filterSheetOpen || Boolean(filters.businessUnitIds?.length)
  )

  // Typed mode: the list is one type (and maybe one sub-type).
  const { registry } = useAssetTypeRegistry()
  const typeView = useMemo(
    () => typeViewOf(registry, filters.types, filters.subType),
    [registry, filters.types, filters.subType]
  )
  const facetKeys = useMemo(() => typeView?.facets.map((f) => f.key) ?? [], [typeView])
  // The open lens (when the list is one lens and not one type).
  const lens = useMemo(
    () =>
      !typeView && filters.lens
        ? inventoryLenses(registry).find((l) => l.id === filters.lens)
        : undefined,
    [registry, typeView, filters.lens]
  )
  const lensLabel = lens ? t(`assets.lens.${lens.id}`, lens.label) : undefined
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
  // Type counts for the Type facet: the open lens's types, or every type,
  // from the caller's scoped, unfiltered stats.
  const typeOptions = useMemo(() => {
    const counts = lensCounts(registry, stats.byTypeSubType)
    const chips = filters.lens
      ? (counts.chips[filters.lens] ?? [])
      : Object.values(counts.chips).flat()
    const labels: Record<string, string> = {}
    const values: Record<string, number> = {}
    for (const c of chips) {
      labels[c.type] = t(`assets.typeLabel.${c.type}`, c.label)
      values[c.type] = (values[c.type] ?? 0) + c.count
    }
    if (!filters.lens) {
      for (const type of counts.otherTypes) labels[type] ??= t(`assets.typeLabel.${type}`, type)
    }
    return { labels, counts: values }
  }, [registry, stats.byTypeSubType, filters.lens, t])
  const attributeFacets = useMemo(
    () =>
      (typeView?.facets ?? []).map((attribute) => ({
        attribute,
        label: propertyLabel(attribute.key),
        counts: typeStats.metadataCounts?.[attribute.key] ?? {},
      })),
    [typeView, typeStats]
  )
  const businessUnitLabels = useMemo(() => {
    const map: Record<string, string> = {}
    for (const bu of buData?.data ?? []) map[bu.id] = bu.name
    return map
  }, [buData])

  const facetGroups = useMemo(
    () => buildFacetGroups(businessUnitLabels, t, typeOptions),
    [businessUnitLabels, t, typeOptions]
  )
  // The expiry views, for a list that can hold expiring assets. Built on
  // every render (two small objects) so their "now" is never stale.
  const extraPresets = [
    ...triagePresets(lastVisit),
    ...(viewHasExpiry(typeView) ? expiryPresets() : []),
  ]

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

  // Search has its own box in the toolbar, and the lens is the open view (the
  // sidebar's quick view), so the filter button counts the rest.
  const activeCount =
    countActiveFilters(filters) - (filters.search ? 1 : 0) - (filters.lens ? 1 : 0)
  // Clearing the filters keeps the open view.
  const clearAll = useCallback(
    () => setFilters({ lens: filters.lens, sort: filters.sort, pageSize: filters.pageSize }),
    [setFilters, filters.lens, filters.sort, filters.pageSize]
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
      toast.error(t('assets.inventoryPage.exportFailed', 'Failed to export assets'))
    } finally {
      setExporting(false)
    }
  }, [exporting, searchFilters, typeView, t])

  if (!canRead) {
    return (
      <Main>
        <PageHeader title={t('assets.overview.title', 'Assets')} />
        <EmptyState
          className="mt-8 border-dashed"
          icon={Lock}
          title={t('assets.inventoryPage.noAccess', "You don't have access to assets")}
          description={t(
            'assets.inventoryPage.noAccessHint',
            'Ask an administrator for the assets:read permission to view the inventory.'
          )}
        />
      </Main>
    )
  }

  const facetPanel = (
    <InventoryFacetPanel
      groups={facetGroups}
      filters={filters}
      stats={scopeLabel ? typeStats : stats}
      onChange={setFilters}
      attributeFacets={attributeFacets}
      tagTypes={typeView ? [typeView.type] : undefined}
      activeCount={activeCount}
      onClearAll={clearAll}
    />
  )

  // Phones and narrow windows: the facets open in a sheet. From `lg` up the
  // filter row's Add filter does the same job without taking the table's width.
  const filterButtons = (
    <FilterButton
      className="lg:hidden"
      onClick={() => setFilterSheetOpen(true)}
      aria-haspopup="dialog"
      activeCount={activeCount}
    />
  )

  const chips = inventoryChips(filters, {
    groups: facetGroups,
    t,
    propertyLabel: attributeLabel,
    formatDate: (iso) => {
      const d = new Date(iso)
      return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString()
    },
  })

  const searchBox = (
    <div className="relative min-w-0 flex-1 sm:max-w-sm">
      <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={searchInput}
        onChange={(e) => setSearchInput(e.target.value)}
        placeholder={t('assets.inventoryPage.search', 'Search name, description or alias…')}
        aria-label={t('assets.inventoryPage.searchAria', 'Search assets')}
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
          aria-label={t('assets.inventoryPage.refresh', 'Refresh')}
        >
          <RefreshCw className={cn('h-4 w-4', (isLoading || statsLoading) && 'animate-spin')} />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{t('assets.inventoryPage.refresh', 'Refresh')}</TooltipContent>
    </Tooltip>
  )

  const page = filters.page ?? 1
  const pageSize = filters.pageSize ?? DEFAULT_PAGE_SIZE

  return (
    <Main>
      <PageHeader title={t('assets.overview.title', 'Assets')} viewSwitcher={viewSwitcher}>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void handleExport()}
          disabled={exporting}
        >
          <Download className="me-2 h-4 w-4" />
          {exporting
            ? t('assets.inventoryPage.exporting', 'Exporting…')
            : t('assets.inventoryPage.export', 'Export')}
        </Button>
        {canWrite && (
          <InventoryAddButton registry={registry} view={typeView} onAdd={forms.openCreate} />
        )}
      </PageHeader>
      <AssetsSectionTabs />

      <div className="mt-5 flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <h2 data-testid="inventory-view-title" className="text-base font-semibold">
          {scopeLabel ?? t('assets.quickView.all', 'All assets')}
        </h2>
        <span className="text-sm tabular-nums text-muted-foreground">
          {(scopeLabel ? typeStatsLoading : statsLoading)
            ? ''
            : (scopeLabel ? typeStats : stats).total.toLocaleString()}
        </span>
        {lens?.description && (
          <span className="text-xs text-muted-foreground">
            {t(`assets.lensDescription.${lens.id}`, lens.description)}
          </span>
        )}
      </div>

      <div className="mt-3">
        <div className="min-w-0">
          {isError ? (
            <Alert variant="destructive">
              <AlertTitle>
                {t('assets.inventoryPage.loadFailed', 'Failed to load assets')}
              </AlertTitle>
              <AlertDescription>
                <p>
                  {error?.message ||
                    t('assets.inventoryPage.unexpected', 'An unexpected error occurred.')}
                </p>
                <Button variant="outline" size="sm" className="mt-2" onClick={refresh}>
                  <RefreshCw className="me-2 h-4 w-4" />
                  {t('assets.inventoryPage.retry', 'Retry')}
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
              filterTags={filters.tags}
              onToggleTagFilter={toggleTagFilter}
              toolbarStart={
                <>
                  {filterButtons}
                  {searchBox}
                </>
              }
              toolbarEnd={
                <>
                  <InventoryViewsMenu
                    filters={filters}
                    onToggle={togglePreset}
                    extraPresets={extraPresets}
                  />
                  {refreshButton}
                </>
              }
              toolbarBelow={
                <InventoryFilterBar
                  leading={
                    !filters.attribution?.length ? (
                      <InventoryHiddenChip
                        onShowAll={() =>
                          setFilters({
                            ...filters,
                            attribution: [...ATTRIBUTION_FILTER_VALUES],
                            page: 1,
                          })
                        }
                      />
                    ) : undefined
                  }
                  chips={chips}
                  groups={facetGroups}
                  attributeFacets={attributeFacets}
                  tagTypes={typeView ? [typeView.type] : undefined}
                  filters={filters}
                  stats={scopeLabel ? typeStats : stats}
                  onChange={setFilters}
                  onClearAll={clearAll}
                  onPickerOpenChange={(open) => open && setFacetsWanted(true)}
                  // The table (and this bar) only renders after the first load,
                  // so the count is always known here.
                  resultLabel={t(
                    'assets.filters.results',
                    '{count, plural, one {# asset} other {# assets}}',
                    { count: total }
                  )}
                />
              }
              hasFilters={!isInventoryFilterEmpty(filters)}
              typeView={typeView}
              onEditAsset={forms.openEdit}
              onDeleteAsset={forms.openDelete}
              {...(typeView &&
              isInventoryFilterEmpty({ ...filters, types: undefined, subType: undefined })
                ? {
                    emptyMessage: t('assets.inventoryPage.emptyType', 'No {type} yet', {
                      type: inSentence(typeView.plural),
                    }),
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
        title={t('assets.inventoryPage.filters', 'Asset filters')}
        resultLabel={
          total === 1
            ? t('assets.inventoryPage.showOne', 'Show 1 asset')
            : t('assets.inventoryPage.showMany', 'Show {count} assets', {
                count: total.toLocaleString(),
              })
        }
      >
        {facetPanel}
      </FilterSheet>
    </Main>
  )
}
