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

import { useOpenForm } from '@/hooks/use-open-form'
import { ScopingDecisionCards } from '../attention/attention-reasons'
import { AssetsSectionTabs } from '../assets-section-tabs'
import { useCallback, useEffect, useEffectEvent, useMemo, useState, type ReactNode } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Boxes, Download, EyeOff, Lock, Network, RefreshCw } from 'lucide-react'
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
import Link from '@/components/link'
import { Main } from '@/components/layout'
import {
  PageHeader,
  PageStack,
  EmptyState,
  ErrorState,
  FilterPanelSlot,
  FilterSheet,
  useFilterPanelOpen,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useLastVisit } from '../../hooks/use-last-visit'
import { useCommittedSearch } from '../../hooks/use-committed-search'
import {
  buildAssetQueryParams,
  useAssets,
  useAssetNetworks,
  useAssetStats,
  type AssetSearchFilters,
} from '../../hooks/use-assets'
import { advancedAssetsDocument } from '../../api/advanced-fetch'
import { queryApi } from '@/features/query/api/query-api'
import { useSavedViews, type SavedView } from '@/features/saved-views/api/use-saved-views'
import { applyTextResult } from '../../lib/inventory-text'
import { formatTotal } from '../../lib/capped-count'
import { TABS_LENS, openTab, tabCounts, withTab } from '../../lib/inventory-tabs'
import { InventoryTypeTabs } from './inventory-type-tabs'
import { InventoryNetworks } from './inventory-networks'
import { FilterGroupActions } from '@/features/asset-groups/components/filter-group-actions'
import type { Asset } from '../../types/asset.types'
import { useBusinessUnits } from '@/features/business-units/api/use-business-units'
import {
  buildFacetGroups,
  deactivatePreset,
  expiryPresets,
  tabPresets,
  triagePresets,
  applyPreset,
  QUICK_PRESETS,
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
    isPrimary: f.isPrimary,
    programAssets: f.programAssets,
    freshness: f.freshness,
    resolution: f.resolution,
    coverage: f.coverage,
    coverageCause: f.coverageCause,
    technologies: f.technologies,
    technologyCategories: f.technologyCategories,
    technologyVersion: f.technologyVersion,
    hasFindings: f.hasFindings,
    lastSeenBefore: f.lastSeenBefore,
    lastSeenAfter: f.lastSeenAfter,
    expiresAfter: f.expiresAfter,
    expiresBefore: f.expiresBefore,
    extra: f.extra,
    advanced: f.advanced,
    attribution: attributionQuery(f),
    scopeStatus: f.scopeStatus,
    monitoringState: f.monitoringState,
    liveness: f.liveness,
    discoveredBy: f.discoveredBy,
    firstSeenAfter: f.firstSeenAfter,
    firstSeenBefore: f.firstSeenBefore,
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
  const [settled, setSettled] = useState<{
    assets: Asset[]
    total: number
    totalCapped: boolean
  } | null>(null)
  const isSettled = !result.isLoading && !result.isError
  if (isSettled && (settled?.assets !== result.assets || settled.total !== result.total)) {
    setSettled({ assets: result.assets, total: result.total, totalCapped: result.totalCapped })
  }
  const shown = result.isLoading && settled ? settled : result
  return {
    ...result,
    assets: shown.assets,
    total: shown.total,
    totalCapped: shown.totalCapped,
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

/**
 * The viewer's own filter as a comparable string (no paging, sort, grouping or
 * open view): what tells an open saved view from the list on screen.
 */
function filterKey(f: InventoryFilters): string {
  const sp = serializeInventoryFilters({
    ...f,
    page: undefined,
    pageSize: undefined,
    sort: undefined,
    group: undefined,
    view: undefined,
  })
  sp.sort()
  return sp.toString()
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

/** Per-browser memory of the side panel (Findings uses the same shape). */
const FILTERS_OPEN_KEY = 'openctem:assets-filters-open'

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

  // The open tab is a locked type condition: the list runs with it, while the
  // chips, the query text and saved views are the viewer's own filter.
  const tab = openTab(filters)
  const runFilters = useMemo(() => withTab(filters), [filters])

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

  // The search box, settled into the URL (`q`) without a replace() per key.
  // The other filters are read at commit time, so changing one of them never
  // pushes a stale search back into the URL.
  const [searchInput, setSearchInput] = useCommittedSearch(filters.search, (next) =>
    setFilters({ ...filters, search: next || undefined, page: 1 })
  )

  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  // The side panel, as on Findings: closed until the viewer opens it, then remembered.
  const [filtersOpen, setFiltersOpen] = useFilterPanelOpen(FILTERS_OPEN_KEY)

  // Data. The headline numbers come from the tenant-wide stats endpoint.
  const searchFilters = useMemo(() => toSearchFilters(runFilters), [runFilters])
  // The filter on screen as list parameters, for "Save filter as group" and "Add all matching".
  const filterParams = useMemo(() => buildAssetQueryParams(searchFilters), [searchFilters])
  const { assets, total, totalCapped, isFirstLoad, isLoading, isError, error, mutate } =
    useAssetsKeepingPrevious(searchFilters)
  const { stats, isLoading: statsLoading, mutate: statsMutate } = useAssetStats()
  // The External surface lens's own counts, for its type tabs (the same request
  // as the tenant-wide stats above everywhere else).
  const inTabsLens = filters.lens === TABS_LENS
  const { stats: lensStats, mutate: lensStatsMutate } = useAssetStats({
    lenses: inTabsLens ? [TABS_LENS] : undefined,
  })
  const tabTotals = useMemo(
    () => (inTabsLens ? tabCounts(lensStats.byTypeSubType) : undefined),
    [inTabsLens, lensStats.byTypeSubType]
  )
  // A page past the end (an old link, a list that shrank) shows the last page
  // instead of an empty table under "Showing 1961 - 11 of 11".
  const clampPage = useEffectEvent((lastPage: number) => setFilters({ ...filters, page: lastPage }))
  useEffect(() => {
    const size = filters.pageSize ?? DEFAULT_PAGE_SIZE
    if (isLoading || isError || total <= 0) return
    const lastPage = Math.max(1, Math.ceil(total / size))
    if ((filters.page ?? 1) > lastPage) clampPage(lastPage)
  }, [filters.page, filters.pageSize, total, isLoading, isError])
  // Business unit names label the Business unit facet and chip: asked for only
  // once something shows them (a chip, the filter sheet or the filter picker).
  const [facetsWanted, setFacetsWanted] = useState(false)
  const { data: buData } = useBusinessUnits(
    undefined,
    facetsWanted || filterSheetOpen || filtersOpen || Boolean(filters.businessUnitIds?.length)
  )

  // Typed mode: the list is one type (and maybe one sub-type).
  const { registry } = useAssetTypeRegistry()
  const typeView = useMemo(
    () => typeViewOf(registry, runFilters.types, runFilters.subType),
    [registry, runFilters.types, runFilters.subType]
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

  // An open tab locks the type, so the Type facet is not offered then.
  const facetGroups = useMemo(
    () => buildFacetGroups(businessUnitLabels, t, tab ? undefined : typeOptions),
    [businessUnitLabels, t, typeOptions, tab]
  )
  // The starter views: the common ones, the open tab's own, the triage views
  // and, for a list that can hold expiring assets, the expiry views. Built on
  // every render (a few small objects) so their "now" is never stale.
  const presets = [
    ...QUICK_PRESETS,
    ...tabPresets(tab?.id),
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
        setFilters(applyPreset(filters, preset))
      }
    },
    [filters, setFilters]
  )

  // Type tabs: a different set of assets, so the filters of the old one reset.
  const selectTab = useCallback(
    (id: string | undefined) =>
      setFilters({ lens: filters.lens, tab: id, sort: filters.sort, pageSize: filters.pageSize }),
    [setFilters, filters.lens, filters.sort, filters.pageSize]
  )
  // A network (a click on a row or a group): list its addresses.
  const filterNetwork = useCallback(
    (network: string) =>
      setFilters({
        ...filters,
        extra: { ...(filters.extra ?? {}), network },
        group: undefined,
        page: 1,
      }),
    [filters, setFilters]
  )
  const groupedByNetwork = filters.group === 'network' && typeView?.type === 'ip_address'
  const networkList = useAssetNetworks(searchFilters, groupedByNetwork)
  const networksMutate = networkList.mutate

  // Saved views (page assets). A view is opened by materializing its checked
  // document into the page's filters, so chips and text show what it holds.
  const { views: savedViews } = useSavedViews('assets', Boolean(filters.view))
  const activeView = savedViews.find((v) => v.id === filters.view)
  const [viewBaseline, setViewBaseline] = useState<{ id: string; key: string } | null>(null)
  useEffect(() => {
    if (!activeView || viewBaseline?.id === activeView.id) return
    let cancelled = false
    queryApi
      .parse({ entity: 'assets', document: activeView.filter })
      .then((r) => {
        if (!cancelled)
          setViewBaseline({ id: activeView.id, key: filterKey(applyTextResult({}, r)) })
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [activeView, viewBaseline?.id])
  const viewModified = Boolean(
    activeView && viewBaseline?.id === activeView.id && viewBaseline.key !== filterKey(filters)
  )
  const openView = useCallback(
    async (view: SavedView | null) => {
      if (!view) {
        setFilters({ sort: filters.sort, pageSize: filters.pageSize })
        return
      }
      try {
        const r = await queryApi.parse({ entity: 'assets', document: view.filter })
        if (!r.valid) throw new Error('invalid')
        setFilters({
          ...applyTextResult({ sort: filters.sort, pageSize: filters.pageSize }, r),
          view: view.id,
        })
      } catch {
        toast.error(t('assets.views.openFailed', 'This view could not be opened'))
      }
    },
    [filters.sort, filters.pageSize, setFilters, t]
  )
  const discardViewChanges = useCallback(async () => {
    const view = savedViews.find((v) => v.id === filters.view)
    if (view) await openView(view)
  }, [savedViews, filters.view, openView])
  // What a saved view stores: the list's own params with the tab's type, or the
  // checked document of a filter given as text. Never the page's paging.
  const resolveViewFilter = useCallback(async () => {
    const base = toSearchFilters(runFilters)
    const params = buildAssetQueryParams({
      ...base,
      attribution: filters.attribution,
      withTriage: false,
      page: undefined,
      pageSize: undefined,
    })
    if (filters.advanced) {
      return {
        filter: await advancedAssetsDocument(`/api/v1/assets?${new URLSearchParams(params)}`),
      }
    }
    return { query: new URLSearchParams(params).toString() }
  }, [runFilters, filters.attribution, filters.advanced])

  // Search has its own box in the toolbar, and the lens is the open view (the
  // sidebar's quick view), so the filter button counts the rest.
  const activeCount =
    countActiveFilters(filters) - (filters.search ? 1 : 0) - (filters.lens ? 1 : 0)
  // Clearing the filters keeps the open view.
  const clearAll = useCallback(
    () =>
      setFilters({
        lens: filters.lens,
        tab: filters.tab,
        sort: filters.sort,
        pageSize: filters.pageSize,
      }),
    [setFilters, filters.lens, filters.tab, filters.sort, filters.pageSize]
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
    void lensStatsMutate()
    void networksMutate()
  }, [mutate, statsMutate, typeStatsMutate, lensStatsMutate, networksMutate])

  const forms = useInventoryAssetForms(registry, refresh)
  // "Add asset" from the Create menu or its "c a" chord: this list's own type,
  // else the type menu of the Add button.
  const [addMenuOpen, setAddMenuOpen] = useState(false)
  const openAddForm = useCallback(() => {
    if (typeView) forms.openCreate(typeView)
    else setAddMenuOpen(true)
  }, [typeView, forms])
  useOpenForm('asset', canWrite && !!registry?.types?.length, openAddForm)
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
        <PageStack>
          <PageHeader title={t('assets.overview.title', 'Assets')} />
          <EmptyState
            className="border-dashed"
            icon={Lock}
            title={t('assets.inventoryPage.noAccess', "You don't have access to assets")}
            description={t(
              'assets.inventoryPage.noAccessHint',
              'Ask an administrator for the assets:read permission to view the inventory.'
            )}
          />
        </PageStack>
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

  // From `lg` up the button toggles the side panel; below it opens the same
  // facets in a sheet. Add filter stays in the filter row for the chips and the
  // advanced attribute filters.
  const filterToggle = {
    open: filtersOpen,
    onToggle: () => setFiltersOpen((o) => !o),
    onOpenSheet: () => setFilterSheetOpen(true),
    activeCount,
    controlsId: 'asset-filters',
  }

  const chips = inventoryChips(filters, {
    groups: facetGroups,
    t,
    propertyLabel: attributeLabel,
    formatDate: (iso) => {
      const d = new Date(iso)
      return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString()
    },
  })

  const search = {
    value: searchInput,
    onChange: setSearchInput,
    placeholder: t('assets.inventoryPage.search', 'Search name, description or alias…'),
    label: t('assets.inventoryPage.searchAria', 'Search assets'),
  }

  const refreshButton = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"

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

  // The default list leaves out names awaiting review and names marked not
  // ours (the locked chip says so). The heading counts every asset of the
  // view; with no other filter, the difference is exactly what the chip
  // hides, so the three numbers on the page add up.
  const hideActive = !filters.attribution?.length
  const viewTotal = tab ? (tabTotals?.[tab.id] ?? 0) : (scopeLabel ? typeStats : stats).total
  const onlyDefaults = isInventoryFilterEmpty({ ...filters, types: undefined, subType: undefined })
  const hiddenCount =
    hideActive && onlyDefaults && !isLoading && !statsLoading && !typeStatsLoading
      ? Math.max(0, viewTotal - total)
      : undefined
  const showAllAttributions = () =>
    setFilters({ ...filters, attribution: [...ATTRIBUTION_FILTER_VALUES], page: 1 })
  // An empty list while the default hide is on is not "nothing yet": say what
  // is left out and offer to show it.
  const hiddenEmpty =
    hideActive && total === 0 && viewTotal > 0 ? (
      <EmptyState
        icon={EyeOff}
        title={t('assets.hidden.emptyTitle', 'No confirmed assets match')}
        description={t(
          'assets.hidden.emptyHint',
          'Names awaiting review and names marked not yours are not in this list. Show them to search every asset.'
        )}
        action={
          <Button variant="outline" size="sm" onClick={showAllAttributions}>
            {t('assets.hidden.showAll', 'Show all assets')}
          </Button>
        }
      />
    ) : undefined
  // Nothing in the view at all, and no filter or search: the organization
  // has no such assets yet. Say so (not "no match") and offer the ways in.
  const noneEmpty =
    !hiddenEmpty &&
    total === 0 &&
    viewTotal === 0 &&
    onlyDefaults &&
    !isLoading &&
    !statsLoading &&
    !typeStatsLoading ? (
      <EmptyState
        icon={Boxes}
        title={t('assets.inv.emptyNoneTitle', 'No assets in this organization yet')}
        description={t(
          'assets.inv.emptyNoneHint',
          'Add an asset, or set up discovery to find the names, addresses and services your organization exposes.'
        )}
        action={
          <div className="flex flex-wrap justify-center gap-2">
            {canWrite && (
              <InventoryAddButton registry={registry} view={typeView} onAdd={forms.openCreate} />
            )}
            <Button variant="outline" size="sm" asChild>
              <Link href="/attack-surface">
                {t('assets.inv.setUpDiscovery', 'Set up discovery')}
              </Link>
            </Button>
          </div>
        }
      />
    ) : undefined

  return (
    <Main>
      <PageStack>
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
            <InventoryAddButton
              registry={registry}
              view={typeView}
              onAdd={forms.openCreate}
              open={addMenuOpen}
              onOpenChange={setAddMenuOpen}
            />
          )}
        </PageHeader>
        <AssetsSectionTabs />
        {/* Scoping decisions waiting (root domains to validate, names to
            decide), only on the whole inventory and only when some wait. */}
        {!typeView && !scopeLabel && <ScopingDecisionCards />}

        {inTabsLens && (
          <InventoryTypeTabs
            value={tab?.id}
            counts={tabTotals}
            total={lensStats.total}
            onChange={selectTab}
          />
        )}

        <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <h2 data-testid="inventory-view-title" className="text-base font-semibold">
            {scopeLabel ?? t('assets.quickView.all', 'All assets')}
          </h2>
          <span className="text-sm tabular-nums text-muted-foreground">
            {(scopeLabel ? typeStatsLoading : statsLoading) ? '' : viewTotal.toLocaleString()}
          </span>
          {lens?.description && (
            <span className="text-xs text-muted-foreground">
              {t(`assets.lensDescription.${lens.id}`, lens.description)}
            </span>
          )}
        </div>

        <div className="flex items-start">
          <FilterPanelSlot
            open={filtersOpen}
            id="asset-filters"
            label={t('assets.inventoryPage.filters', 'Asset filters')}
          >
            {facetPanel}
          </FilterPanelSlot>
          <div className="min-w-0 flex-1">
            {isFirstLoad && !isError ? (
              <InventoryTableSkeleton />
            ) : (
              <InventoryTable
                // A failed read keeps the toolbar, so a bad search or filter
                // from a shared link can still be changed.
                errorState={
                  isError ? (
                    <ErrorState
                      title={t('assets.inventoryPage.errorTitle', 'assets')}
                      error={error}
                      onRetry={refresh}
                    />
                  ) : groupedByNetwork ? (
                    // Group by network replaces the rows; the toolbar stays.
                    <InventoryNetworks
                      networks={networkList.networks}
                      capped={networkList.capped}
                      isLoading={networkList.isLoading}
                      error={networkList.isError ? true : undefined}
                      onRetry={refresh}
                      onFilter={filterNetwork}
                    />
                  ) : undefined
                }
                emptyState={hiddenEmpty ?? noneEmpty}
                onFilterNetwork={filterNetwork}
                totalCapped={totalCapped}
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
                search={search}
                filterToggle={filterToggle}
                toolbarEnd={
                  <>
                    {typeView?.type === 'ip_address' && !typeView.subType && (
                      <Button
                        variant={groupedByNetwork ? 'secondary' : 'outline'}
                        size="sm"
                        aria-pressed={groupedByNetwork}
                        disabled={Boolean(filters.advanced)}
                        title={
                          filters.advanced
                            ? t(
                                'assets.ip.groupDisabled',
                                'Not available for a filter given as query text'
                              )
                            : undefined
                        }
                        onClick={() =>
                          setFilters({
                            ...filters,
                            group: groupedByNetwork ? undefined : 'network',
                            page: 1,
                          })
                        }
                      >
                        <Network className="me-2 h-4 w-4" />
                        {t('assets.ip.groupBy', 'Group by network /24')}
                      </Button>
                    )}
                    <InventoryViewsMenu
                      filters={filters}
                      presets={presets}
                      onToggle={togglePreset}
                      resolveFilter={resolveViewFilter}
                      modified={viewModified}
                      onDiscard={() => void discardViewChanges()}
                      onSelect={(v) => void openView(v)}
                    />
                    {!isInventoryFilterEmpty(filters) && !filters.advanced && (
                      <FilterGroupActions params={filterParams} total={total} />
                    )}
                    {refreshButton}
                  </>
                }
                toolbarBelow={
                  <InventoryFilterBar
                    locked={
                      !filters.attribution?.length &&
                      hiddenCount !== undefined &&
                      hiddenCount > 0 ? (
                        <InventoryHiddenChip count={hiddenCount} onShowAll={showAllAttributions} />
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
                    resultLabel={
                      totalCapped
                        ? t('assets.filters.resultsCapped', '{count}+ assets', {
                            count: total.toLocaleString(),
                          })
                        : t(
                            'assets.filters.results',
                            '{count, plural, one {# asset} other {# assets}}',
                            {
                              count: total,
                            }
                          )
                    }
                    resultCount={total}
                    preferFields={tab?.fields}
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
      </PageStack>

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
                count: formatTotal(total, totalCapped, t),
              })
        }
      >
        {facetPanel}
      </FilterSheet>
    </Main>
  )
}
