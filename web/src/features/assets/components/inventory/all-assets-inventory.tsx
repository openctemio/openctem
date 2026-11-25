'use client'

/**
 * Unified All-Assets inventory: ONE server-paginated table across every asset
 * type, composed like the Findings list (the reference list page — see
 * docs/ui-style-contract.md): the open view's name and count, then a single
 * toolbar row above the table (Add filter is its one filter entry; a phone
 * opens every facet in a sheet) and a floating bulk-action bar. The views themselves (All assets and the registry's lenses,
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
import { AssetsSectionTabs } from '../assets-section-tabs'
import {
  useCallback,
  useEffect,
  useEffectEvent,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Boxes, Download, EyeOff, MoreHorizontal, Network, RefreshCw } from 'lucide-react'
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
  NoAccessState,
  FilterSheet,
  usePhoneSelectMode,
} from '@/features/shared'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { useIsMobile } from '@/hooks/use-mobile'
import { copyToClipboard } from '@/lib/clipboard'
import { shareableLink } from '@/lib/org-link'
import {
  ListCount,
  ListTitleRow,
  ListViewChanged,
} from '@/features/shared/components/list-title-row'
import type { SavedViewsActions } from '@/features/saved-views/components/saved-views-menu'
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
import { applyTextResult, textParams } from '../../lib/inventory-text'
import {
  useListQueryMode,
  viewOpensInQueryMode,
  withQueryMode,
} from '@/features/query/components/query-mode'
import { formatTotal } from '../../lib/capped-count'
import { TABS_LENS, openTab, tabCounts, withTab } from '../../lib/inventory-tabs'
import { InventoryTypeSelect } from './inventory-type-select'
import { InventoryNetworks } from './inventory-networks'
import {
  FilterGroupActions,
  filterHasNoGroupRule,
  type FilterGroupDialog,
} from '@/features/asset-groups/components/filter-group-actions'
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
import { useInventoryTableBulk } from './inventory-bulk-bar'
import { InventoryFacetPanel } from './inventory-facet-panel'
import { InventoryTable } from './inventory-table'
import { InventoryHiddenChip } from './inventory-hidden-chip'
import { InventoryAddFilter, InventoryFilterBar } from './inventory-filter-bar'
import { InventoryProviderChip } from './inventory-provider-chip'
import { inventoryChips } from '../../lib/inventory-chips'
import { propertyLabel as attributeLabel } from '@/features/asset-types/lib/property-schema'
import { inventoryLenses, lensCounts } from '../../lib/inventory-lenses'
import { formatDate, formatNumber } from '@/lib/app-locale'

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
function emptyHint(
  view: TypeView,
  t: (key: string, fallback?: string, vars?: Record<string, string | number>) => string
): string {
  if (view.type === 'repository') {
    return t(
      'assets.inventoryPage.emptyHint.repository',
      'Connect a source-code integration in Settings to import repositories, or add one.'
    )
  }
  if (view.type === 'cloud_account') {
    return t(
      'assets.inventoryPage.emptyHint.cloudAccount',
      'Connect a cloud integration in Settings to import accounts, or add one.'
    )
  }
  const type = inSentence(view.plural)
  return view.scannable
    ? t(
        'assets.inventoryPage.emptyHint.scannable',
        'Add one, or run a discovery scan to find {type}.',
        { type }
      )
    : t(
        'assets.inventoryPage.emptyHint.imported',
        'Add one, or import {type} from a connected source.',
        { type }
      )
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
    // The search mode is how the filter is shown, not a change to the view.
    queryMode: undefined,
  })
  sp.sort()
  return sp.toString()
}

/** First-load placeholder shaped like the toolbar + table it stands in for. */
function InventoryTableSkeleton() {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Skeleton className="h-control min-w-0 flex-1" />
        <Skeleton className="h-control w-28 shrink-0" />
      </div>
      <div className="space-y-2 rounded-md border p-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    </div>
  )
}

/**
 * The list's order while the address names none: risk, highest first, so the
 * order a person sees is explained by a column on screen (Risk carries the
 * sort arrow). Assets of one score follow by name.
 */
const DEFAULT_SORT = '-risk_score'
const DEFAULT_SORT_REQUEST = `${DEFAULT_SORT},name`

export function AllAssetsInventory({ viewSwitcher }: { viewSwitcher?: ReactNode } = {}) {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const { can } = usePermissions()
  const canRead = can(Permission.AssetsRead)
  const canWrite = can(Permission.AssetsWrite)
  const { t, locale } = useTranslation()
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
      // The search mode stays unless the change sets it (a tab, a lens or
      // clearing the filters keeps Query mode).
      const qs = serializeInventoryFilters({ queryMode: filters.queryMode, ...next }).toString()
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false })
    },
    [router, pathname, filters.queryMode]
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

  // Data. The headline numbers come from the tenant-wide stats endpoint.
  const searchFilters = useMemo(
    () => toSearchFilters({ ...runFilters, sort: runFilters.sort ?? DEFAULT_SORT_REQUEST }),
    [runFilters]
  )
  // The filter on screen as list parameters, for "Save filter as group" and "Add all matching".
  const filterParams = useMemo(() => buildAssetQueryParams(searchFilters), [searchFilters])
  const { assets, total, totalCapped, isFirstLoad, isLoading, isError, error, mutate } =
    useAssetsKeepingPrevious(searchFilters)
  // Provider addresses (research/531) leave the default list and its totals;
  // the chip counts them for the same view, and is not asked for otherwise.
  const providerOnly = useMemo(
    () => ({
      ...searchFilters,
      attribution: ['provider_address'],
      withTriage: false,
      page: 1,
      pageSize: 1,
      skip: !!runFilters.attribution?.length,
    }),
    [searchFilters, runFilters.attribution]
  )
  const { total: providerCount, hasLoaded: providerLoaded } = useAssets(providerOnly)
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
    facetsWanted || filterSheetOpen || Boolean(filters.businessUnitIds?.length)
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
        label: propertyLabel(attribute.key, locale),
        counts: typeStats.metadataCounts?.[attribute.key] ?? {},
      })),
    [typeView, typeStats, locale]
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
          // The view opens in the search mode it was saved in.
          queryMode: viewOpensInQueryMode(view) || undefined,
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

  const refresh = useCallback(() => {
    void mutate()
    void statsMutate()
    void typeStatsMutate()
    void lensStatsMutate()
    void networksMutate()
  }, [mutate, statsMutate, typeStatsMutate, lensStatsMutate, networksMutate])

  const forms = useInventoryAssetForms(registry, refresh)

  // Several assets at once: the table draws the checkbox column and the bulk
  // bar (two direct actions, the rest under More). Without a bulk permission
  // there is no checkbox column.
  const tableBulk = useInventoryTableBulk({ canWrite, onDone: refresh })
  const assetsBulk = tableBulk.bulk
  // Row selection: the table owns the checkboxes; a new query clears them, so
  // the bulk bar only ever acts on rows of the current view. Switching the
  // search mode changes no rows.
  const clearSelection = tableBulk.clear
  const queryKey = withQueryMode(searchParams, false).toString()
  useEffect(() => {
    clearSelection()
  }, [queryKey, clearSelection])
  // Phone cards have no header checkbox: "Select" starts the list's More.
  const isPhone = useIsMobile()
  const phoneSelect = usePhoneSelectMode(isPhone && !!assetsBulk)
  // "Save filter as group" and "Add all matching to group", from the list's More.
  const [groupDialog, setGroupDialog] = useState<FilterGroupDialog | null>(null)
  const viewsActions = useRef<SavedViewsActions>(null)
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

  // Query mode of the search field: the same filter as one line of query
  // text (chips and text are two views of one state, lib/inventory-text).
  const queryMode = useListQueryMode({
    entity: 'assets',
    active: !!filters.queryMode,
    onActiveChange: (on) => setFilters({ ...filters, queryMode: on || undefined }),
    fq: filters.advanced ?? null,
    params: textParams(filters),
    onApply: (r, on) =>
      setFilters({ ...applyTextResult(filters, r), page: 1, queryMode: on || undefined }),
    resultCount: isLoading ? null : total,
    preferFields: tab?.fields,
    recentScope: filters.tab ? `assets:${filters.tab}` : 'assets',
    testId: 'inventory-query-editor',
  })

  if (!canRead) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={t('assets.overview.title', 'Assets')} />
          <NoAccessState
            title={inSentence(t('assets.overview.title', 'Assets'))}
            permission={Permission.AssetsRead}
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

  // One filter entry per width, and no docked panel: from 768 Add filter
  // (right after the field) opens its picker; on a phone the Filters button,
  // joined to the search field, opens every facet in a sheet.
  const filterToggle = {
    open: filterSheetOpen,
    onToggle: () => setFilterSheetOpen(true),
    onOpenSheet: () => setFilterSheetOpen(true),
    activeCount,
    controlsId: 'asset-filters',
    sheetOnly: true,
  }

  const chips = inventoryChips(filters, {
    groups: facetGroups,
    t,
    propertyLabel: (key) => attributeLabel(key, locale),
    formatDate: (iso) => {
      const d = new Date(iso)
      return Number.isNaN(d.getTime()) ? iso : formatDate(d)
    },
  })

  const search = {
    value: searchInput,
    onChange: setSearchInput,
    // A phone's field holds a short phrase whole.
    placeholder: isPhone
      ? t('assets.inventoryPage.searchShort', 'Search assets…')
      : t('assets.inventoryPage.search', 'Search name, description or alias…'),
    label: t('assets.inventoryPage.searchAria', 'Search assets'),
    query: queryMode.query,
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

  // The list's More, after Refresh and Export. On a phone it starts with
  // "Select" (the cards have no header checkbox), in a group of its own. The
  // two group actions work on the filter on screen: they are always listed,
  // dimmed with the reason while there is no filter a group rule can hold.
  // "Copy link" copies this list as it is shown (filters, sort, view, mode:
  // all in the address).
  // The view this list is: an open saved view by its name, else the type or
  // lens, else every asset. "Modified" says the filter differs from that view
  // (a saved view changed, or filters added to a built-in one); Reset goes
  // back to it. Saving is in the Views menu, on the chips row on a phone.
  const viewTitle = activeView?.name ?? scopeLabel ?? t('assets.quickView.all', 'All assets')
  const titleModified = activeView ? viewModified : activeCount > 0 || Boolean(filters.search)
  const resetView = () => (activeView ? void discardViewChanges() : clearAll())
  // Save view opens the one save dialog, which the Views menu owns (anyone
  // may save a view of their own).
  const openSaveView = () => viewsActions.current?.openSave()
  const canGroup = can(Permission.AssetGroupsWrite)
  const groupReason = filters.advanced
    ? t('assets.inventoryPage.groupNoQueryText', 'Not available for a filter given as query text')
    : isInventoryFilterEmpty(filters) || filterHasNoGroupRule(filterParams)
      ? t('assets.inventoryPage.groupNeedsFilter', 'Add a filter a group rule can hold first')
      : total <= 0
        ? t('assets.inventoryPage.groupNoMatch', 'No asset matches this filter')
        : undefined
  const listMoreItems: ActionMenuEntry[] = [
    ...(phoneSelect.item ? [phoneSelect.item] : []),
    // On a phone Refresh and Export are here, so the view's row keeps its
    // name, count and view state.
    ...(isPhone
      ? [
          {
            id: 'refresh',
            label: t('assets.inventoryPage.refresh', 'Refresh'),
            onSelect: refresh,
          },
          {
            id: 'export',
            label: t('assets.inventoryPage.export', 'Export'),
            onSelect: () => void handleExport(),
            disabledReason: exporting
              ? t('assets.inventoryPage.exportRunning', 'An export is running')
              : undefined,
          },
        ]
      : []),
    ...(isPhone && titleModified
      ? [
          {
            id: 'view-save',
            section: 'view',
            label: t('common.listView.save', 'Save view'),
            onSelect: openSaveView,
          },
          {
            id: 'view-reset',
            section: 'view',
            label: t('common.listView.reset', 'Reset'),
            onSelect: resetView,
          },
        ]
      : []),
    ...(canGroup
      ? [
          {
            id: 'save-as-group',
            section: 'group',
            label: t('assetGroups.filterActions.save', 'Save filter as group'),
            onSelect: () => setGroupDialog('save'),
            disabledReason: groupReason,
          },
          {
            id: 'add-matching-to-group',
            section: 'group',
            label: groupReason
              ? t('assetGroups.filterActions.addAllShort', 'Add all matching to group')
              : t('assetGroups.filterActions.addAll', 'Add all {count} matching to group', {
                  count: formatNumber(total),
                }),
            onSelect: () => setGroupDialog('add'),
            disabledReason: groupReason,
          },
        ]
      : []),
    {
      id: 'copy-link',
      section: 'link',
      label: t('assets.inventoryPage.copyLink', 'Copy link'),
      onSelect: () =>
        void copyToClipboard(
          shareableLink(`${window.location.pathname}${window.location.search}`)
        ).then((ok) =>
          ok
            ? toast.success(t('assets.inventoryPage.linkCopied', 'Link copied to clipboard'))
            : toast.error(t('assets.inventoryPage.copyFailed', 'Could not copy to the clipboard'))
        ),
    },
  ]

  // The default list leaves out names awaiting review and names marked not
  // ours (the locked chip says so). The heading counts every asset of the
  // view; with no other filter, the difference is exactly what the chip
  // hides, so the three numbers on the page add up.
  const hideActive = !filters.attribution?.length
  const viewTotal = tab ? (tabTotals?.[tab.id] ?? 0) : (scopeLabel ? typeStats : stats).total
  const onlyDefaults = isInventoryFilterEmpty({ ...filters, types: undefined, subType: undefined })
  const providerHidden = hideActive && providerLoaded ? providerCount : undefined
  const hiddenCount =
    hideActive && onlyDefaults && !isLoading && !statsLoading && !typeStatsLoading
      ? Math.max(0, viewTotal - total - (providerHidden ?? 0))
      : undefined
  const showProviderAddresses = () =>
    setFilters({ ...filters, attribution: ['provider_address'], page: 1 })
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

  // The list's "..." menu: the title row's end from 768 px; on a phone the end
  // of the toolbar (a control never stands alone on the phone title row), with
  // Refresh and Export inside it.
  const listMenu = (
    <ActionMenu
      title={viewTitle}
      label={t('common.actionMenu.label', 'Actions for {name}', { name: viewTitle })}
      items={listMoreItems}
      trigger={
        <Button
          variant="outline"
          size="icon"
          aria-label={t('assets.inventoryPage.moreActions', 'More actions')}
        >
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </Button>
      }
    />
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('assets.overview.title', 'Assets')}
          viewSwitcher={viewSwitcher}
          // On a phone the primary action is a 36 px square in the title row,
          // before the view switch (not a row of its own), so the switch keeps
          // its place at the row's end on both views: the title gives up the
          // room it does not use.
          className="max-md:[&>div:first-child]:basis-24"
          actionsClassName="order-1 basis-auto sm:order-2"
        >
          {canWrite && (
            <InventoryAddButton
              compact
              registry={registry}
              view={typeView}
              onAdd={forms.openCreate}
              open={addMenuOpen}
              onOpenChange={setAddMenuOpen}
            />
          )}
        </PageHeader>
        <AssetsSectionTabs />

        {/* The view's title row: its name and its one count (the results the
            list shows, filters and search applied), then the list's actions.
            The page header keeps the page-level ones (Add, the view switch). */}
        <ListTitleRow
          data-testid="inventory-title-row"
          title={<span data-testid="inventory-view-title">{viewTitle}</span>}
          count={
            <ListCount
              total={total}
              capped={totalCapped}
              loading={isFirstLoad}
              label={
                totalCapped
                  ? t('assets.filters.resultsCapped', '{count}+ assets', {
                      count: formatNumber(total),
                    })
                  : t('assets.filters.results', '{count, plural, one {# asset} other {# assets}}', {
                      count: total,
                    })
              }
            />
          }
          start={
            titleModified ? (
              // The shared view state: Modified, then Save view and Reset. On
              // a phone the two actions are in the row's More; the lozenge stays.
              <ListViewChanged
                changed
                actionsClassName="max-md:hidden"
                onSave={openSaveView}
                onReset={resetView}
              />
            ) : lens?.description ? (
              <span className="hidden truncate text-xs text-muted-foreground md:inline">
                {t(`assets.lensDescription.${lens.id}`, lens.description)}
              </span>
            ) : undefined
          }
        >
          {!isPhone && refreshButton}
          {!isPhone && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleExport()}
              disabled={exporting}
            >
              <Download className="me-2 h-4 w-4" aria-hidden />
              {exporting
                ? t('assets.inventoryPage.exporting', 'Exporting…')
                : t('assets.inventoryPage.export', 'Export')}
            </Button>
          )}
          {!isPhone && listMenu}
        </ListTitleRow>

        <div className="flex items-start">
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
                sort={filters.sort ?? DEFAULT_SORT}
                onPageChange={(nextPage, nextSize) =>
                  setFilters({
                    ...filters,
                    pageSize: nextSize,
                    // A new page size starts from the first page.
                    page: nextSize !== pageSize ? 1 : nextPage,
                  })
                }
                onSortChange={(sort) =>
                  // The default order is not written into the address.
                  setFilters({
                    ...filters,
                    sort: sort === DEFAULT_SORT ? undefined : sort,
                    page: 1,
                  })
                }
                bulk={assetsBulk}
                selectMode={phoneSelect.selectMode}
                resetSelectionKey={tableBulk.resetKey}
                isRefreshing={isLoading}
                onClearFilters={clearAll}
                filterTags={filters.tags}
                onToggleTagFilter={toggleTagFilter}
                search={search}
                filterToggle={filterToggle}
                toolbarStart={
                  // Kept in Query mode (dimmed and inert), so the switch moves nothing.
                  // In the External surface lens the type comes first: a token,
                  // not a second tab row under the Assets tabs.
                  <>
                    {inTabsLens && (
                      <InventoryTypeSelect
                        value={tab?.id}
                        counts={tabTotals}
                        total={lensStats.total}
                        onChange={selectTab}
                      />
                    )}
                    <InventoryAddFilter
                      groups={facetGroups}
                      attributeFacets={attributeFacets}
                      tagTypes={typeView ? [typeView.type] : undefined}
                      filters={filters}
                      stats={scopeLabel ? typeStats : stats}
                      onChange={setFilters}
                      onOpenChange={(open) => open && setFacetsWanted(true)}
                    />
                  </>
                }
                toolbarEnd={
                  <>
                    <InventoryViewsMenu
                      filters={filters}
                      presets={presets}
                      onToggle={togglePreset}
                      resolveFilter={resolveViewFilter}
                      modified={viewModified}
                      onDiscard={() => void discardViewChanges()}
                      onSelect={(v) => void openView(v)}
                      actionsRef={viewsActions}
                    />
                    {typeView?.type === 'ip_address' && !typeView.subType && (
                      <Button
                        variant={groupedByNetwork ? 'secondary' : 'outline'}
                        size="sm"
                        // A view control, as Views and Display: its label from a
                        // 64rem toolbar, an icon below it and on a phone.
                        iconOnlyBelow="@5xl/toolbar"
                        aria-label={t('assets.ip.groupBy', 'Group by network /24')}
                        aria-pressed={groupedByNetwork}
                        disabled={Boolean(filters.advanced)}
                        title={
                          filters.advanced
                            ? t(
                                'assets.ip.groupDisabled',
                                'Not available for a filter given as query text'
                              )
                            : t('assets.ip.groupBy', 'Group by network /24')
                        }
                        onClick={() =>
                          setFilters({
                            ...filters,
                            group: groupedByNetwork ? undefined : 'network',
                            page: 1,
                          })
                        }
                      >
                        <Network className="h-4 w-4" aria-hidden />
                        <span className="sr-only @5xl/toolbar:not-sr-only group-data-[fold=true]/toolbar:sr-only">
                          {t('assets.ip.groupBy', 'Group by network /24')}
                        </span>
                      </Button>
                    )}
                    {isPhone && listMenu}
                  </>
                }
                toolbarBelow={
                  <InventoryFilterBar
                    locked={
                      !filters.attribution?.length &&
                      ((hiddenCount ?? 0) > 0 || (providerHidden ?? 0) > 0) ? (
                        <>
                          <InventoryHiddenChip
                            count={hiddenCount}
                            onShowAll={showAllAttributions}
                          />
                          <InventoryProviderChip
                            count={providerHidden}
                            onShow={showProviderAddresses}
                          />
                        </>
                      ) : undefined
                    }
                    chips={chips}
                    filters={filters}
                    onChange={setFilters}
                    onClearAll={clearAll}
                    queryActive={queryMode.active}
                    onOpenQuery={() => queryMode.setActive(true)}
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
                      emptyDescription: emptyHint(typeView, t),
                    }
                  : {})}
              />
            )}
          </div>
        </div>
      </PageStack>

      {tableBulk.dialogs}

      {canGroup && (
        <FilterGroupActions
          params={filterParams}
          total={total}
          dialog={groupReason ? null : groupDialog}
          onDialogChange={setGroupDialog}
        />
      )}

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
