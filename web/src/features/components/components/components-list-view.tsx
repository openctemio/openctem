'use client'

/**
 * /components: the software components inventory, one row per package.
 * Filters, search, sort and page live in the URL; everything is computed on
 * the server and limited to the caller's data scope. The page follows the
 * shared list pattern of /findings (web/docs/ui-style-contract.md, "Lists").
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Download, MoreHorizontal, Package, RefreshCw, Upload } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  FilterSheet,
  MetricStrip,
  type MetricStripItem,
  PageHeader,
  RelativeTime,
  RiskScoreBadge,
  PageStack,
} from '@/features/shared'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import {
  ListCount,
  ListTitleRow,
  ListViewChanged,
} from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useListParams } from '@/hooks/use-list-params'
import { accessStateOf } from '@/lib/api/access-state'
import { usePermissions, Permission } from '@/lib/permissions'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { useComponentsList, useComponentsSummary } from '../api/hooks'
import type { ComponentPackage } from '../api/types'
import { componentHref } from '../lib/links'
import {
  activeFilterCount,
  apiFilters,
  COMPONENT_DEFAULT_SORT,
  COMPONENT_FILTER_DEFAULTS,
  COMPONENT_PAGE_SIZES,
  COMPONENT_SORT_FIELDS,
  type ComponentFilterName,
  type ComponentPreset,
  currentPreset,
  listValues,
  PRESET_FILTERS,
} from '../lib/filters'
import {
  EcosystemBadge,
  FixPill,
  KevPill,
  LicenseList,
  SeverityCountsCell,
  useRelationshipLabel,
  useScopeLabel,
  useSeverityLabel,
} from './component-cells'
import { ComponentFacetsPanel } from './component-facets'
import { ComponentPhoneCard } from './component-phone-card'
import { SbomExportDialog } from './sbom-export-dialog'
import { SbomImportDialog } from './sbom-import-dialog'
import { VexImportDialog } from './vex-import-dialog'

const PANEL_ID = 'component-filters'

/**
 * Columns that step aside while the table frame is narrower than this (px);
 * they stay under Display > Columns. Frame = screen - 326 at 1440 and 1280,
 * about 700 at 1024 with the sidebar open, about 650 at 768. Each threshold
 * is above the sum of the columns still shown with it (name 240, counts 96,
 * vulnerabilities 216, risk 148, fix 72, license 176), so the table never
 * scrolls sideways: 604 below 720, 700 below 820, 796 below 900, 868 below
 * 1080, 1044 from there.
 */
const COMPONENT_HIDE_BELOW = { license: 1080, fix: 900, versions: 820, assets: 720 } as const

/**
 * Column widths (px). Every column but the package has a fixed width, so the
 * package name takes what is left (at least `name`). Counts hold "Phiên bản"
 * and "2,304"; Vulnerabilities holds four severity counts and the KEV mark.
 */
const COMPONENT_WIDTH = {
  name: 240,
  count: 96,
  vulns: 216,
  fix: 72,
  license: 176,
} as const

export function ComponentsListView() {
  const { t } = useTranslation()
  const router = useRouter()
  const { can } = usePermissions()
  const list = useListParams<ComponentFilterName>({
    pageSizes: COMPONENT_PAGE_SIZES,
    defaultPageSize: COMPONENT_PAGE_SIZES[0],
    sortFields: COMPONENT_SORT_FIELDS,
    defaultSort: COMPONENT_DEFAULT_SORT,
    filters: { ...COMPONENT_FILTER_DEFAULTS },
  })
  const [search, setSearch] = useState(list.q)
  const debouncedSearch = useSearchQuery(search).term
  const { setSearch: setListSearch } = list
  useEffect(() => {
    if (debouncedSearch !== list.q) setListSearch(debouncedSearch)
  }, [debouncedSearch, list.q, setListSearch])

  const filters = useMemo(() => apiFilters(list.filters, list.q), [list.filters, list.q])
  const { data, error, isLoading, isValidating, mutate, canRead } = useComponentsList({
    ...filters,
    page: list.page,
    per_page: list.perPage,
    sort: list.sort,
  })
  // The tiles are page-level (the whole inventory, whatever the filters), so a
  // tile's number is what its preset opens.
  const { data: summary, isLoading: summaryLoading } = useComponentsSummary({})
  const [readAt, setReadAt] = useState<Date | undefined>(undefined)
  useEffect(() => {
    if (data) setReadAt(new Date())
  }, [data])

  const [sheetOpen, setSheetOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [vexOpen, setVexOpen] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const canImport = can(Permission.ComponentsWrite)
  const canImportVex = can(Permission.FindingsApprove)

  const activeCount = activeFilterCount(list.filters)
  const preset = currentPreset(list.filters)
  const narrowed = activeCount > 0 || list.q !== ''
  const viewChanged = narrowed || list.sort !== COMPONENT_DEFAULT_SORT
  const total = data?.total ?? 0

  const severityLabel = useSeverityLabel()
  const relationshipLabel = useRelationshipLabel()
  const scopeLabel = useScopeLabel()

  const applyPreset = (p: ComponentPreset) => {
    // A preset replaces every filter, the search included.
    setSearch('')
    setListSearch('')
    for (const name of Object.keys(COMPONENT_FILTER_DEFAULTS) as ComponentFilterName[]) {
      list.setFilter(name, PRESET_FILTERS[p][name] ?? '')
    }
  }
  const { reset } = list
  // Back to the list as it opens: no filter, no search, the default order.
  const backToList = useCallback(() => {
    setSearch('')
    reset()
  }, [reset])

  const metrics: MetricStripItem[] = [
    {
      // Every package: clears the presets (and the search).
      key: 'packages',
      label: t('components.kpi.packages', 'Packages'),
      value: summary?.packages ?? 0,
      hint: t('components.kpi.packagesHint', '{versions} versions on {assets} assets', {
        versions: summary?.versions ?? 0,
        assets: summary?.assets ?? 0,
      }),
      onClick: () => applyPreset('all'),
      active: preset === 'all' && list.q === '',
    },
    {
      key: 'vulnerable',
      label: t('components.kpi.vulnerable', 'Vulnerable'),
      value: summary?.vulnerable_packages ?? 0,
      tone: summary?.vulnerable_packages ? 'warning' : 'default',
      onClick: () => applyPreset('vulnerable'),
      active: preset === 'vulnerable',
    },
    {
      key: 'kev',
      label: t('components.kpi.kev', 'Known exploited'),
      value: summary?.kev_packages ?? 0,
      tone: summary?.kev_packages ? 'danger' : 'default',
      onClick: () => applyPreset('kev'),
      active: preset === 'kev',
    },
    {
      key: 'fixable',
      label: t('components.kpi.fixable', 'Fix available'),
      value: summary?.fixable_packages ?? 0,
      onClick: () => applyPreset('fixable'),
      active: preset === 'fixable',
    },
  ]

  const columns = useMemo<ColumnDef<ComponentPackage>[]>(
    () => [
      {
        id: 'name',
        accessorKey: 'name',
        enableSorting: true,
        enableHiding: false,
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: COMPONENT_WIDTH.name,
          label: t('components.col.package', 'Package'),
        },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('components.col.package', 'Package')} />
        ),
        cell: ({ row }) => {
          const open = () => router.push(componentHref(row.original.id))
          return (
            // Name, ecosystem, then the package URL where the cell has room
            // for it (the whole URL in the tooltip).
            <span
              className="@container flex min-w-0 items-center gap-2 whitespace-nowrap"
              title={row.original.purl}
            >
              <RowNameLink
                href={componentHref(row.original.id)}
                onOpen={open}
                className="min-w-0 font-medium"
              >
                {toDisplayText(row.original.name, 200)}
              </RowNameLink>
              <EcosystemBadge ecosystem={row.original.ecosystem} className="shrink-0" />
              <span className="hidden min-w-0 flex-1 basis-0 truncate font-mono text-xs text-muted-foreground @[18rem]:inline">
                {toDisplayText(row.original.purl, 200)}
              </span>
            </span>
          )
        },
      },
      {
        id: 'versions',
        accessorKey: 'versions_in_use',
        enableSorting: true,
        meta: {
          kind: 'number',
          width: COMPONENT_WIDTH.count,
          hideBelow: COMPONENT_HIDE_BELOW.versions,
          label: t('components.col.versions', 'Versions'),
        },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('components.col.versions', 'Versions')} />
        ),
        cell: ({ row }) => <span className="tabular-nums">{row.original.versions_in_use}</span>,
      },
      {
        id: 'assets',
        accessorKey: 'assets',
        enableSorting: true,
        meta: {
          kind: 'number',
          width: COMPONENT_WIDTH.count,
          hideBelow: COMPONENT_HIDE_BELOW.assets,
          label: t('components.col.assets', 'Assets'),
        },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('components.col.assets', 'Assets')} />
        ),
        cell: ({ row }) => (
          <span
            className="tabular-nums"
            title={t('components.col.assetsHint', '{direct} direct, {transitive} transitive uses', {
              direct: row.original.direct_links,
              transitive: row.original.transitive_links,
            })}
          >
            {row.original.assets}
          </span>
        ),
      },
      {
        id: 'vulns',
        enableSorting: true,
        meta: {
          kind: 'signals',
          width: COMPONENT_WIDTH.vulns,
          label: t('components.col.vulns', 'Vulnerabilities'),
        },
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('components.col.vulns', 'Vulnerabilities')}
          />
        ),
        cell: ({ row }) => (
          <div className="flex min-w-0 items-center gap-1.5 overflow-hidden whitespace-nowrap">
            <SeverityCountsCell counts={row.original.vulnerabilities} className="flex-nowrap" />
            <KevPill count={row.original.kev} />
          </div>
        ),
      },
      {
        id: 'risk',
        accessorKey: 'risk_score',
        enableSorting: true,
        meta: { kind: 'risk', label: t('components.col.risk', 'Risk') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('components.col.risk', 'Risk')} />
        ),
        cell: ({ row }) => <RiskScoreBadge score={row.original.risk_score} size="sm" />,
      },
      {
        id: 'fix',
        enableSorting: false,
        meta: {
          kind: 'text',
          width: COMPONENT_WIDTH.fix,
          hideBelow: COMPONENT_HIDE_BELOW.fix,
          label: t('components.col.fix', 'Fix'),
        },
        header: () => t('components.col.fix', 'Fix'),
        cell: ({ row }) => <FixPill available={row.original.fix_available} compact />,
      },
      {
        id: 'license',
        enableSorting: false,
        meta: {
          kind: 'tags',
          width: COMPONENT_WIDTH.license,
          hideBelow: COMPONENT_HIDE_BELOW.license,
          label: t('components.col.license', 'License'),
        },
        header: () => t('components.col.license', 'License'),
        cell: ({ row }) => <LicenseList licenses={row.original.licenses} oneLine />,
      },
      {
        id: 'last_seen',
        accessorKey: 'last_seen_at',
        enableSorting: true,
        meta: { kind: 'datetime-recent', label: t('components.col.lastSeen', 'Last seen') },
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('components.col.lastSeen', 'Last seen')}
          />
        ),
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
    ],
    [t, router]
  )

  // One chip per filter, its values joined; the asset filter (set by links
  // from an asset's page) has a chip of its own.
  const chipText: Record<ComponentFilterName, (v: string) => string> = {
    severity: (v) =>
      t('components.chip.severity', 'Severity: {values}', {
        values: listValues(v).map(severityLabel).join(', '),
      }),
    ecosystem: (v) =>
      t('components.chip.ecosystem', 'Ecosystem: {values}', {
        values: listValues(v).join(', '),
      }),
    relationship: (v) =>
      t('components.chip.relationship', 'Dependency: {values}', {
        values: listValues(v).map(relationshipLabel).join(', '),
      }),
    scope: (v) =>
      t('components.chip.scope', 'Scope: {values}', {
        values: listValues(v)
          .map((s) => String(scopeLabel(s)))
          .join(', '),
      }),
    license: (v) =>
      t('components.chip.license', 'License: {values}', { values: listValues(v).join(', ') }),
    kev: () => t('components.facets.kev', 'Known exploited (KEV)'),
    has_fix: () => t('components.facets.fix', 'Fix available'),
    has_vulnerabilities: () => t('components.facets.vulnerable', 'Has open vulnerabilities'),
    asset_id: () => t('components.chip.asset', 'On one asset'),
  }
  const chipList = (Object.keys(COMPONENT_FILTER_DEFAULTS) as ComponentFilterName[])
    .filter((name) => list.filters[name])
    .map((name) => ({
      key: name,
      text: toDisplayText(chipText[name](list.filters[name]), 120),
      clear: () => list.setFilter(name, ''),
    }))
  const clearFilters = useCallback(() => {
    setSearch('')
    setListSearch('')
    for (const name of Object.keys(COMPONENT_FILTER_DEFAULTS) as ComponentFilterName[]) {
      list.setFilter(name, '')
    }
  }, [list, setListSearch])
  const chipsRow =
    chipList.length > 0 ? (
      <FilterChipsRow
        data-testid="component-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chipList.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={c.clear}
            removeLabel={t('components.chip.remove', 'Remove filter {filter}', {
              filter: c.text,
            })}
          />
        ))}
        onClearAll={chipList.length > 1 ? clearFilters : undefined}
      />
    ) : undefined

  const facets = (
    <ComponentFacetsPanel
      facets={data?.facets}
      filters={list.filters}
      activeCount={activeCount}
      onChange={list.setFilter}
      onClearAll={clearFilters}
    />
  )

  const viewTitle = t('components.list.viewAll', 'All packages')
  const refreshLabel = t('components.list.refresh', 'Refresh')
  const refreshing = isValidating && !isLoading
  const refreshButton = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          onClick={() => void mutate()}
          disabled={refreshing}
          aria-label={refreshLabel}
        >
          <RefreshCw
            className={cn('h-4 w-4', refreshing && 'animate-spin motion-reduce:animate-none')}
            aria-hidden
          />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{refreshLabel}</TooltipContent>
    </Tooltip>
  )
  const exportLabel = t('components.export', 'Export SBOM')
  const vexLabel = t('components.importVex', 'Import VEX')
  // Under 42rem of row width (and on a phone) the row's actions fold into
  // More: Reset on a changed view, then Export SBOM. Import VEX is always
  // there (a rare act beside the page's primary Import SBOM).
  const moreItems = (folded: boolean): ActionMenuEntry[] => [
    ...(folded && viewChanged
      ? [{ id: 'view-reset', label: t('common.listView.reset', 'Reset'), onSelect: backToList }]
      : []),
    ...(folded
      ? [
          {
            id: 'export-sbom',
            label: exportLabel,
            section: 'io',
            onSelect: () => setExportOpen(true),
          },
        ]
      : []),
    ...(canImportVex
      ? [{ id: 'import-vex', label: vexLabel, section: 'io', onSelect: () => setVexOpen(true) }]
      : []),
  ]
  const moreMenu = (folded: boolean) => {
    const items = moreItems(folded)
    if (items.length === 0) return null
    return (
      <ActionMenu
        title={viewTitle}
        label={t('common.actionMenu.label', 'Actions for {name}', { name: viewTitle })}
        items={items}
        trigger={
          <Button
            variant="outline"
            size="icon"
            aria-label={t('common.actionMenu.more', 'More actions')}
          >
            <MoreHorizontal className="h-4 w-4" aria-hidden />
          </Button>
        }
      />
    )
  }
  const wideMore = moreMenu(false)
  const narrowMore = moreMenu(true)

  const titleRow = (
    <ListTitleRow
      data-testid="components-title-row"
      className="@container/actions"
      title={viewTitle}
      count={
        <ListCount
          total={total}
          loading={!data && !error}
          label={t('components.list.total', '{count, plural, one {# package} other {# packages}}', {
            count: total,
          })}
        />
      }
      start={
        <ListViewChanged
          changed={viewChanged}
          // On a row under 42rem Reset is in the row's More.
          actionsClassName="hidden @2xl/actions:flex"
          onReset={backToList}
        />
      }
    >
      {refreshButton}
      <div className="hidden @2xl/actions:flex @2xl/actions:items-center @2xl/actions:gap-2">
        <Button variant="outline" size="sm" onClick={() => setExportOpen(true)}>
          <Download aria-hidden />
          {exportLabel}
        </Button>
        {wideMore}
      </div>
      {narrowMore && <div className="@2xl/actions:hidden">{narrowMore}</div>}
    </ListTitleRow>
  )

  const noAccess = !canRead || accessStateOf(error) === 'no_access'
  const readError = error && !data ? error : undefined
  const firstRun = !!data && !error && total === 0 && !narrowed

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('components.title', 'Components')}
          // On a phone the list comes first: the description is read out but
          // not drawn, and the tiles follow the list.
          description={
            <span className="max-md:sr-only">
              {t(
                'components.description',
                'Open-source and third-party packages your repositories, images and hosts are built from, with where they are used and what is wrong with them.'
              )}
            </span>
          }
        >
          {canImport && (
            <Button size="sm" iconOnlyBelow="md" onClick={() => setImportOpen(true)}>
              <Upload aria-hidden />
              <span className="sr-only md:not-sr-only">
                {t('components.import', 'Import SBOM')}
              </span>
            </Button>
          )}
        </PageHeader>

        <MetricStrip loading={summaryLoading && !summary} items={metrics} listFirst />
        {titleRow}

        {noAccess ? (
          <NoAccessState title={t('components.list.subject', 'the components list')} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            error={readError}
            onRetry={() => void mutate()}
            errorTitle={t('components.list.subject', 'the components list')}
            showSearch={false}
            search={{
              value: search,
              onChange: setSearch,
              placeholder: t('components.searchPlaceholder', 'Search packages…'),
              label: t('components.searchLabel', 'Search packages by name or namespace'),
            }}
            // One filter entry per width: Add filter from 768, this button
            // (joined to the search field) on a phone, where it opens the sheet.
            filterToggle={{
              open: false,
              onToggle: () => setSheetOpen(true),
              onOpenSheet: () => setSheetOpen(true),
              activeCount,
              controlsId: PANEL_ID,
              label: t('components.filtersLabel', 'Component filters'),
              sheetOnly: true,
            }}
            toolbarStart={<AddFilterPanel>{facets}</AddFilterPanel>}
            toolbarBelow={chipsRow}
            manualPagination
            rowCount={total}
            pageCount={Math.max(1, data?.total_pages ?? 1)}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
            pageSize={list.perPage}
            pageSizeOptions={[...COMPONENT_PAGE_SIZES]}
            sorting={list.sorting}
            onSortingChange={list.setSorting}
            getRowId={(p) => p.id}
            isLoading={isLoading && !data}
            isRefreshing={refreshing}
            refreshingLabel={t('components.list.refreshing', 'Refreshing components')}
            // A first run has nothing to search, filter or arrange.
            showToolbar={!firstRun}
            staleAt={readAt}
            refreshFailed={!!error && !!data}
            onRefresh={() => void mutate()}
            onRowClick={(p) => router.push(componentHref(p.id))}
            initialColumnVisibility={{ last_seen: false }}
            mobileRow={(p) => (
              <ComponentPhoneCard item={p} onOpen={() => router.push(componentHref(p.id))} />
            )}
            paginationNoun={t('components.list.noun', 'packages')}
            isFiltered={narrowed}
            onClearFilters={clearFilters}
            emptyState={{
              nothingYet: (
                <EmptyState
                  icon={Package}
                  title={t('components.empty.title', 'No components yet')}
                  description={t(
                    'components.empty.description',
                    'Components appear when a sensor runs an SCA tool, a CI job uploads a report, or you import an SBOM (CycloneDX or SPDX JSON).'
                  )}
                  action={
                    <Button variant="outline" size="sm" asChild>
                      <Link href="/sensors">
                        {t('components.empty.sensors', 'Set up a sensor')}
                      </Link>
                    </Button>
                  }
                />
              ),
              noMatch: {
                title: t('components.noMatch', 'No packages match these filters'),
                hint: t('components.noMatchHint', 'Remove a filter or clear the search.'),
              },
            }}
          />
        )}

        <FilterSheet
          open={sheetOpen}
          onOpenChange={setSheetOpen}
          title={t('components.filtersLabel', 'Component filters')}
        >
          {facets}
        </FilterSheet>
      </PageStack>
      <SbomImportDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        onImported={() => mutate()}
      />
      <SbomExportDialog open={exportOpen} onOpenChange={setExportOpen} />
      <VexImportDialog open={vexOpen} onOpenChange={setVexOpen} onImported={() => mutate()} />
    </Main>
  )
}
