'use client'

/**
 * /components: the software components inventory, one row per package.
 * Filters, search, sort and page live in the URL; everything is computed on
 * the server and limited to the caller's data scope.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Download, Package, Search, Upload } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  ErrorState,
  FilterPanelToggle,
  FilterSheet,
  MetricStrip,
  type MetricStripItem,
  PageHeader,
  RelativeTime,
  RiskScoreBadge,
  SegmentedLens,
  StackedCell,
} from '@/features/shared'
import { TableSkeleton } from '@/components/list-page-parts'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import { Can, Permission } from '@/lib/permissions'
import { useComponentsList, useComponentsSummary } from '../api/hooks'
import type { ComponentPackage } from '../api/types'
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
  PRESET_FILTERS,
} from '../lib/filters'
import {
  EcosystemBadge,
  FixPill,
  KevPill,
  LicenseList,
  SeverityCountsCell,
} from './component-cells'
import { ComponentFacetsPanel } from './component-facets'
import { SbomExportDialog } from './sbom-export-dialog'
import { SbomImportDialog } from './sbom-import-dialog'

const FILTERS_OPEN_KEY = 'components.filters.open'

function useFiltersOpen(): [boolean, (open: boolean) => void] {
  const [open, setOpen] = useState(true)
  useEffect(() => {
    try {
      const v = window.localStorage.getItem(FILTERS_OPEN_KEY)
      if (v !== null) setOpen(v === '1')
    } catch {
      // storage unavailable: keep the default
    }
  }, [])
  const set = useCallback((next: boolean) => {
    setOpen(next)
    try {
      window.localStorage.setItem(FILTERS_OPEN_KEY, next ? '1' : '0')
    } catch {
      // storage unavailable
    }
  }, [])
  return [open, set]
}

export function ComponentsListView() {
  const { t } = useTranslation()
  const list = useListParams<ComponentFilterName>({
    pageSizes: COMPONENT_PAGE_SIZES,
    defaultPageSize: COMPONENT_PAGE_SIZES[0],
    sortFields: COMPONENT_SORT_FIELDS,
    defaultSort: COMPONENT_DEFAULT_SORT,
    filters: { ...COMPONENT_FILTER_DEFAULTS },
  })
  const [search, setSearch] = useState(list.q)
  const debouncedSearch = useDebounce(search, 300)
  const { setSearch: setListSearch } = list
  useEffect(() => {
    if (debouncedSearch !== list.q) setListSearch(debouncedSearch)
  }, [debouncedSearch, list.q, setListSearch])

  const filters = useMemo(() => apiFilters(list.filters, list.q), [list.filters, list.q])
  const { data, error, isLoading, mutate } = useComponentsList({
    ...filters,
    page: list.page,
    per_page: list.perPage,
    sort: list.sort,
  })
  const { data: summary, isLoading: summaryLoading } = useComponentsSummary(filters)

  const [filtersOpen, setFiltersOpen] = useFiltersOpen()
  const [sheetOpen, setSheetOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)

  const activeCount = activeFilterCount(list.filters)
  const preset = currentPreset(list.filters)
  const hasQuery = activeCount > 0 || list.q !== ''

  const applyPreset = (p: ComponentPreset) => {
    for (const name of Object.keys(COMPONENT_FILTER_DEFAULTS) as ComponentFilterName[]) {
      list.setFilter(name, PRESET_FILTERS[p][name] ?? '')
    }
  }
  const clearAll = () => {
    setSearch('')
    list.reset()
  }

  const metrics: MetricStripItem[] = [
    {
      key: 'packages',
      label: t('components.kpi.packages', 'Packages'),
      value: summary?.packages ?? 0,
      hint: t('components.kpi.packagesHint', '{versions} versions on {assets} assets', {
        versions: summary?.versions ?? 0,
        assets: summary?.assets ?? 0,
      }),
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
    {
      key: 'outdated',
      label: t('components.kpi.outdated', 'Outdated'),
      value: summary?.outdated ?? '—',
      hint:
        summary?.outdated == null
          ? t(
              'components.kpi.outdatedHint',
              'Needs package health data from the vulnerability feed'
            )
          : undefined,
    },
  ]

  const columns = useMemo<ColumnDef<ComponentPackage>[]>(
    () => [
      {
        id: 'name',
        accessorKey: 'name',
        enableSorting: true,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('components.col.package', 'Package')} />
        ),
        cell: ({ row }) => (
          <StackedCell
            truncate
            primary={
              <span className="flex min-w-0 items-center gap-1.5">
                <Link
                  href={`/components/${row.original.id}`}
                  className="truncate font-medium hover:underline"
                >
                  {row.original.name}
                </Link>
                <EcosystemBadge ecosystem={row.original.ecosystem} className="shrink-0" />
              </span>
            }
            secondary={<span className="font-mono text-xs">{row.original.purl}</span>}
          />
        ),
      },
      {
        id: 'versions',
        accessorKey: 'versions_in_use',
        enableSorting: true,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('components.col.versions', 'Versions')} />
        ),
        cell: ({ row }) => <span className="tabular-nums">{row.original.versions_in_use}</span>,
      },
      {
        id: 'assets',
        accessorKey: 'assets',
        enableSorting: true,
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
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('components.col.vulns', 'Vulnerabilities')}
          />
        ),
        cell: ({ row }) => (
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityCountsCell counts={row.original.vulnerabilities} />
            <KevPill count={row.original.kev} />
          </div>
        ),
      },
      {
        id: 'fix',
        enableSorting: false,
        header: () => t('components.col.fix', 'Fix'),
        cell: ({ row }) => <FixPill available={row.original.fix_available} compact />,
      },
      {
        id: 'license',
        enableSorting: false,
        header: () => t('components.col.license', 'License'),
        cell: ({ row }) => <LicenseList licenses={row.original.licenses} />,
      },
      {
        id: 'risk',
        accessorKey: 'risk_score',
        enableSorting: true,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('components.col.risk', 'Risk')} />
        ),
        cell: ({ row }) => <RiskScoreBadge score={row.original.risk_score} size="sm" />,
      },
      {
        id: 'last_seen',
        accessorKey: 'last_seen_at',
        enableSorting: true,
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('components.col.lastSeen', 'Last seen')}
          />
        ),
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
    ],
    [t]
  )

  const facets = (
    <ComponentFacetsPanel
      facets={data?.facets}
      filters={list.filters}
      activeCount={activeCount}
      onChange={list.setFilter}
      onClearAll={clearAll}
    />
  )

  const presetOptions: { value: ComponentPreset; label: string }[] = [
    { value: 'all', label: t('components.preset.all', 'All') },
    { value: 'vulnerable', label: t('components.preset.vulnerable', 'Vulnerable') },
    { value: 'kev', label: t('components.preset.kev', 'Known exploited') },
    { value: 'fixable', label: t('components.preset.fixable', 'Fixable') },
    { value: 'direct', label: t('components.preset.direct', 'Direct dependencies') },
  ]

  const toolbarStart = (
    <>
      <FilterPanelToggle
        open={filtersOpen}
        onToggle={() => setFiltersOpen(!filtersOpen)}
        onOpenSheet={() => setSheetOpen(true)}
        activeCount={activeCount}
        controlsId="component-filters"
        label={t('components.filters', 'Filters')}
      />
      <div className="relative w-full sm:w-72">
        <Search
          className="pointer-events-none absolute start-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t('components.searchPlaceholder', 'Search packages…')}
          aria-label={t('components.searchLabel', 'Search packages by name or namespace')}
          className="h-9 ps-8"
        />
      </div>
    </>
  )

  const empty = !isLoading && !error && data && data.total === 0 && !hasQuery

  return (
    <Main>
      <PageHeader
        title={t('components.title', 'Components')}
        description={t(
          'components.description',
          'Open-source and third-party packages your repositories, images and hosts are built from, with where they are used and what is wrong with them.'
        )}
      >
        <Button variant="outline" onClick={() => setExportOpen(true)}>
          <Download className="me-2 h-4 w-4" aria-hidden />
          {t('components.export', 'Export SBOM')}
        </Button>
        <Can permission={Permission.ComponentsWrite}>
          <Button onClick={() => setImportOpen(true)}>
            <Upload className="me-2 h-4 w-4" aria-hidden />
            {t('components.import', 'Import SBOM')}
          </Button>
        </Can>
      </PageHeader>

      <MetricStrip loading={summaryLoading && !summary} items={metrics} />

      <div className="mt-4 overflow-x-auto">
        <SegmentedLens<ComponentPreset>
          label={t('components.preset.label', 'View')}
          value={preset ?? 'all'}
          options={presetOptions}
          onChange={applyPreset}
          countNoun={t('components.packagesNoun', 'packages')}
        />
      </div>

      {error ? (
        <div className="mt-5">
          <ErrorState
            title={t('components.loadError', 'Could not load components')}
            error={error}
            onRetry={() => mutate()}
          />
        </div>
      ) : empty ? (
        <EmptyState
          className="mt-5"
          card
          icon={Package}
          title={t('components.empty.title', 'No components yet')}
          description={t(
            'components.empty.description',
            'Components appear when a sensor runs an SCA tool, a CI job uploads a report, or you import an SBOM (CycloneDX or SPDX JSON).'
          )}
          action={
            <div className="flex flex-wrap justify-center gap-2">
              <Can permission={Permission.ComponentsWrite}>
                <Button onClick={() => setImportOpen(true)}>
                  <Upload className="me-2 h-4 w-4" aria-hidden />
                  {t('components.import', 'Import SBOM')}
                </Button>
              </Can>
              <Button variant="outline" asChild>
                <Link href="/sensors">{t('components.empty.sensors', 'Set up a sensor')}</Link>
              </Button>
            </div>
          }
        />
      ) : (
        <div className="mt-4 flex items-start gap-5">
          {filtersOpen && (
            <aside
              id="component-filters"
              aria-label={t('components.filtersLabel', 'Component filters')}
              className="sticky top-4 hidden h-[calc(100svh-7.5rem)] w-64 shrink-0 flex-col rounded-xl border bg-card p-4 shadow-sm lg:flex"
            >
              <div className="flex min-h-0 flex-1 flex-col">{facets}</div>
            </aside>
          )}
          <div className="min-w-0 flex-1">
            {isLoading && !data ? (
              <TableSkeleton rows={8} />
            ) : (
              <DataTable
                columns={columns}
                data={data?.data ?? []}
                showSearch={false}
                toolbarStart={toolbarStart}
                manualPagination
                rowCount={data?.total ?? 0}
                pagination={list.pagination}
                onPaginationChange={list.setPagination}
                pageSize={list.perPage}
                pageSizeOptions={[...COMPONENT_PAGE_SIZES]}
                sorting={list.sorting}
                onSortingChange={list.setSorting}
                getRowId={(p) => p.id}
                initialColumnVisibility={{ last_seen: false }}
                emptyMessage={t('components.noMatch', 'No packages match these filters')}
                emptyDescription={t(
                  'components.noMatchHint',
                  'Remove a filter or clear the search.'
                )}
              />
            )}
          </div>
        </div>
      )}

      <FilterSheet
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        title={t('components.filtersLabel', 'Component filters')}
      >
        {facets}
      </FilterSheet>
      <SbomImportDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        onImported={() => mutate()}
      />
      <SbomExportDialog open={exportOpen} onOpenChange={setExportOpen} />
    </Main>
  )
}
