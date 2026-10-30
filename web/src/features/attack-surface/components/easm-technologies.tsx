'use client'

/**
 * Attack surface > Technologies: the technologies detected on the tenant's
 * assets, one row per technology and version, with how many assets run it,
 * the CVEs the corpus knows for that version, whether one is exploited and
 * the open alerts about them. The asset count opens the inventory filtered to
 * that exact version. Rows come from the data-scoped read-layer endpoint;
 * every value is scan output and is shown as text.
 */

import { useCallback, useMemo, useState, type ReactElement } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Download, ShieldX } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  DataTable,
  EmptyState,
  ErrorState,
  FilterSelect,
  KEVIndicatorBadge,
  MetricStrip,
  RelativeTime,
  StackedCell,
  TonePill,
  type MetricStripItem,
} from '@/features/shared'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import {
  TECHNOLOGY_CATEGORIES,
  useCategoryLabel,
} from '@/features/assets/components/technologies/technologies-by-category'
import type { TechnologyCategory as AssetTechnologyCategory } from '@/features/assets/types'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
import { downloadCsv } from '@/hooks/use-csv-export'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  fetchAllTechnologies,
  useTechnologies,
  useTechnologyStats,
} from '../hooks/use-technologies'
import {
  VERSION_FILTERS,
  isTechnologyCategory,
  isVersionFilter,
  technologiesCsv,
  technologyAssetsHref,
  type TechnologyFilters,
  type TechnologyRow,
  type VersionFilter,
} from '../lib/technologies'

const PAGE_SIZES = [20, 50, 100]
const SORT_FIELDS = [
  'name',
  'version',
  'category',
  'vendor',
  'asset_count',
  'cve_count',
  'top_cvss',
  'active_alerts',
  'last_seen',
] as const

/** The CVE figures of a row: count, the top CVE (linked when allowed) and its score. */
function CVECell({ row, canSeeVulns }: { row: TechnologyRow; canSeeVulns: boolean }) {
  const { t } = useTranslation()
  if (row.cve_count === 0) {
    return (
      <span className="text-muted-foreground">
        {t('attackSurface.technologies.noCves', 'None known')}
      </span>
    )
  }
  const top = row.top_cve
  const topLabel =
    top && row.top_cvss !== undefined
      ? t('attackSurface.technologies.topCve', '{cve} (CVSS {score})', {
          cve: top,
          score: row.top_cvss.toFixed(1),
        })
      : top
  return (
    <StackedCell
      primary={t('attackSurface.technologies.cveCount', '{count} CVEs', { count: row.cve_count })}
      secondary={
        top ? (
          canSeeVulns ? (
            <Link href={`/vulnerabilities/${encodeURIComponent(top)}`} className="hover:underline">
              {topLabel}
            </Link>
          ) : (
            topLabel
          )
        ) : undefined
      }
    />
  )
}

/** KEV when a CVE is known exploited, otherwise a public-exploit pill. */
function ExploitCell({ row }: { row: TechnologyRow }) {
  const { t } = useTranslation()
  if (row.kev) return <KEVIndicatorBadge inKEV size="sm" showDueDate={false} />
  if (row.exploit_available) {
    return (
      <TonePill
        tone="warning"
        state="exploit"
        label={t('attackSurface.technologies.exploit', 'Public exploit')}
      />
    )
  }
  return <span className="text-muted-foreground">-</span>
}

function useColumns(canSeeVulns: boolean): ColumnDef<TechnologyRow>[] {
  const { t } = useTranslation()
  const categoryLabel = useCategoryLabel()
  return useMemo<ColumnDef<TechnologyRow>[]>(
    () => [
      {
        id: 'name',
        header: t('attackSurface.technologies.col.technology', 'Technology'),
        cell: ({ row }) => (
          <StackedCell
            truncate
            className="max-w-[260px]"
            primary={<span className="font-medium">{row.original.name}</span>}
            secondary={row.original.vendor || undefined}
          />
        ),
      },
      {
        id: 'version',
        header: t('attackSurface.technologies.col.version', 'Version'),
        cell: ({ row }) =>
          row.original.version_known ? (
            <code className="font-mono text-xs">{row.original.version}</code>
          ) : (
            <span className="text-muted-foreground">
              {t('attackSurface.technologies.versionUnknown', 'Unknown')}
            </span>
          ),
      },
      {
        id: 'category',
        header: t('attackSurface.technologies.col.category', 'Category'),
        cell: ({ row }) => categoryLabel(row.original.category as AssetTechnologyCategory),
      },
      {
        id: 'asset_count',
        header: t('attackSurface.technologies.col.assets', 'Assets'),
        cell: ({ row }) => (
          <Link
            href={technologyAssetsHref(row.original)}
            className="font-medium tabular-nums hover:underline"
            aria-label={t(
              'attackSurface.technologies.openAssets',
              'Open the {count} assets running {name}',
              {
                count: row.original.asset_count,
                name: row.original.name,
              }
            )}
          >
            {row.original.asset_count}
          </Link>
        ),
      },
      {
        id: 'cve_count',
        header: t('attackSurface.technologies.col.cves', 'CVEs'),
        cell: ({ row }) => <CVECell row={row.original} canSeeVulns={canSeeVulns} />,
      },
      {
        id: 'exploit',
        header: t('attackSurface.technologies.col.exploit', 'Exploit'),
        enableSorting: false,
        cell: ({ row }) => <ExploitCell row={row.original} />,
      },
      {
        id: 'active_alerts',
        header: t('attackSurface.technologies.col.alerts', 'Active alerts'),
        cell: ({ row }) => (
          <span
            className={
              row.original.active_alerts > 0
                ? 'font-medium tabular-nums'
                : 'text-muted-foreground tabular-nums'
            }
          >
            {row.original.active_alerts}
          </span>
        ),
      },
      {
        id: 'last_seen',
        header: t('attackSurface.technologies.col.lastSeen', 'Last seen'),
        cell: ({ row }) => <RelativeTime date={row.original.last_seen} />,
      },
    ],
    [t, categoryLabel, canSeeVulns]
  )
}

export function EASMTechnologies() {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.AssetsRead)
  const canSeeVulns = useHasPermission(Permission.VulnerabilitiesRead)
  const categoryLabel = useCategoryLabel()
  const {
    q,
    searchTerm,
    setSearch,
    sort,
    sorting,
    setSorting,
    filters: urlFilters,
    setFilter,
    pagination,
    setPagination,
  } = useListParams({
    pageSizes: PAGE_SIZES,
    defaultPageSize: 20,
    sortFields: SORT_FIELDS,
    defaultSort: '-asset_count',
    filters: { category: '', version: '', cves: '', kev: '' },
  })
  const category = isTechnologyCategory(urlFilters.category) ? urlFilters.category : undefined
  const version: VersionFilter | undefined = isVersionFilter(urlFilters.version)
    ? urlFilters.version
    : undefined
  const withCves = urlFilters.cves === 'true'
  const kev = urlFilters.kev === 'true'
  const filters: TechnologyFilters = useMemo(
    () => ({ q: searchTerm, category, version, withCves, kev }),
    [searchTerm, category, version, withCves, kev]
  )
  const list = useTechnologies(
    filters,
    { page: pagination.pageIndex + 1, perPage: pagination.pageSize },
    sort
  )
  const stats = useTechnologyStats(filters)
  const columns = useColumns(canSeeVulns)
  const [exporting, setExporting] = useState(false)

  const versionLabel = useCallback(
    (v: VersionFilter) =>
      v === 'known'
        ? t('attackSurface.technologies.version.known', 'Version known')
        : t('attackSurface.technologies.version.unknown', 'Version unknown'),
    [t]
  )
  const toggle = useCallback(
    (name: 'cves' | 'kev' | 'version', on: boolean, value = 'true') => {
      setFilter(name, on ? value : '')
    },
    [setFilter]
  )

  const exportCsv = async () => {
    setExporting(true)
    try {
      const rows = await fetchAllTechnologies(filters, sort)
      downloadCsv(
        technologiesCsv(rows, [
          t('attackSurface.technologies.col.technology', 'Technology'),
          t('attackSurface.technologies.col.version', 'Version'),
          t('attackSurface.technologies.csv.vendor', 'Vendor'),
          t('attackSurface.technologies.col.category', 'Category'),
          t('attackSurface.technologies.col.assets', 'Assets'),
          t('attackSurface.technologies.col.cves', 'CVEs'),
          t('attackSurface.technologies.csv.topCve', 'Top CVE'),
          t('attackSurface.technologies.csv.topCvss', 'Top CVSS'),
          t('attackSurface.technologies.col.exploit', 'Exploit'),
          t('attackSurface.technologies.csv.sources', 'Detected by'),
        ]),
        'technologies.csv'
      )
    } catch {
      toast.error(t('attackSurface.technologies.exportFailed', 'Could not export. Try again.'))
    } finally {
      setExporting(false)
    }
  }

  if (!canRead) {
    return (
      <EmptyState
        icon={ShieldX}
        title={t('attackSurface.technologies.noAccess.title', 'Access denied')}
        description={t(
          'attackSurface.technologies.noAccess.description',
          "You don't have permission to view assets. Ask your administrator for access."
        )}
      />
    )
  }

  const s = stats.data
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('attackSurface.technologies.metric.total', 'Technology versions'),
      value: s?.total ?? 0,
      active: !withCves && !kev && !version,
      onClick: () => {
        toggle('cves', false)
        toggle('kev', false)
        toggle('version', false)
      },
    },
    {
      key: 'with_cves',
      label: t('attackSurface.technologies.metric.withCves', 'With known CVEs'),
      value: s?.with_cves ?? 0,
      tone: 'warning',
      active: withCves,
      onClick: () => toggle('cves', !withCves),
    },
    {
      key: 'exploited',
      label: t('attackSurface.technologies.metric.kev', 'Known exploited'),
      value: s?.kev ?? 0,
      tone: 'danger',
      active: kev,
      onClick: () => toggle('kev', !kev),
    },
    {
      key: 'unknown_version',
      label: t('attackSurface.technologies.metric.unknownVersion', 'Version unknown'),
      value: s?.unknown_version ?? 0,
      active: version === 'unknown',
      onClick: () => toggle('version', version !== 'unknown', 'unknown'),
    },
  ]

  const chips = [
    category && (
      <RemovableFilterChip
        key="category"
        text={t('attackSurface.technologies.chip.category', 'Category is {value}', {
          value: categoryLabel(category),
        })}
        onRemove={() => setFilter('category', '')}
        removeLabel={t('attackSurface.technologies.chip.remove', 'Remove filter {filter}', {
          filter: categoryLabel(category),
        })}
      />
    ),
    version && (
      <RemovableFilterChip
        key="version"
        text={versionLabel(version)}
        onRemove={() => toggle('version', false)}
        removeLabel={t('attackSurface.technologies.chip.remove', 'Remove filter {filter}', {
          filter: versionLabel(version),
        })}
      />
    ),
    withCves && (
      <RemovableFilterChip
        key="cves"
        text={t('attackSurface.technologies.metric.withCves', 'With known CVEs')}
        onRemove={() => toggle('cves', false)}
        removeLabel={t('attackSurface.technologies.chip.remove', 'Remove filter {filter}', {
          filter: t('attackSurface.technologies.metric.withCves', 'With known CVEs'),
        })}
      />
    ),
    kev && (
      <RemovableFilterChip
        key="kev"
        text={t('attackSurface.technologies.metric.kev', 'Known exploited')}
        onRemove={() => toggle('kev', false)}
        removeLabel={t('attackSurface.technologies.chip.remove', 'Remove filter {filter}', {
          filter: t('attackSurface.technologies.metric.kev', 'Known exploited'),
        })}
      />
    ),
  ].filter((c): c is ReactElement => Boolean(c))

  return (
    <>
      <MetricStrip loading={stats.isLoading && !s} items={metrics} />
      <DataTable
        columns={columns}
        data={list.rows}
        getRowId={(r) => `${r.key}\u0000${r.version}`}
        showSearch={false}
        search={{
          value: q,
          onChange: setSearch,
          placeholder: t(
            'attackSurface.technologies.search',
            'Search technology, version or vendor…'
          ),
        }}
        showColumnToggle={false}
        toolbarStart={
          <>
            <FilterSelect<AssetTechnologyCategory>
              label={t('attackSurface.technologies.filter.category', 'Category')}
              value={category ?? ''}
              options={TECHNOLOGY_CATEGORIES.map((c) => ({ value: c, label: categoryLabel(c) }))}
              onChange={(v) => setFilter('category', v)}
            />
            <FilterSelect<VersionFilter>
              label={t('attackSurface.technologies.filter.version', 'Version')}
              value={version ?? ''}
              options={VERSION_FILTERS.map((v) => ({ value: v, label: versionLabel(v) }))}
              onChange={(v) => setFilter('version', v)}
            />
          </>
        }
        toolbarEnd={
          <Button variant="outline" size="sm" onClick={exportCsv} disabled={exporting}>
            <Download className="me-2 h-4 w-4" aria-hidden />
            {t('attackSurface.technologies.export', 'Export CSV')}
          </Button>
        }
        toolbarBelow={
          chips.length > 0 ? (
            <FilterChipsRow
              label={t('attackSurface.technologies.activeFilters', 'Active filters')}
              chips={chips}
              end={t('attackSurface.technologies.count', '{count} technology versions', {
                count: list.total,
              })}
            />
          ) : undefined
        }
        isLoading={list.isLoading && list.rows.length === 0}
        errorState={
          list.error && !list.isLoading ? (
            <ErrorState
              title={t('attackSurface.technologies.error', 'technologies')}
              error={list.error}
              onRetry={() => list.mutate()}
            />
          ) : undefined
        }
        manualPagination
        rowCount={list.total}
        pagination={pagination}
        onPaginationChange={setPagination}
        sorting={sorting}
        onSortingChange={setSorting}
        pageSizeOptions={PAGE_SIZES}
        emptyMessage={t('attackSurface.technologies.empty.title', 'No technologies yet')}
        emptyDescription={t(
          'attackSurface.technologies.empty.description',
          'Technologies appear here once a scan of your external assets fingerprints what they run.'
        )}
      />
    </>
  )
}
