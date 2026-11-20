'use client'

/**
 * Paths: a web origin's endpoints as a tree of path segments
 * (server/docs/architecture/web-surface.md, "Path tree").
 *
 * - From 1024 px: the tree on the start side, the endpoints of the selected
 *   path in the shared table beside it. A row opens the endpoint sheet (an
 *   overlay, never a third panel).
 * - Below 1024 px: one level at a time, as a list with a breadcrumb; a path
 *   drills in, an endpoint opens the sheet.
 *
 * Filters are tokens of the list toolbar and apply to the tree and the table
 * alike. Static files are hidden by default; whatever a filter hides is
 * counted on the status line, with one button to show everything again. A
 * path under a scope exclusion stays listed and marked, never hidden. Every
 * value is scan output and renders as text; parameter values are never
 * stored, so none can show.
 */

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Braces, ChevronRight, Download, Folder, Radar, Route } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  DrillDownBreadcrumb,
  EmptyState,
  ErrorState,
  FilterSelect,
  FilterToggle,
  ListToolbar,
  RelativeTime,
  StackedCell,
  ToolbarAction,
} from '@/features/shared'
import { useIsMobile, useIsTablet } from '@/hooks/use-mobile'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useUrlFilter } from '@/hooks/use-url-param'
import { LazyScanAssetsDialog } from '@/features/scans/components/lazy-dialogs'
import { useWebPaths, type WebPathEndpoint, type WebPathFolder } from '../api/use-web-paths'
import { downloadCsv, endpointsCsv, fetchAllEndpoints } from '../lib/web-csv'
import {
  DEFAULT_PATH_FILTERS,
  PATH_METHODS,
  normalizeNodePath,
  pathTrail,
  type PathFilters,
  type PathScope,
} from '../lib/web-paths-url'
import { EndpointSheet } from './endpoint-sheet'
import { NodeCounts, PathTree, SeverityDot } from './path-tree'
import { AuthPill, ExcludedBadge, MethodBadge, PathText } from './web-surface-badges'

const PAGE_SIZES = [20, 50, 100]

export interface OriginPathsTabProps {
  assetId: string
  /** The origin (asset name): the root row's label and the crawl target. */
  assetName: string
  /** The viewer may start a scan of this asset now (the page's scan gate). */
  canCrawl: boolean
}

function usePathColumns(): ColumnDef<WebPathEndpoint>[] {
  const { t } = useTranslation()
  return useMemo<ColumnDef<WebPathEndpoint>[]>(
    () => [
      {
        id: 'endpoint',
        header: t('attackSurface.web.col.endpoint', 'Endpoint'),
        enableSorting: false,
        meta: {
          kind: 'name',
          label: t('attackSurface.web.col.endpoint', 'Endpoint'),
          pin: 'start',
        },
        cell: ({ row }) => (
          <div className="flex min-w-0 items-start gap-2">
            <MethodBadge method={row.original.method} />
            <StackedCell
              truncate
              primary={<PathText path={row.original.path_template} />}
              secondary={
                !row.original.in_scope ? (
                  <ExcludedBadge exclusionId={row.original.exclusion_id} />
                ) : undefined
              }
            />
          </div>
        ),
      },
      {
        id: 'status',
        header: t('attackSurface.paths.col.status', 'Last status'),
        enableSorting: false,
        meta: { kind: 'number', label: t('attackSurface.paths.col.status', 'Last status') },
        cell: ({ row }) => <span className="tabular-nums">{row.original.last_status || '-'}</span>,
      },
      {
        id: 'findings',
        header: t('attackSurface.paths.col.findings', 'Findings'),
        enableSorting: false,
        meta: { kind: 'number', label: t('attackSurface.paths.col.findings', 'Findings') },
        cell: ({ row }) =>
          row.original.finding_count > 0 ? (
            <span className="inline-flex items-center gap-1.5 tabular-nums">
              <SeverityDot severity={row.original.top_severity} />
              {row.original.finding_count}
            </span>
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        id: 'content_type',
        header: t('attackSurface.paths.col.contentType', 'Content type'),
        enableSorting: false,
        meta: {
          kind: 'text',
          label: t('attackSurface.paths.col.contentType', 'Content type'),
          hideBelow: 900,
          maxWidth: 180,
        },
        cell: ({ row }) => (
          <span className="truncate text-sm text-muted-foreground">
            {row.original.content_type || '-'}
          </span>
        ),
      },
      {
        id: 'last_seen',
        header: t('attackSurface.web.col.lastSeen', 'Last seen'),
        enableSorting: false,
        meta: {
          kind: 'datetime-recent',
          label: t('attackSurface.web.col.lastSeen', 'Last seen'),
          width: 128,
        },
        cell: ({ row }) => (
          <RelativeTime date={row.original.last_seen_at} className="block truncate" />
        ),
      },
      {
        id: 'auth',
        header: t('attackSurface.web.col.auth', 'Auth'),
        enableSorting: false,
        meta: { kind: 'status', label: t('attackSurface.web.col.auth', 'Auth') },
        cell: ({ row }) => <AuthPill state={row.original.auth_state} />,
      },
      {
        id: 'params',
        header: t('attackSurface.web.col.params', 'Params'),
        enableSorting: false,
        meta: {
          kind: 'number',
          label: t('attackSurface.web.col.params', 'Params'),
          hideBelow: 960,
        },
        cell: ({ row }) => <span className="tabular-nums">{row.original.param_count ?? 0}</span>,
      },
    ],
    [t]
  )
}

/** The filter tokens, the search and Export, over the tree and the table alike. */
function PathsToolbar({
  input,
  onInput,
  filters,
  onFilters,
  onExport,
  exporting,
}: {
  input: string
  onInput: (v: string) => void
  filters: PathFilters
  onFilters: (f: PathFilters) => void
  onExport: () => void
  exporting: boolean
}) {
  const { t } = useTranslation()
  const set = (patch: Partial<PathFilters>) => onFilters({ ...filters, ...patch })
  return (
    <ListToolbar
      search={{
        value: input,
        onChange: onInput,
        placeholder: t('attackSurface.paths.search', 'Search paths'),
      }}
      start={
        <>
          <FilterToggle
            label={t('attackSurface.paths.filter.hideStatic', 'Hide static files')}
            shortLabel={t('attackSurface.paths.filter.hideStaticShort', 'No static')}
            pressed={filters.hideStatic}
            onPressedChange={(v) => set({ hideStatic: v })}
          />
          <FilterToggle
            label={t('attackSurface.paths.filter.hide4xx', 'Hide 4xx answers')}
            shortLabel={t('attackSurface.paths.filter.hide4xxShort', 'No 4xx')}
            pressed={filters.hide4xx}
            onPressedChange={(v) => set({ hide4xx: v })}
          />
          <FilterToggle
            label={t('attackSurface.paths.filter.withFindings', 'Only with findings')}
            shortLabel={t('attackSurface.paths.filter.withFindingsShort', 'With findings')}
            pressed={filters.withFindings}
            onPressedChange={(v) => set({ withFindings: v })}
          />
          <FilterSelect<Exclude<PathScope, ''>>
            label={t('attackSurface.paths.filter.scope', 'Scope')}
            value={filters.scope}
            options={[
              { value: 'in', label: t('attackSurface.paths.filter.inScope', 'In scope') },
              { value: 'out', label: t('attackSurface.paths.filter.outOfScope', 'Out of scope') },
            ]}
            onChange={(v) => set({ scope: v })}
          />
          <FilterSelect<string>
            label={t('attackSurface.paths.filter.method', 'Method')}
            value={filters.method}
            options={PATH_METHODS.map((m) => ({ value: m, label: m }))}
            onChange={(v) => set({ method: v })}
          />
        </>
      }
      end={
        <ToolbarAction
          icon={Download}
          label={t('attackSurface.originWeb.export', 'Export CSV')}
          onClick={onExport}
          disabled={exporting}
        />
      }
    />
  )
}

/** The phone and tablet form: one level as a list, a breadcrumb back up. */
function PathDrillList({
  assetName,
  path,
  folders,
  endpoints,
  loading,
  onPath,
  onEndpoint,
}: {
  assetName: string
  path: string
  folders: WebPathFolder[]
  endpoints: WebPathEndpoint[]
  loading: boolean
  onPath: (p: string) => void
  onEndpoint: (id: string) => void
}) {
  const { t } = useTranslation()
  const trail = pathTrail(path)
  return (
    <div className="flex min-w-0 flex-col gap-2" data-testid="path-drill">
      {path !== '/' && (
        <DrillDownBreadcrumb
          mono
          steps={[
            { label: assetName.replace(/^https?:\/\//i, ''), onSelect: () => onPath('/') },
            ...trail.slice(0, -1).map((n) => ({ label: n.name, onSelect: () => onPath(n.path) })),
          ]}
          value={trail[trail.length - 1]?.name ?? ''}
        />
      )}
      <ul
        className="divide-y rounded-lg border bg-card"
        aria-label={t('attackSurface.paths.levelLabel', 'Paths at this level')}
        aria-busy={loading}
      >
        {loading && folders.length === 0 && endpoints.length === 0
          ? [0, 1, 2].map((i) => (
              <li key={i} className="flex h-11 items-center px-3">
                <Skeleton className="h-3 w-40" />
              </li>
            ))
          : null}
        {endpoints.map((e) => (
          <li key={e.id}>
            <button
              type="button"
              onClick={() => e.id && onEndpoint(e.id)}
              className="flex min-h-11 w-full items-center gap-2 px-3 py-2 text-start hover:bg-muted"
            >
              <MethodBadge method={e.method} />
              <span className="min-w-0 flex-1">
                <PathText path={e.path_template} className="line-clamp-2" />
                {!e.in_scope && <ExcludedBadge exclusionId={e.exclusion_id} />}
              </span>
              <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
                {e.last_status || '-'}
              </span>
              <span className="inline-flex min-w-9 shrink-0 items-center justify-end gap-1 text-xs tabular-nums">
                {e.finding_count > 0 && (
                  <>
                    <SeverityDot severity={e.top_severity} />
                    {e.finding_count}
                  </>
                )}
              </span>
            </button>
          </li>
        ))}
        {folders.map((f) => (
          <li key={f.path}>
            <button
              type="button"
              onClick={() => onPath(f.path)}
              className="flex min-h-11 w-full items-center gap-2 px-3 py-2 text-start hover:bg-muted"
            >
              {f.param ? (
                <Braces aria-hidden className="size-4 shrink-0 text-primary" />
              ) : (
                <Folder aria-hidden className="size-4 shrink-0 text-muted-foreground" />
              )}
              <span className="min-w-0 flex-1 truncate font-mono text-sm">
                {f.param && (
                  <span className="sr-only">
                    {t('attackSurface.paths.paramNode', 'Variable segment')}{' '}
                  </span>
                )}
                {f.name}
              </span>
              <NodeCounts
                endpoints={f.endpoints}
                findings={f.findings}
                severity={f.top_severity}
                outOfScope={f.out_of_scope}
              />
              <ChevronRight aria-hidden className="size-4 shrink-0 text-muted-foreground" />
            </button>
          </li>
        ))}
        {!loading && folders.length === 0 && endpoints.length === 0 && (
          <li className="px-3 py-4 text-sm text-muted-foreground">
            {t('attackSurface.paths.nothingHere', 'Nothing at this path with these filters.')}
          </li>
        )}
      </ul>
    </div>
  )
}

export function OriginPathsTab({ assetId, assetName, canCrawl }: OriginPathsTabProps) {
  const { t } = useTranslation()
  const phone = useIsMobile()
  const tablet = useIsTablet()
  const compact = phone || tablet
  const [rawPath, setRawPath] = useUrlFilter('path', '/')
  const path = normalizeNodePath(rawPath)
  const [input, setInput] = useState('')
  const { term } = useSearchQuery(input)
  const [base, setBase] = useState<PathFilters>(DEFAULT_PATH_FILTERS)
  const filters = useMemo(() => ({ ...base, q: term }), [base, term])
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 50 })
  const [selected, setSelected] = useState<string | null>(null)
  const [crawlOpen, setCrawlOpen] = useState(false)
  const [exporting, setExporting] = useState(false)

  const goTo = useCallback(
    (p: string) => {
      setRawPath(p)
      setPagination((s) => ({ ...s, pageIndex: 0 }))
    },
    [setRawPath]
  )
  const onFilters = (f: PathFilters) => {
    setBase(f)
    setPagination((s) => ({ ...s, pageIndex: 0 }))
  }

  // The selected node: its endpoints (all below it on desktop, its own on a
  // phone, where its children are the list) and its child paths.
  const level = useWebPaths(assetId, path, filters, {
    here: compact,
    page: pagination.pageIndex + 1,
    perPage: compact ? 100 : pagination.pageSize,
  })
  // The origin as a whole: the root row, the empty state and the status line.
  const root = useWebPaths(assetId, '/', filters, { perPage: 0 })
  const columns = usePathColumns()
  const data = level.data
  const totals = root.data?.totals

  const exportCsv = async () => {
    setExporting(true)
    try {
      const rows = await fetchAllEndpoints({ originAssetId: assetId })
      downloadCsv(
        endpointsCsv(rows, [
          t('attackSurface.originWeb.csv.method', 'Method'),
          t('attackSurface.originWeb.csv.path', 'Path'),
          t('attackSurface.originWeb.csv.kind', 'Kind'),
          t('attackSurface.originWeb.csv.status', 'Status'),
          t('attackSurface.originWeb.csv.auth', 'Auth'),
          t('attackSurface.originWeb.csv.params', 'Parameters'),
          t('attackSurface.originWeb.csv.lastSeen', 'Last seen'),
        ]),
        'web-endpoints.csv'
      )
    } catch {
      toast.error(t('attackSurface.originWeb.exportFailed', 'Could not export. Try again.'))
    } finally {
      setExporting(false)
    }
  }

  if (root.error && !root.data) {
    return (
      <ErrorState
        title={t('attackSurface.paths.title', 'Paths')}
        error={root.error}
        onRetry={() => void root.mutate()}
      />
    )
  }

  // Never crawled: say so, with the one thing to do about it.
  if (totals && totals.recorded === 0 && totals.findings === 0) {
    return (
      <>
        <EmptyState
          icon={Route}
          title={t('attackSurface.paths.emptyTitle', 'This site has not been crawled yet')}
          description={t(
            'attackSurface.paths.emptyHint',
            'Paths appear here after a crawl visits the site and records the pages and API calls it finds. Paths under a scope exclusion are recorded but never requested.'
          )}
          action={
            canCrawl ? (
              <Button onClick={() => setCrawlOpen(true)}>
                <Radar aria-hidden />
                {t('attackSurface.paths.crawl', 'Crawl this site')}
              </Button>
            ) : undefined
          }
        />
        {canCrawl && (
          <LazyScanAssetsDialog
            open={crawlOpen}
            onOpenChange={setCrawlOpen}
            title={t('attackSurface.paths.crawl', 'Crawl this site')}
            preferCapabilities={['crawler', 'crawl', 'crawl.web']}
            candidates={[{ id: assetId, label: assetName, target: assetName.trim() }]}
          />
        )}
      </>
    )
  }

  const hidden = data?.totals.hidden ?? 0
  const status = (
    <p
      className="flex h-8 min-w-0 items-center gap-2 text-sm text-muted-foreground"
      aria-live="polite"
    >
      <span className="truncate">
        {data
          ? t(
              'attackSurface.paths.shown',
              '{count, plural, one {# endpoint under this path} other {# endpoints under this path}}',
              {
                count: data.totals.endpoints,
              }
            )
          : ' '}
        {data && hidden > 0
          ? ` ${t('attackSurface.paths.hiddenCount', '({count} hidden by filters)', { count: hidden })}`
          : ''}
        {path === '/' && totals && totals.origin_findings > 0
          ? ` ${t(
              'attackSurface.paths.originFindings',
              '{count, plural, one {# finding on the site as a whole} other {# findings on the site as a whole}}',
              {
                count: totals.origin_findings,
              }
            )}`
          : ''}
      </span>
      {hidden > 0 && (
        <Button
          variant="link"
          className="shrink-0"
          onClick={() =>
            onFilters({ ...DEFAULT_PATH_FILTERS, hideStatic: false, includeGone: true })
          }
        >
          {t('attackSurface.paths.showAll', 'Show all')}
        </Button>
      )}
    </p>
  )

  return (
    <div className="flex min-w-0 flex-col gap-2" data-testid="origin-paths">
      <PathsToolbar
        input={input}
        onInput={setInput}
        filters={base}
        onFilters={onFilters}
        onExport={() => void exportCsv()}
        exporting={exporting}
      />
      {status}
      {compact ? (
        <PathDrillList
          assetName={assetName}
          path={path}
          folders={data?.folders ?? []}
          endpoints={data?.endpoints ?? []}
          loading={level.isLoading}
          onPath={goTo}
          onEndpoint={setSelected}
        />
      ) : (
        <div className="grid min-w-0 grid-cols-[16rem_minmax(0,1fr)] items-start gap-4">
          <nav
            aria-label={t('attackSurface.paths.treeLabel', 'Paths of this site')}
            className="sticky top-[calc(var(--app-header-h,3.5rem)+0.5rem)] max-h-[calc(100dvh-var(--app-header-h,3.5rem)-2rem)] min-h-64 overflow-auto rounded-lg border bg-card px-1"
          >
            <PathTree
              assetId={assetId}
              filters={filters}
              selected={path}
              onSelect={goTo}
              rootLabel={assetName.replace(/^https?:\/\//i, '')}
              rootEndpoints={totals?.endpoints ?? 0}
              rootFindings={totals?.findings ?? 0}
              rootSeverity={totals?.top_severity}
            />
          </nav>
          <DataTable
            columns={columns}
            data={data?.endpoints ?? []}
            getRowId={(e) => e.id ?? `${e.method} ${e.path_template}`}
            onRowClick={(e) => setSelected(e.id ?? null)}
            showToolbar={false}
            showColumnToggle={false}
            caption={t('attackSurface.paths.tableCaption', 'Endpoints under {path}', { path })}
            isLoading={level.isLoading && !data}
            errorState={
              level.error && !data ? (
                <ErrorState
                  title={t('attackSurface.paths.title', 'Paths')}
                  error={level.error}
                  onRetry={() => void level.mutate()}
                />
              ) : undefined
            }
            manualPagination
            rowCount={data?.endpoint_total ?? 0}
            pagination={pagination}
            onPaginationChange={setPagination}
            pageSizeOptions={PAGE_SIZES}
            emptyMessage={t(
              'attackSurface.paths.nothingHere',
              'Nothing at this path with these filters.'
            )}
            emptyDescription={
              hidden > 0
                ? t(
                    'attackSurface.paths.nothingHereHint',
                    '{count, plural, one {Filters hide # endpoint here.} other {Filters hide # endpoints here.}}',
                    {
                      count: hidden,
                    }
                  )
                : undefined
            }
          />
        </div>
      )}
      <EndpointSheet
        endpointId={selected}
        onClose={() => setSelected(null)}
        onChanged={() => void level.mutate()}
      />
    </div>
  )
}
