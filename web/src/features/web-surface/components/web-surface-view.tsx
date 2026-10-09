'use client'

import { useCallback, useMemo, useState } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Globe, ShieldX } from 'lucide-react'
import { Main } from '@/components/layout'
import {
  DataTable,
  EmptyState,
  ErrorState,
  MetricStrip,
  PageHeader,
  RelativeTime,
  SegmentedLens,
  StackedCell,
  type MetricStripItem,
} from '@/features/shared'
import { AssetsSectionTabs } from '@/features/assets/components/assets-section-tabs'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Permission, useHasPermission } from '@/lib/permissions'
import type {
  WebEndpointEventResponse,
  WebEndpointResponse,
  WebOriginResponse,
  WebPathCatalogEntry,
  WebPathPatternResponse,
} from '@/lib/api/generated'
import {
  useWebEndpointEvents,
  useWebEndpointStats,
  useWebEndpoints,
  useWebOrigins,
  useWebPathCatalog,
  useWebPathPatterns,
} from '../api/use-web-surface'
import { isWebSurfaceTab, type EndpointFilters, type WebSurfaceTab } from '../lib/web-surface-url'
import { AuthPill, CatalogBadge, ExcludedBadge, MethodBadge, PathText } from './web-surface-badges'
import { EndpointSheet } from './endpoint-sheet'

const PAGE_SIZES = [20, 50, 100]

const TAB_LABEL: Record<WebSurfaceTab, string> = {
  origins: 'Origins',
  endpoints: 'Endpoints',
  patterns: 'Path patterns',
  changes: 'Changes',
}

const EVENT_LABEL: Record<string, string> = {
  appeared: 'Appeared',
  returned: 'Seen again',
  gone: 'Gone',
  status_changed: 'Status changed',
  auth_changed: 'Auth changed',
  param_added: 'New parameter',
}

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'ANY']
const KINDS = ['page', 'api', 'form', 'script', 'graphql', 'websocket', 'other']

function num(v: number | undefined): number {
  return v ?? 0
}

/** Detail of a change event in words (status codes and auth states only). */
export function eventDetail(e: WebEndpointEventResponse): string {
  const d = (e.detail ?? {}) as Record<string, unknown>
  if (e.kind === 'status_changed' || e.kind === 'auth_changed') {
    return `${String(d.from ?? '?')} → ${String(d.to ?? '?')}`
  }
  if (e.kind === 'param_added') return `${String(d.count ?? 1)} new`
  return ''
}

function usePaging(prefix: string) {
  const [pageParam, setPageParam] = useUrlFilter(`${prefix}page`, '1')
  const [perPageParam, setPerPageParam] = useUrlFilter(`${prefix}per_page`, '20')
  const pagination = useMemo(
    () => ({
      pageIndex: Math.max(0, (parseInt(pageParam, 10) || 1) - 1),
      pageSize: PAGE_SIZES.includes(parseInt(perPageParam, 10)) ? parseInt(perPageParam, 10) : 20,
    }),
    [pageParam, perPageParam]
  )
  const setPagination = useCallback(
    (next: { pageIndex: number; pageSize: number }) => {
      setPageParam(String(next.pageIndex + 1))
      setPerPageParam(String(next.pageSize))
    },
    [setPageParam, setPerPageParam]
  )
  const page = useMemo(
    () => ({ page: pagination.pageIndex + 1, perPage: pagination.pageSize }),
    [pagination]
  )
  const reset = useCallback(() => setPageParam('1'), [setPageParam])
  return { pagination, setPagination, page, reset }
}

function TableSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 8 }).map((_, i) => (
        <Skeleton key={i} className="h-12 w-full" />
      ))}
    </div>
  )
}

/**
 * Web surface (RFC-056): the origins (http_service assets), the endpoints
 * (method + path template) they serve, the same path across origins, and what
 * changed. Values are scan output: paths render as text, never as links that
 * fetch them. Endpoints under a scope exclusion show as "Excluded, untested":
 * recorded, never tested.
 */
export function WebSurfaceView() {
  const canRead = useHasPermission(Permission.AssetsRead)
  const [tabParam, setTabParam] = useUrlFilter('tab', 'origins')
  const tab: WebSurfaceTab = isWebSurfaceTab(tabParam) ? tabParam : 'origins'

  const [q, setQ] = useUrlFilter('q', '')
  const [origin, setOrigin] = useUrlFilter('origin', '')
  const [pathHash, setPathHash] = useUrlFilter('path_hash', '')
  const [method, setMethod] = useUrlFilter('method', '')
  const [kind, setKind] = useUrlFilter('kind', '')
  const [excluded, setExcluded] = useUrlFilter('excluded', 'false')
  const [sensitive, setSensitive] = useUrlFilter('sensitive', 'false')
  const [eventKind, setEventKind] = useUrlFilter('event', '')
  const [selected, setSelected] = useState<string | null>(null)

  const paging = usePaging('')

  const filters: EndpointFilters = useMemo(
    () => ({
      q,
      originAssetId: origin || undefined,
      pathHash: pathHash || undefined,
      method: method || undefined,
      kind: kind || undefined,
      excludedOnly: excluded === 'true',
      sensitiveOnly: sensitive === 'true',
    }),
    [q, origin, pathHash, method, kind, excluded, sensitive]
  )

  const stats = useWebEndpointStats(filters, canRead)
  const { data: catalog } = useWebPathCatalog(canRead)
  const catalogByKey = useMemo(() => {
    const m = new Map<string, WebPathCatalogEntry>()
    for (const e of catalog?.entries ?? []) if (e.key) m.set(e.key, e)
    return m
  }, [catalog])

  const origins = useWebOrigins(filters, paging.page, canRead && tab === 'origins')
  const endpoints = useWebEndpoints(filters, paging.page, canRead && tab === 'endpoints')
  const patterns = useWebPathPatterns(filters, paging.page, canRead && tab === 'patterns')
  const events = useWebEndpointEvents(
    {
      kind: eventKind || undefined,
      originAssetId: origin || undefined,
      sensitiveOnly: sensitive === 'true',
    },
    paging.page,
    canRead && tab === 'changes'
  )

  const go = useCallback(
    (next: WebSurfaceTab, extra?: { origin?: string; pathHash?: string }) => {
      setTabParam(next)
      if (extra?.origin !== undefined) setOrigin(extra.origin)
      if (extra?.pathHash !== undefined) setPathHash(extra.pathHash)
      paging.reset()
    },
    [setTabParam, setOrigin, setPathHash, paging]
  )

  const s = stats.data
  const metrics: MetricStripItem[] = [
    { key: 'endpoints', label: 'Endpoints', value: num(s?.total), onClick: () => go('endpoints') },
    {
      key: 'unauth_sensitive',
      label: 'Sensitive, no auth',
      value: num(s?.unauth_sensitive),
      tone: 'danger',
      hint: 'Sensitive paths answering without authentication',
      onClick: () => {
        setSensitive('true')
        go('endpoints')
      },
    },
    {
      key: 'excluded_untested',
      label: 'Excluded, untested',
      value: num(s?.excluded_untested),
      tone: 'warning',
      hint: 'Under a scope exclusion: never tested',
      active: excluded === 'true',
      onClick: () => {
        setExcluded(excluded === 'true' ? 'false' : 'true')
        go('endpoints')
      },
    },
    {
      key: 'excluded_sensitive',
      label: 'Sensitive and untested',
      value: num(s?.excluded_sensitive),
      tone: 'danger',
      hint: 'Sensitive paths behind an exclusion',
    },
  ]

  const originColumns = useMemo<ColumnDef<WebOriginResponse>[]>(
    () => [
      {
        id: 'origin',
        header: 'Origin',
        enableSorting: false,
        cell: ({ row }) => (
          <StackedCell
            truncate
            className="max-w-[340px]"
            primary={
              <Link href={`/assets/${row.original.origin_asset_id}`} className="hover:underline">
                {row.original.origin}
              </Link>
            }
            secondary={`${num(row.original.active_count)} active of ${num(row.original.endpoint_count)}`}
          />
        ),
      },
      {
        id: 'new',
        header: 'New (7 days)',
        enableSorting: false,
        cell: ({ row }) => (
          <span className="tabular-nums">{num(row.original.new_last_7_days)}</span>
        ),
      },
      {
        id: 'unauth',
        header: 'Sensitive, no auth',
        enableSorting: false,
        cell: ({ row }) =>
          num(row.original.unauth_sensitive) > 0 ? (
            <Badge variant="destructive" className="tabular-nums">
              {row.original.unauth_sensitive}
            </Badge>
          ) : (
            <span className="text-muted-foreground">0</span>
          ),
      },
      {
        id: 'gap',
        header: 'Coverage gap',
        enableSorting: false,
        cell: ({ row }) => {
          const o = row.original
          if (num(o.excluded_untested) === 0)
            return <span className="text-muted-foreground">None</span>
          return (
            <span className="text-sm">
              {o.excluded_untested} untested
              {num(o.excluded_sensitive) > 0 && (
                <span className="text-warning"> ({o.excluded_sensitive} sensitive)</span>
              )}
            </span>
          )
        },
      },
      {
        id: 'last_seen',
        header: 'Last seen',
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
      {
        id: 'open',
        header: '',
        enableSorting: false,
        cell: ({ row }) => (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => go('endpoints', { origin: row.original.origin_asset_id ?? '' })}
          >
            Endpoints
          </Button>
        ),
      },
    ],
    [go]
  )

  const endpointColumns = useMemo<ColumnDef<WebEndpointResponse>[]>(
    () => [
      {
        id: 'endpoint',
        header: 'Endpoint',
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex min-w-0 items-start gap-2">
            <MethodBadge method={row.original.method} />
            <StackedCell
              truncate
              className="max-w-[420px]"
              primary={<PathText path={row.original.path_template} />}
              secondary={row.original.origin}
            />
          </div>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        enableSorting: false,
        cell: ({ row }) => <span className="tabular-nums">{row.original.last_status || '—'}</span>,
      },
      {
        id: 'auth',
        header: 'Auth',
        enableSorting: false,
        cell: ({ row }) => <AuthPill state={row.original.auth_state} />,
      },
      {
        id: 'flags',
        header: 'Notes',
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
            <CatalogBadge entry={row.original.catalog} />
            {!row.original.in_scope && <ExcludedBadge exclusionId={row.original.exclusion_id} />}
            {row.original.state === 'ignored' && (
              <Badge variant="secondary" className="font-normal">
                Ignored
              </Badge>
            )}
          </div>
        ),
      },
      {
        id: 'params',
        header: 'Params',
        enableSorting: false,
        cell: ({ row }) => <span className="tabular-nums">{num(row.original.param_count)}</span>,
      },
      {
        id: 'last_seen',
        header: 'Last seen',
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
    ],
    []
  )

  const patternColumns = useMemo<ColumnDef<WebPathPatternResponse>[]>(
    () => [
      {
        id: 'pattern',
        header: 'Path',
        enableSorting: false,
        cell: ({ row }) => (
          <StackedCell
            truncate
            className="max-w-[420px]"
            primary={<PathText path={row.original.path_template} />}
            secondary={(row.original.methods ?? []).join(' · ')}
          />
        ),
      },
      {
        id: 'origins',
        header: 'Origins',
        enableSorting: false,
        cell: ({ row }) => <span className="tabular-nums">{num(row.original.origin_count)}</span>,
      },
      {
        id: 'reachable',
        header: 'Answers 2xx',
        enableSorting: false,
        cell: ({ row }) => (
          <span className="tabular-nums">{num(row.original.reachable_count)}</span>
        ),
      },
      {
        id: 'unauth',
        header: 'No auth',
        enableSorting: false,
        cell: ({ row }) => <span className="tabular-nums">{num(row.original.unauth_count)}</span>,
      },
      {
        id: 'untested',
        header: 'Untested',
        enableSorting: false,
        cell: ({ row }) => (
          <span className="tabular-nums">{num(row.original.excluded_untested)}</span>
        ),
      },
      {
        id: 'catalog',
        header: 'Sensitive',
        enableSorting: false,
        cell: ({ row }) => <CatalogBadge entry={row.original.catalog} />,
      },
      {
        id: 'open',
        header: '',
        enableSorting: false,
        cell: ({ row }) => (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => go('endpoints', { pathHash: row.original.path_hash ?? '', origin: '' })}
          >
            Where
          </Button>
        ),
      },
    ],
    [go]
  )

  const eventColumns = useMemo<ColumnDef<WebEndpointEventResponse>[]>(
    () => [
      {
        id: 'at',
        header: 'When',
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.at} />,
      },
      {
        id: 'kind',
        header: 'Change',
        enableSorting: false,
        cell: ({ row }) => (
          <Badge
            variant={row.original.kind === 'gone' ? 'outline' : 'secondary'}
            className="font-normal"
          >
            {EVENT_LABEL[row.original.kind ?? ''] ?? row.original.kind}
          </Badge>
        ),
      },
      {
        id: 'endpoint',
        header: 'Endpoint',
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex min-w-0 items-start gap-2">
            <MethodBadge method={row.original.method} />
            <StackedCell
              truncate
              className="max-w-[420px]"
              primary={<PathText path={row.original.path_template} />}
              secondary={row.original.origin}
            />
          </div>
        ),
      },
      {
        id: 'detail',
        header: 'Detail',
        enableSorting: false,
        cell: ({ row }) => <span className="text-sm">{eventDetail(row.original) || '—'}</span>,
      },
      {
        id: 'sensitive',
        header: 'Sensitive',
        enableSorting: false,
        cell: ({ row }) =>
          row.original.catalog_key ? (
            <CatalogBadge entry={catalogByKey.get(row.original.catalog_key)} />
          ) : null,
      },
    ],
    [catalogByKey]
  )

  if (!canRead) {
    return (
      <Main>
        <PageHeader title="Web surface" description="Origins, endpoints and parameters." />
        <EmptyState
          className="mt-5"
          icon={ShieldX}
          title="Access denied"
          description="You don't have permission to view assets. Ask your administrator for access."
        />
      </Main>
    )
  }

  const active =
    tab === 'origins'
      ? origins
      : tab === 'endpoints'
        ? endpoints
        : tab === 'patterns'
          ? patterns
          : events

  const toolbarStart = (
    <div className="flex flex-wrap items-center gap-2">
      {tab !== 'changes' && (
        <Input
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            paging.reset()
          }}
          placeholder="Search paths"
          aria-label="Search paths"
          className="h-9 w-[220px]"
        />
      )}
      {tab === 'endpoints' && (
        <>
          <Select value={method || 'all'} onValueChange={(v) => setMethod(v === 'all' ? '' : v)}>
            <SelectTrigger className="h-9 w-[120px]" aria-label="Method">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Any method</SelectItem>
              {METHODS.map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={kind || 'all'} onValueChange={(v) => setKind(v === 'all' ? '' : v)}>
            <SelectTrigger className="h-9 w-[120px]" aria-label="Kind">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Any kind</SelectItem>
              {KINDS.map((k) => (
                <SelectItem key={k} value={k} className="capitalize">
                  {k}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </>
      )}
      {tab === 'changes' && (
        <Select
          value={eventKind || 'all'}
          onValueChange={(v) => setEventKind(v === 'all' ? '' : v)}
        >
          <SelectTrigger className="h-9 w-[160px]" aria-label="Change">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any change</SelectItem>
            {Object.entries(EVENT_LABEL).map(([k, label]) => (
              <SelectItem key={k} value={k}>
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      <div className="flex items-center gap-2">
        <Switch
          id="sensitive-only"
          checked={sensitive === 'true'}
          onCheckedChange={(c) => {
            setSensitive(c ? 'true' : 'false')
            paging.reset()
          }}
        />
        <Label htmlFor="sensitive-only" className="cursor-pointer text-sm font-normal">
          Sensitive only
        </Label>
      </div>
      {(origin || pathHash) && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            setOrigin('')
            setPathHash('')
            paging.reset()
          }}
        >
          Clear {origin ? 'origin' : 'path'} filter
        </Button>
      )}
    </div>
  )

  return (
    <Main>
      <PageHeader
        title="Web surface"
        description="What your web origins serve: endpoints, their parameters (names only), the same path across origins, and what changed."
      />
      <AssetsSectionTabs />
      <MetricStrip className="mt-5" loading={stats.isLoading && !s} items={metrics} />
      <SegmentedLens
        className="mt-5"
        label="Web surface view"
        value={tab}
        options={(Object.keys(TAB_LABEL) as WebSurfaceTab[]).map((t) => ({
          value: t,
          label: TAB_LABEL[t],
        }))}
        onChange={(t) => go(t)}
      />
      <div className="mt-4">
        {active.error && !active.isLoading ? (
          <ErrorState title="web surface" error={active.error} onRetry={() => active.mutate()} />
        ) : active.isLoading && active.rows.length === 0 ? (
          <TableSkeleton />
        ) : tab === 'origins' ? (
          <DataTable
            columns={originColumns}
            data={origins.rows}
            getRowId={(o) => o.origin_asset_id ?? o.origin ?? ''}
            showSearch={false}
            showColumnToggle={false}
            toolbarStart={toolbarStart}
            manualPagination
            rowCount={origins.total}
            pagination={paging.pagination}
            onPaginationChange={paging.setPagination}
            pageSizeOptions={PAGE_SIZES}
            emptyMessage="No web origins yet"
            emptyDescription="Crawl a web service (a workflow with a web crawl step) to record what it serves."
          />
        ) : tab === 'endpoints' ? (
          <DataTable
            columns={endpointColumns}
            data={endpoints.rows}
            getRowId={(e) => e.id ?? ''}
            onRowClick={(e) => setSelected(e.id ?? null)}
            showSearch={false}
            showColumnToggle={false}
            toolbarStart={toolbarStart}
            manualPagination
            rowCount={endpoints.total}
            pagination={paging.pagination}
            onPaginationChange={paging.setPagination}
            pageSizeOptions={PAGE_SIZES}
            emptyMessage="No endpoints match"
            emptyDescription="Clear a filter, or crawl the origin again."
          />
        ) : tab === 'patterns' ? (
          <DataTable
            columns={patternColumns}
            data={patterns.rows}
            getRowId={(p) => p.path_hash ?? ''}
            showSearch={false}
            showColumnToggle={false}
            toolbarStart={toolbarStart}
            manualPagination
            rowCount={patterns.total}
            pagination={paging.pagination}
            onPaginationChange={paging.setPagination}
            pageSizeOptions={PAGE_SIZES}
            emptyMessage="No path patterns"
            emptyDescription="Paths appear here once an origin is crawled; the same path on many origins is listed once."
          />
        ) : (
          <DataTable
            columns={eventColumns}
            data={events.rows}
            getRowId={(e) => e.id ?? ''}
            onRowClick={(e) => setSelected(e.endpoint_id ?? null)}
            showSearch={false}
            showColumnToggle={false}
            toolbarStart={toolbarStart}
            manualPagination
            rowCount={events.total}
            pagination={paging.pagination}
            onPaginationChange={paging.setPagination}
            pageSizeOptions={PAGE_SIZES}
            emptyMessage="No changes"
            emptyDescription="New, gone and changed endpoints appear here after each crawl."
          />
        )}
      </div>
      <EndpointSheet
        endpointId={selected}
        onClose={() => setSelected(null)}
        onChanged={() => void endpoints.mutate()}
      />
      <p className="mt-4 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Globe className="h-3.5 w-3.5" aria-hidden />
        Paths are shown as text and never opened from here.
      </p>
    </Main>
  )
}
