'use client'

/**
 * The Web section of an origin asset (http_service, website): the security
 * header posture, and the origin's endpoints, parameters and changes. It
 * reuses the endpoint and change tables, the sheet and the data-scoped list
 * endpoints of the Web surface page, filtered by this origin. Everything
 * shown is scan output and renders as text: no HTML, no raw links (the
 * origin itself links through SafeExternalLink, http and https only).
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Download, ShieldQuestion } from 'lucide-react'
import { toast } from 'sonner'
import { SafeExternalLink } from '@/components/safe-external-link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  EmptyState,
  ErrorState,
  FilterSelect,
  MetricStrip,
  StackedCell,
  TonePill,
  type MetricStripItem,
} from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'
import type { WebEndpointResponse } from '@/lib/api/generated'
import {
  useWebEndpointEvents,
  useWebEndpointStats,
  useWebEndpoints,
  useWebEndpointsParams,
  useWebPathCatalog,
} from '../api/use-web-surface'
import type { EndpointFilters } from '../lib/web-surface-url'
import { flattenParams, type ParamRow } from '../lib/origin-params'
import {
  POSTURE_HEADER_NAME,
  readPosture,
  type OriginPosture,
  type PostureCookie,
} from '../lib/origin-posture'
import {
  downloadCsv,
  endpointsCsv,
  eventsCsv,
  fetchAllEndpoints,
  fetchAllEvents,
  paramsCsv,
} from '../lib/web-csv'
import { EndpointSheet, RISK_LABEL, SOURCE_LABEL } from './endpoint-sheet'
import { MethodBadge, PathText } from './web-surface-badges'
import { EVENT_KINDS, num, useEndpointColumns, useEventColumns } from './web-surface-columns'

const PAGE_SIZES = [20, 50, 100]
const SECTION_TABS = ['overview', 'endpoints', 'parameters', 'changes'] as const
type SectionTab = (typeof SECTION_TABS)[number]

export interface OriginWebSectionProps {
  assetId: string
  /** The asset name; shown as a link when it is an http(s) URL. */
  assetName?: string
  /** The asset's properties (`asset.metadata`), read for `http_posture`. */
  properties?: unknown
}

/** Asset types that are web origins. */
export function isWebOriginType(type: string | undefined): boolean {
  return type === 'http_service' || type === 'website'
}

function usePaging() {
  const [pageIndex, setPageIndex] = useState(0)
  const [pageSize, setPageSize] = useState(20)
  return {
    pagination: { pageIndex, pageSize },
    setPagination: (n: { pageIndex: number; pageSize: number }) => {
      setPageIndex(n.pageIndex)
      setPageSize(n.pageSize)
    },
    page: { page: pageIndex + 1, perPage: pageSize },
    reset: () => setPageIndex(0),
  }
}

function ExportButton({ onClick, busy }: { onClick: () => void; busy: boolean }) {
  const { t } = useTranslation()
  return (
    <Button variant="outline" size="sm" onClick={onClick} disabled={busy}>
      <Download className="me-2 h-4 w-4" aria-hidden />
      {t('attackSurface.originWeb.export', 'Export CSV')}
    </Button>
  )
}

function useExport() {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const run = async (build: () => Promise<string>, name: string) => {
    setBusy(true)
    try {
      downloadCsv(await build(), `${name}.csv`)
    } catch {
      toast.error(t('attackSurface.originWeb.exportFailed', 'Could not export. Try again.'))
    } finally {
      setBusy(false)
    }
  }
  return { busy, run }
}

function flagPill(t: ReturnType<typeof useTranslation>['t'], label: string, on: boolean | null) {
  if (on === null)
    return (
      <TonePill
        tone="muted"
        label={`${label}: ${t('attackSurface.originWeb.posture.unknown', 'Unknown')}`}
      />
    )
  return <TonePill tone={on ? 'success' : 'warning'} label={label} />
}

function CookieRow({ cookie }: { cookie: PostureCookie }) {
  const { t } = useTranslation()
  return (
    <li className="flex flex-wrap items-center gap-2 py-2">
      <span className="font-mono text-sm break-all">{cookie.name}</span>
      {flagPill(t, t('attackSurface.originWeb.cookie.secure', 'Secure'), cookie.secure)}
      {flagPill(t, t('attackSurface.originWeb.cookie.httpOnly', 'HttpOnly'), cookie.httpOnly)}
      {cookie.sameSite && (
        <Badge variant="outline" className="font-normal">
          {`SameSite ${cookie.sameSite}`}
        </Badge>
      )}
    </li>
  )
}

/** Header posture card: which security headers the origin sends, and its cookie flags. */
export function PostureCard({ posture }: { posture: OriginPosture | null }) {
  const { t } = useTranslation()
  if (!posture) {
    return (
      <EmptyState
        icon={ShieldQuestion}
        title={t('attackSurface.originWeb.posture.emptyTitle', 'No header data yet')}
        description={t(
          'attackSurface.originWeb.posture.emptyHint',
          'Security headers appear here after a sensor inspects this origin. Names and cookie flags are kept, never values.'
        )}
      />
    )
  }
  const missing = posture.headers.filter((h) => !h.present).length
  return (
    <div className="space-y-4">
      <div>
        <p className="mb-2 text-sm text-muted-foreground">
          {missing === 0
            ? t(
                'attackSurface.originWeb.posture.allPresent',
                'All listed security headers are present.'
              )
            : t(
                'attackSurface.originWeb.posture.missingCount',
                '{count} of {total} security headers are missing.',
                {
                  count: missing,
                  total: posture.headers.length,
                }
              )}
        </p>
        <ul
          className="flex flex-wrap gap-2"
          aria-label={t('attackSurface.originWeb.posture.headers', 'Security headers')}
        >
          {posture.headers.map((h) => (
            <li key={h.key}>
              <TonePill
                tone={h.present ? 'success' : 'warning'}
                label={`${POSTURE_HEADER_NAME[h.key]}: ${
                  h.present
                    ? t('attackSurface.originWeb.posture.present', 'Present')
                    : t('attackSurface.originWeb.posture.missing', 'Missing')
                }`}
              />
            </li>
          ))}
        </ul>
      </div>
      {posture.cookies.length > 0 && (
        <div>
          <p className="text-sm font-medium">{t('attackSurface.originWeb.cookies', 'Cookies')}</p>
          <ul className="divide-y" aria-label={t('attackSurface.originWeb.cookies', 'Cookies')}>
            {posture.cookies.map((c) => (
              <CookieRow key={c.name} cookie={c} />
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function OverviewTab({
  assetId,
  assetName,
  properties,
  onOpen,
}: OriginWebSectionProps & { onOpen: (tab: SectionTab) => void }) {
  const { t } = useTranslation()
  const filters: EndpointFilters = useMemo(() => ({ originAssetId: assetId }), [assetId])
  const stats = useWebEndpointStats(filters)
  const s = stats.data
  const items: MetricStripItem[] = [
    {
      key: 'endpoints',
      label: t('attackSurface.originWeb.metric.endpoints', 'Endpoints'),
      value: num(s?.total),
      onClick: () => onOpen('endpoints'),
    },
    {
      key: 'unauth',
      label: t('attackSurface.originWeb.metric.unauth', 'Sensitive, no auth'),
      value: num(s?.unauth_sensitive),
      tone: 'danger',
      onClick: () => onOpen('endpoints'),
    },
    {
      key: 'untested',
      label: t('attackSurface.originWeb.metric.untested', 'Excluded, untested'),
      value: num(s?.excluded_untested),
      tone: 'warning',
      onClick: () => onOpen('endpoints'),
    },
  ]
  const posture = useMemo(() => readPosture(properties), [properties])
  const isUrl = !!assetName && /^https?:\/\//i.test(assetName)
  return (
    <div className="space-y-4">
      <MetricStrip loading={stats.isLoading && !s} items={items} />
      {isUrl && (
        <p className="text-sm">
          <SafeExternalLink href={assetName} className="break-all underline underline-offset-2">
            {assetName}
          </SafeExternalLink>
        </p>
      )}
      <PostureCard posture={posture} />
    </div>
  )
}

function EndpointsTab({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const paging = usePaging()
  const [q, setQ] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const filters: EndpointFilters = useMemo(
    () => ({ originAssetId: assetId, q: q || undefined }),
    [assetId, q]
  )
  const list = useWebEndpoints(filters, paging.page)
  const columns = useEndpointColumns()
  const exp = useExport()
  return (
    <>
      <DataTable
        columns={columns}
        data={list.rows}
        getRowId={(e) => e.id ?? ''}
        onRowClick={(e) => setSelected(e.id ?? null)}
        showSearch={false}
        search={{
          value: q,
          onChange: (v: string) => {
            setQ(v)
            paging.reset()
          },
          placeholder: t('attackSurface.web.search.placeholder', 'Search paths…'),
        }}
        showColumnToggle={false}
        toolbarEnd={
          <ExportButton
            busy={exp.busy}
            onClick={() =>
              void exp.run(
                async () =>
                  endpointsCsv(await fetchAllEndpoints(filters), [
                    t('attackSurface.originWeb.csv.method', 'Method'),
                    t('attackSurface.originWeb.csv.path', 'Path'),
                    t('attackSurface.originWeb.csv.kind', 'Kind'),
                    t('attackSurface.originWeb.csv.status', 'Status'),
                    t('attackSurface.originWeb.csv.auth', 'Auth'),
                    t('attackSurface.originWeb.csv.params', 'Parameters'),
                    t('attackSurface.originWeb.csv.lastSeen', 'Last seen'),
                  ]),
                'web-endpoints'
              )
            }
          />
        }
        isLoading={list.isLoading && list.rows.length === 0}
        errorState={
          list.error && !list.isLoading ? (
            <ErrorState
              title={t('attackSurface.originWeb.errorTitle', 'web surface')}
              error={list.error}
              onRetry={() => list.mutate()}
            />
          ) : undefined
        }
        manualPagination
        rowCount={list.total}
        pagination={paging.pagination}
        onPaginationChange={paging.setPagination}
        pageSizeOptions={PAGE_SIZES}
        emptyMessage={t('attackSurface.originWeb.endpoints.empty', 'No endpoints for this origin')}
        emptyDescription={t(
          'attackSurface.originWeb.endpoints.emptyHint',
          'Crawl this origin to record the endpoints it serves.'
        )}
      />
      <EndpointSheet
        endpointId={selected}
        onClose={() => setSelected(null)}
        onChanged={() => void list.mutate()}
      />
    </>
  )
}

function ParametersTab({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const paging = usePaging()
  const [risk, setRisk] = useState('')
  const filters: EndpointFilters = useMemo(() => ({ originAssetId: assetId }), [assetId])
  // The API lists parameters per endpoint, so the table pages over the
  // endpoints that have some and flattens the parameters of this page.
  const list = useWebEndpoints(filters, paging.page)
  const withParams = useMemo<WebEndpointResponse[]>(
    () => list.rows.filter((e) => e.id && num(e.param_count) > 0),
    [list.rows]
  )
  const ids = useMemo(() => withParams.map((e) => e.id as string), [withParams])
  const params = useWebEndpointsParams(ids)
  const all = useMemo(
    () => (params.lists ? flattenParams(withParams, params.lists) : []),
    [withParams, params.lists]
  )
  const rows = useMemo(
    () => (risk ? all.filter((p) => (p.risk_hints ?? []).includes(risk)) : all),
    [all, risk]
  )
  const exp = useExport()

  const columns = useMemo<ColumnDef<ParamRow>[]>(
    () => [
      {
        id: 'name',
        header: t('attackSurface.originWeb.param.name', 'Parameter'),
        enableSorting: false,
        cell: ({ row }) => <span className="font-mono text-sm break-all">{row.original.name}</span>,
      },
      {
        id: 'location',
        header: t('attackSurface.originWeb.param.location', 'In'),
        enableSorting: false,
        cell: ({ row }) => (
          <Badge variant="outline" className="font-normal">
            {row.original.location}
          </Badge>
        ),
      },
      {
        id: 'endpoint',
        header: t('attackSurface.web.col.endpoint', 'Endpoint'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex min-w-0 items-start gap-2">
            <MethodBadge method={row.original.method} />
            <StackedCell
              truncate
              className="max-w-[360px]"
              primary={<PathText path={row.original.pathTemplate} />}
            />
          </div>
        ),
      },
      {
        id: 'risk',
        header: t('attackSurface.originWeb.param.risk', 'Risk hints'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
            {(row.original.risk_hints ?? []).map((h) => (
              <Badge key={h} variant="secondary" className="font-normal">
                {RISK_LABEL[h] ?? h}
              </Badge>
            ))}
          </div>
        ),
      },
      {
        id: 'sensitive',
        header: t('attackSurface.web.col.sensitive', 'Sensitive'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.sensitive ? (
            <TonePill tone="warning" label={String(row.original.sensitive)} />
          ) : null,
      },
      {
        id: 'sources',
        header: t('attackSurface.originWeb.param.sources', 'Sources'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-sm">
            {(row.original.sources ?? []).map((s) => SOURCE_LABEL[s] ?? s).join(', ')}
          </span>
        ),
      },
    ],
    [t]
  )

  const hints = useMemo(() => {
    const set = new Set<string>(Object.keys(RISK_LABEL))
    for (const p of all) for (const h of p.risk_hints ?? []) set.add(h)
    return [...set]
  }, [all])

  return (
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(p) => `${p.endpointId}:${p.location}:${p.name}`}
      showSearch={false}
      showColumnToggle={false}
      toolbarStart={
        <FilterSelect<string>
          label={t('attackSurface.originWeb.param.riskFilter', 'Risk hint')}
          value={risk}
          options={hints.map((h) => ({ value: h, label: RISK_LABEL[h] ?? h }))}
          onChange={(v) => setRisk(v ?? '')}
        />
      }
      toolbarEnd={
        <ExportButton
          busy={exp.busy}
          onClick={() =>
            void exp.run(
              async () =>
                paramsCsv(rows, [
                  t('attackSurface.originWeb.param.name', 'Parameter'),
                  t('attackSurface.originWeb.param.location', 'In'),
                  t('attackSurface.originWeb.csv.method', 'Method'),
                  t('attackSurface.originWeb.csv.path', 'Path'),
                  t('attackSurface.originWeb.param.risk', 'Risk hints'),
                  t('attackSurface.web.col.sensitive', 'Sensitive'),
                ]),
              'web-parameters'
            )
          }
        />
      }
      isLoading={(list.isLoading || params.isLoading) && rows.length === 0}
      errorState={
        (list.error || params.error) && !list.isLoading ? (
          <ErrorState
            title={t('attackSurface.originWeb.errorTitle', 'web surface')}
            error={list.error ?? params.error}
            onRetry={() => list.mutate()}
          />
        ) : undefined
      }
      manualPagination
      rowCount={list.total}
      pagination={paging.pagination}
      onPaginationChange={paging.setPagination}
      pageSizeOptions={PAGE_SIZES}
      emptyMessage={t('attackSurface.originWeb.params.empty', 'No parameters recorded')}
      emptyDescription={t(
        'attackSurface.originWeb.params.emptyHint',
        'Parameter names appear after a crawl finds forms, queries or API specs. Values are never stored.'
      )}
    />
  )
}

function ChangesTab({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const paging = usePaging()
  const [kind, setKind] = useState('')
  const filters = useMemo(
    () => ({ originAssetId: assetId, kind: kind || undefined }),
    [assetId, kind]
  )
  const list = useWebEndpointEvents(filters, paging.page)
  const { data: catalog } = useWebPathCatalog()
  const catalogByKey = useMemo(() => {
    const m = new Map<string, NonNullable<NonNullable<typeof catalog>['entries']>[number]>()
    for (const e of catalog?.entries ?? []) if (e.key) m.set(e.key, e)
    return m
  }, [catalog])
  const columns = useEventColumns(catalogByKey)
  const [selected, setSelected] = useState<string | null>(null)
  const exp = useExport()
  return (
    <>
      <DataTable
        columns={columns}
        data={list.rows}
        getRowId={(e) => e.id ?? ''}
        onRowClick={(e) => setSelected(e.endpoint_id ?? null)}
        showSearch={false}
        showColumnToggle={false}
        toolbarStart={
          <FilterSelect<string>
            label={t('attackSurface.originWeb.changes.kind', 'Change')}
            value={kind}
            options={Object.entries(EVENT_KINDS).map(([k, label]) => ({
              value: k,
              label: t(`attackSurface.web.event.${k}`, label),
            }))}
            onChange={(v) => {
              setKind(v ?? '')
              paging.reset()
            }}
          />
        }
        toolbarEnd={
          <ExportButton
            busy={exp.busy}
            onClick={() =>
              void exp.run(
                async () =>
                  eventsCsv(await fetchAllEvents(filters), [
                    t('attackSurface.web.col.when', 'When'),
                    t('attackSurface.web.col.change', 'Change'),
                    t('attackSurface.originWeb.csv.method', 'Method'),
                    t('attackSurface.originWeb.csv.path', 'Path'),
                    t('attackSurface.originWeb.csv.catalog', 'Catalog entry'),
                  ]),
                'web-changes'
              )
            }
          />
        }
        isLoading={list.isLoading && list.rows.length === 0}
        errorState={
          list.error && !list.isLoading ? (
            <ErrorState
              title={t('attackSurface.originWeb.errorTitle', 'web surface')}
              error={list.error}
              onRetry={() => list.mutate()}
            />
          ) : undefined
        }
        manualPagination
        rowCount={list.total}
        pagination={paging.pagination}
        onPaginationChange={paging.setPagination}
        pageSizeOptions={PAGE_SIZES}
        emptyMessage={t('attackSurface.web.noChanges', 'No changes')}
        emptyDescription={t(
          'attackSurface.web.noChangesHint',
          'New, gone and changed endpoints appear here after each crawl.'
        )}
      />
      <EndpointSheet endpointId={selected} onClose={() => setSelected(null)} />
    </>
  )
}

export function OriginWebSection(props: OriginWebSectionProps) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.AssetsRead)
  const [tab, setTab] = useState<SectionTab>('overview')
  if (!canRead) return null
  const labels: Record<SectionTab, string> = {
    overview: t('attackSurface.originWeb.tab.overview', 'Overview'),
    endpoints: t('attackSurface.originWeb.tab.endpoints', 'Endpoints'),
    parameters: t('attackSurface.originWeb.tab.parameters', 'Parameters'),
    changes: t('attackSurface.originWeb.tab.changes', 'Changes'),
  }
  return (
    <Card id="asset-web">
      <CardHeader>
        <CardTitle>{t('attackSurface.originWeb.title', 'Web')}</CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs value={tab} onValueChange={(v) => setTab(v as SectionTab)}>
          <TabsList>
            {SECTION_TABS.map((k) => (
              <TabsTrigger key={k} value={k}>
                {labels[k]}
              </TabsTrigger>
            ))}
          </TabsList>
          <TabsContent value="overview" className="pt-4">
            <OverviewTab {...props} onOpen={setTab} />
          </TabsContent>
          <TabsContent value="endpoints" className="pt-4">
            {tab === 'endpoints' && <EndpointsTab assetId={props.assetId} />}
          </TabsContent>
          <TabsContent value="parameters" className="pt-4">
            {tab === 'parameters' && <ParametersTab assetId={props.assetId} />}
          </TabsContent>
          <TabsContent value="changes" className="pt-4">
            {tab === 'changes' && <ChangesTab assetId={props.assetId} />}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}
