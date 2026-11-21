'use client'

/**
 * Imports (GET /api/v1/findings/imports): every upload and run receipt with
 * what it did to the organization's findings. The dashboard's intake figures
 * open it with the same filters as the figure (origin, tool, since), which
 * show as context chips under the toolbar; the totals above the list are the
 * API's sums over every receipt the filter keeps, so they equal the figure
 * that was clicked. A receipt opens in a side sheet built from the row (no
 * extra read). A reader without the organization view sees only their own
 * uploads; the API decides.
 */

import { useCallback, useMemo, useState } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { type ColumnDef } from '@tanstack/react-table'
import { FileInput, Upload } from 'lucide-react'
import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import {
  DataTable,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  FilterSelect,
  PageStack,
  ToolbarAction,
} from '@/features/shared'
import { DetailStat, DetailStatGrid } from '@/features/shared/components/detail-sheet'
import { PageHeader } from '@/features/shared/components/page-header'
import { EmptyState } from '@/features/shared/components/empty-state'
import { StatusChip } from '@/features/shared/components/status-chip'
import { MetaLine } from '@/features/shared/components/text-layout'
import {
  ContextFilterChips,
  type ContextFilterChip,
} from '@/features/shared/components/context-filter-chips'
import { formatAbsoluteTime, formatCount, formatRelativeTime } from '@/lib/format-metric'
import { toDisplayText } from '@/lib/untrusted-text'
import { tCount } from '@/components/dashboard-kit/flow-parts'
import { useOpenForm } from '@/hooks/use-open-form'
import { RetiredSourcesSection } from './source-retirement'
import { ReceiptClosing, ReceiptOutcomes, ReceiptSummary } from './receipt-summary'
import { ImportResultsDialog } from './import-results-dialog'
import {
  isReceiptOrigin,
  useReceipts,
  type ReceiptListFilters,
  type ReceiptResponse,
  type ReceiptSourceKind,
} from '../api/receipts-api'

const PER_PAGE = 50

/** The source kinds of a receipt, in the order the Source filter lists them. */
export const RECEIPT_SOURCE_KINDS = [
  'upload',
  'scan_run',
  'command',
  'ci_run',
  'connector',
  'sensor',
  'platform',
] as const satisfies readonly ReceiptSourceKind[]

/** The words of a receipt's source kind (the receipt panels' keys). */
const KIND_KEY: Record<ReceiptSourceKind, string> = {
  upload: 'findings.receipts.kindUpload',
  scan_run: 'findings.receipts.kindScanRun',
  command: 'findings.receipts.kindCommand',
  ci_run: 'findings.receipts.kindCiRun',
  connector: 'findings.receipts.kindConnector',
  sensor: 'findings.receipts.kindSensor',
  platform: 'findings.receipts.kindPlatform',
}

function isSourceKind(v: unknown): v is ReceiptSourceKind {
  return typeof v === 'string' && (RECEIPT_SOURCE_KINDS as readonly string[]).includes(v)
}

/** Table frame widths (px) under which a count column folds away; the source and status stay. */
export const RECEIPT_HIDE_BELOW = {
  started: 520,
  received: 600,
  created: 680,
  closed: 760,
  notStored: 840,
  updated: 1040,
  reactivated: 1120,
  suppressed: 1200,
} as const

/** The filters of the URL that the list accepts; anything else is ignored. */
export function receiptFiltersOf(params: URLSearchParams): ReceiptListFilters {
  const origin = params.get('origin')
  const tool = params.get('tool')
  const since = params.get('since')
  const kind = params.get('source_kind')
  const page = Number(params.get('page') ?? '1')
  return {
    sourceKind: isSourceKind(kind) ? kind : undefined,
    origin: isReceiptOrigin(origin) ? origin : undefined,
    tool: tool && tool.length <= 100 ? tool : undefined,
    since: since && !Number.isNaN(Date.parse(since)) ? since : undefined,
    page: Number.isInteger(page) && page > 1 ? page : undefined,
    perPage: PER_PAGE,
  }
}

export function ReceiptHistory() {
  const { t, locale } = useTranslation()
  const params = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()
  const { hasPermission } = usePermissions()
  const filters = useMemo(() => receiptFiltersOf(new URLSearchParams(params.toString())), [params])
  const { data, error, isLoading, mutate } = useReceipts(filters)
  const n = useCallback((v: number | undefined) => formatCount(v ?? 0, locale), [locale])
  const [openId, setOpenId] = useState<string | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  // The gate of POST /findings/imports (the API stays authoritative).
  const canImport =
    hasPermission('findings:write') &&
    hasPermission('assets:write') &&
    hasPermission('assets:import')
  const openImport = useCallback(() => setImportOpen(true), [])
  useOpenForm('import', canImport, openImport)

  const setParams = useCallback(
    (changes: Record<string, string | null>) => {
      const next = new URLSearchParams(params.toString())
      for (const [key, value] of Object.entries(changes)) {
        if (value == null) next.delete(key)
        else next.set(key, value)
      }
      if (!('page' in changes)) next.delete('page')
      const qs = next.toString()
      router.replace(qs ? `${pathname}?${qs}` : pathname)
    },
    [params, pathname, router]
  )

  const kindLabel = useCallback(
    (kind: string | undefined) => {
      const key = isSourceKind(kind) ? KIND_KEY[kind] : undefined
      return key ? t(key, kind) : (kind ?? '')
    },
    [t]
  )
  const toolLabel = useCallback(
    (r: ReceiptResponse) =>
      r.tool ? toDisplayText(r.tool, 80) : t('dashboardKit.flow.unnamedTool', 'Unnamed tool'),
    [t]
  )
  const statusChip = useCallback(
    (r: ReceiptResponse, className?: string) => (
      <StatusChip domain="ingestReceipt" value={r.status ?? ''} className={className} />
    ),
    []
  )

  const columns = useMemo<ColumnDef<ReceiptResponse>[]>(() => {
    const count = (
      id: string,
      label: string,
      value: (r: ReceiptResponse) => number | undefined,
      hideBelow: number
    ): ColumnDef<ReceiptResponse> => ({
      id,
      header: label,
      meta: { kind: 'number', label, hideBelow },
      cell: ({ row }) => <span className="tabular-nums">{n(value(row.original))}</span>,
    })
    return [
      {
        id: 'source',
        header: t('findings.receiptHistory.col.source', 'Source'),
        meta: { kind: 'name', label: t('findings.receiptHistory.col.source', 'Source') },
        cell: ({ row }) => (
          <span className="block min-w-0">
            <span className="block truncate font-medium" dir="auto">
              {toolLabel(row.original)}
            </span>
            <span className="text-muted-foreground block truncate text-xs">
              {kindLabel(row.original.source?.kind)}
              {row.original.released_from_quarantine
                ? `, ${t('findings.receipts.releasedFromQuarantine', 'Released from quarantine')}`
                : ''}
            </span>
          </span>
        ),
      },
      {
        id: 'status',
        header: t('findings.receiptHistory.col.status', 'Status'),
        meta: { kind: 'status', label: t('findings.receiptHistory.col.status', 'Status') },
        cell: ({ row }) => statusChip(row.original),
      },
      {
        id: 'started',
        header: t('findings.receiptHistory.col.started', 'Started'),
        meta: {
          kind: 'datetime-recent',
          label: t('findings.receiptHistory.col.started', 'Started'),
          hideBelow: RECEIPT_HIDE_BELOW.started,
        },
        cell: ({ row }) => (
          <span title={formatAbsoluteTime(row.original.started_at, locale)}>
            {formatRelativeTime(row.original.started_at, locale)}
          </span>
        ),
      },
      count(
        'received',
        t('findings.receiptHistory.col.received', 'Received'),
        (r) => r.received,
        RECEIPT_HIDE_BELOW.received
      ),
      count(
        'created',
        t('findings.receiptHistory.col.new', 'New'),
        (r) => r.counts?.created,
        RECEIPT_HIDE_BELOW.created
      ),
      count(
        'closed',
        t('findings.receiptHistory.col.closed', 'Resolved'),
        (r) => r.counts?.closed,
        RECEIPT_HIDE_BELOW.closed
      ),
      count(
        'not_stored',
        t('findings.receiptHistory.col.notStored', 'Not stored'),
        (r) => (r.counts?.skipped ?? 0) + (r.counts?.failed ?? 0),
        RECEIPT_HIDE_BELOW.notStored
      ),
      count(
        'updated',
        t('findings.receiptHistory.col.still', 'Still detected'),
        (r) => r.counts?.updated,
        RECEIPT_HIDE_BELOW.updated
      ),
      count(
        'reactivated',
        t('findings.receiptHistory.col.reopened', 'Reopened'),
        (r) => r.counts?.reactivated,
        RECEIPT_HIDE_BELOW.reactivated
      ),
      count(
        'suppressed',
        t('findings.receiptHistory.col.suppressed', 'Suppressed'),
        (r) => r.counts?.suppressed,
        RECEIPT_HIDE_BELOW.suppressed
      ),
    ]
  }, [t, locale, n, kindLabel, toolLabel, statusChip])

  // Filters a deep link set (the dashboard figures): removable chips under the toolbar.
  const chips: ContextFilterChip[] = []
  if (filters.origin)
    chips.push({
      param: 'origin',
      kind: t('findings.receiptHistory.chip.origin', 'Origin'),
      label: t(`dashboardKit.flow.origin.${filters.origin}`, filters.origin),
    })
  if (filters.tool)
    chips.push({
      param: 'tool',
      kind: t('findings.receiptHistory.chip.tool', 'Tool'),
      label:
        filters.tool === 'unknown'
          ? t('dashboardKit.flow.unnamedTool', 'Unnamed tool')
          : filters.tool,
    })
  if (filters.since)
    chips.push({
      param: 'since',
      kind: t('findings.receiptHistory.chip.since', 'Since'),
      label: formatAbsoluteTime(filters.since, locale),
    })
  const filtered = chips.length > 0 || !!filters.sourceKind

  const rows = useMemo(() => data?.data ?? [], [data])
  const openIndex = openId ? rows.findIndex((r) => r.id === openId) : -1
  const open = openIndex >= 0 ? rows[openIndex] : null
  const totals = data?.totals

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('findings.receiptHistory.title', 'Imports')}
          description={t(
            'findings.receiptHistory.description',
            "What each upload and run did to the organization's findings. The intake figures on the dashboard open this list with the same source and period."
          )}
        />
        <RetiredSourcesSection />
        {totals && totals.receipts > 0 && (
          <section aria-labelledby="receipt-totals" className="rounded-lg border p-3">
            <h2 id="receipt-totals" className="text-muted-foreground mb-2 text-xs font-medium">
              {tCount(
                t,
                'findings.receiptHistory.totals',
                'Totals of {count} receipts',
                'Totals of {count} receipt',
                totals.receipts,
                { count: n(totals.receipts) }
              )}
            </h2>
            <DetailStatGrid data-testid="receipt-totals">
              {(
                [
                  [
                    'received',
                    t('findings.receiptHistory.col.received', 'Received'),
                    totals.received,
                  ],
                  ['created', t('findings.receiptHistory.col.new', 'New'), totals.created],
                  [
                    'updated',
                    t('findings.receiptHistory.col.still', 'Still detected'),
                    totals.updated,
                  ],
                  [
                    'reactivated',
                    t('findings.receiptHistory.col.reopened', 'Reopened'),
                    totals.reactivated,
                  ],
                  ['closed', t('findings.receiptHistory.col.closed', 'Resolved'), totals.closed],
                  [
                    'suppressed',
                    t('findings.receiptHistory.col.suppressed', 'Suppressed'),
                    totals.suppressed,
                  ],
                  [
                    'not_stored',
                    t('findings.receiptHistory.col.notStored', 'Not stored'),
                    totals.skipped + totals.failed,
                  ],
                ] as const
              ).map(([k, label, v]) => (
                <DetailStat key={k} label={label} value={n(v)} />
              ))}
            </DetailStatGrid>
          </section>
        )}
        <DataTable
          columns={columns}
          data={rows}
          showSearch={false}
          caption={t('findings.receiptHistory.caption', 'Import and run receipts, newest first')}
          toolbarStart={
            <FilterSelect<ReceiptSourceKind>
              label={t('findings.receiptHistory.col.source', 'Source')}
              value={filters.sourceKind ?? ''}
              options={RECEIPT_SOURCE_KINDS.map((k) => ({ value: k, label: kindLabel(k) }))}
              onChange={(v) => setParams({ source_kind: v || null })}
            />
          }
          toolbarEnd={
            canImport && (
              <ToolbarAction
                icon={Upload}
                label={t('findings.receiptHistory.import', 'Import results')}
                onClick={openImport}
              />
            )
          }
          toolbarBelow={
            chips.length > 0 ? (
              <ContextFilterChips chips={chips} onRemove={(p) => setParams({ [p]: null })} />
            ) : undefined
          }
          isLoading={isLoading && !data}
          error={error && !data ? error : undefined}
          errorTitle={t('findings.receiptHistory.errorTitle', 'Import and run receipts')}
          onRetry={() => void mutate()}
          isFiltered={filtered}
          onClearFilters={() =>
            setParams({ origin: null, tool: null, since: null, source_kind: null })
          }
          emptyState={{
            nothingYet: (
              <EmptyState
                icon={FileInput}
                title={t('findings.receiptHistory.emptyNone', 'No receipts yet.')}
                description={t(
                  'findings.receiptHistory.emptyHint',
                  'Run a scan or import a report; each upload and run leaves a receipt here.'
                )}
                card
              />
            ),
            noMatch: {
              title: t('findings.receiptHistory.empty', 'No receipts match these filters.'),
              hint: t(
                'findings.receiptHistory.emptyMatchHint',
                'Remove a filter to see more receipts.'
              ),
            },
          }}
          manualPagination
          pageCount={data?.total_pages ?? 1}
          rowCount={data?.total ?? 0}
          pagination={{ pageIndex: (filters.page ?? 1) - 1, pageSize: PER_PAGE }}
          pageSizeOptions={[PER_PAGE]}
          onPaginationChange={(p) =>
            setParams({ page: p.pageIndex > 0 ? String(p.pageIndex + 1) : null })
          }
          paginationNoun={t('findings.receiptHistory.noun', 'receipts')}
          getRowId={(r) => r.id ?? ''}
          onRowClick={(r) => setOpenId(r.id ?? null)}
          mobileRow={(r) => (
            <div data-slot="receipt-card" className="flex min-w-0 flex-col gap-1 px-3 py-3">
              <div className="flex min-w-0 items-center justify-between gap-3">
                <span className="min-w-0 truncate font-medium" dir="auto">
                  {toolLabel(r)}
                </span>
                {statusChip(r, 'shrink-0')}
              </div>
              <MetaLine
                oneLine
                items={[
                  kindLabel(r.source?.kind),
                  <span key="when" title={formatAbsoluteTime(r.started_at, locale)}>
                    {formatRelativeTime(r.started_at, locale)}
                  </span>,
                ]}
              />
              <MetaLine
                className="tabular-nums"
                items={[
                  t('findings.receiptHistory.card.received', '{count} received', {
                    count: n(r.received),
                  }),
                  t('findings.receiptHistory.card.new', '{count} new', {
                    count: n(r.counts?.created),
                  }),
                  t('findings.receiptHistory.card.resolved', '{count} resolved', {
                    count: n(r.counts?.closed),
                  }),
                ]}
              />
            </div>
          )}
        />
      </PageStack>

      <DetailSheet
        open={!!open}
        onOpenChange={(o) => !o && setOpenId(null)}
        header={
          open ? (
            <DetailHeader
              title={<span dir="auto">{toolLabel(open)}</span>}
              badges={statusChip(open)}
              meta={[
                kindLabel(open.source?.kind),
                t('findings.receiptHistory.startedAt', 'Started {when}', {
                  when: formatAbsoluteTime(open.started_at, locale),
                }),
                t('findings.receiptHistory.position', 'Receipt {n} of {total}', {
                  n: n(openIndex + 1),
                  total: n(rows.length),
                }),
              ]}
              onClose={() => setOpenId(null)}
            />
          ) : null
        }
      >
        {open && (
          <DetailSections>
            <DetailSection title={t('findings.receiptHistory.didTitle', 'What this run did')}>
              <ReceiptSummary receipt={open} />
            </DetailSection>
            {(Object.values(open.outcomes ?? {}).some((v) => v > 0) ||
              !!open.closing?.considered) && (
              <DetailSection title={t('findings.receiptHistory.otherTitle', 'Other findings')}>
                <ReceiptOutcomes outcomes={open.outcomes} />
                <ReceiptClosing closing={open.closing} />
              </DetailSection>
            )}
          </DetailSections>
        )}
      </DetailSheet>

      <ImportResultsDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        onImported={() => void mutate()}
      />
    </Main>
  )
}
