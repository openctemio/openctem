'use client'

/**
 * Imports (GET /api/v1/findings/imports): every upload and run receipt with
 * what it did to the organization's findings. The dashboard's intake figures
 * open it with the same filters as the figure (origin, tool, since), which
 * show as context chips in the toolbar; the totals under the list are the
 * API's sums over every receipt the filter keeps, so they equal the figure
 * that was clicked. Each row says in words what the receipt changed ("12
 * new, 3 resolved"); a status shows only when it needs a look (failed, partly
 * stored, still running). The runs of one tool that received no findings at
 * all (asset discovery) fold into one row naming how many runs it holds
 * (lib/import-rows.ts). A receipt, or a folded row with every run in it,
 * opens in a side sheet built from the rows (no extra read). A reader without the organization view sees only their own
 * uploads; the API decides.
 */

import { useCallback, useMemo, useState } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { type ColumnDef } from '@tanstack/react-table'
import { ChevronRight, FileInput, Upload } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { useBootstrapModules } from '@/context/bootstrap-provider'
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
import { cn } from '@/lib/utils'
import {
  foldNoFindingRuns,
  importChange,
  receiptIssue,
  sumChanges,
  type ImportChange,
  type ImportRow,
} from '../lib/import-rows'
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

/** Table frame widths (px) under which a column folds away; the source and the change stay. */
export const RECEIPT_HIDE_BELOW = {
  started: 520,
  received: 640,
  created: 720,
  closed: 800,
  notStored: 880,
  updated: 1040,
  reactivated: 1120,
  suppressed: 1200,
} as const

/**
 * The per-count columns start hidden: the "What changed" words say the same
 * thing; Display > Columns turns any of them on.
 */
const COUNT_COLUMNS_HIDDEN = {
  created: false,
  closed: false,
  not_stored: false,
  updated: false,
  reactivated: false,
  suppressed: false,
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

type Translate = ReturnType<typeof useTranslation>['t']

/**
 * What a receipt (or the runs of a folded row) changed, in plain words:
 * "12 new, 3 resolved, 1 reopened". `quiet` marks words that need no look
 * (nothing changed, or nothing was received).
 */
export function changeWords(
  t: Translate,
  n: (v: number) => string,
  c: ImportChange,
  opts: { runs?: number; running?: boolean } = {}
): { text: string; quiet: boolean } {
  const parts: string[] = []
  if (c.created > 0)
    parts.push(t('findings.receiptHistory.change.new', '{count} new', { count: n(c.created) }))
  if (c.closed > 0)
    parts.push(
      t('findings.receiptHistory.change.resolved', '{count} resolved', { count: n(c.closed) })
    )
  if (c.reactivated > 0)
    parts.push(
      t('findings.receiptHistory.change.reopened', '{count} reopened', {
        count: n(c.reactivated),
      })
    )
  if (c.suppressed > 0)
    parts.push(
      t('findings.receiptHistory.change.suppressed', '{count} closed by a rule', {
        count: n(c.suppressed),
      })
    )
  const changed = parts.length > 0
  if (c.notStored > 0)
    parts.push(
      t('findings.receiptHistory.change.notStored', '{count} not stored', {
        count: n(c.notStored),
      })
    )
  if (opts.runs && opts.runs > 1) {
    parts.unshift(
      t(
        'findings.receiptHistory.change.runsNoFindings',
        '{count, plural, one {# run} other {# runs}}, no findings',
        { count: opts.runs }
      )
    )
  } else if (!changed && c.updated > 0) {
    parts.unshift(
      t('findings.receiptHistory.change.stillOnly', 'No change, {count} still detected', {
        count: n(c.updated),
      })
    )
  } else if (!changed && c.received === 0 && c.notStored === 0) {
    parts.unshift(
      opts.running
        ? t('findings.receipts.noFindingsYet', 'No findings yet')
        : t('findings.receiptHistory.change.noFindings', 'No findings')
    )
  } else if (!changed && c.notStored === 0) {
    parts.unshift(t('findings.receiptHistory.change.none', 'No change'))
  }
  if (!changed && c.assets > 0)
    parts.push(
      t(
        'findings.receiptHistory.change.assets',
        '{count, plural, one {# asset found} other {# assets found}}',
        { count: c.assets }
      )
    )
  return { text: parts.join(', '), quiet: !changed && c.notStored === 0 }
}

export function ReceiptHistory() {
  const { t, locale } = useTranslation()
  const params = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()
  const { hasPermission } = usePermissions()
  const { hasModule } = useBootstrapModules()
  const filters = useMemo(() => receiptFiltersOf(new URLSearchParams(params.toString())), [params])
  const { data, error, isLoading, mutate } = useReceipts(filters)
  const n = useCallback((v: number | undefined) => formatCount(v ?? 0, locale), [locale])
  const [openId, setOpenId] = useState<string | null>(null)
  // A run opened from a folded row offers the way back to that row.
  const [backTo, setBackTo] = useState<string | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  // The gate of POST /findings/imports (the API stays authoritative).
  const canImport =
    hasPermission('findings:write') &&
    hasPermission('assets:write') &&
    hasPermission('assets:import')
  // Where a run's effect can be followed; those routes check again.
  const canOpenRuns = hasPermission('scans:read')
  const canOpenAssetChanges = hasPermission('assets:read') && hasModule('attack_surface')
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
  /** The status chip, only when the status needs a look (never "Completed"). */
  const issueChip = useCallback((r: ReceiptResponse, className?: string) => {
    const issue = receiptIssue(r)
    return issue ? <StatusChip domain="ingestReceipt" value={issue} className={className} /> : null
  }, [])
  const rowChange = useCallback(
    (row: ImportRow) =>
      changeWords(t, n, row.runs ? sumChanges(row.runs) : importChange(row.receipt), {
        runs: row.runs?.length,
        running: row.receipt.status === 'queued' || row.receipt.status === 'processing',
      }),
    [t, n]
  )
  const changeCell = useCallback(
    (row: ImportRow) => {
      const { text, quiet } = rowChange(row)
      return (
        <span className="flex min-w-0 items-center gap-2" data-slot="receipt-change">
          {issueChip(row.receipt, 'shrink-0')}
          <span
            data-cut-tooltip
            title={text}
            className={cn('min-w-0 truncate tabular-nums', quiet && 'text-muted-foreground')}
          >
            {text}
          </span>
        </span>
      )
    },
    [rowChange, issueChip]
  )

  const columns = useMemo<ColumnDef<ImportRow>[]>(() => {
    const count = (
      id: string,
      label: string,
      value: (c: ImportChange) => number,
      hideBelow: number
    ): ColumnDef<ImportRow> => ({
      id,
      header: label,
      meta: { kind: 'number', label, hideBelow },
      cell: ({ row }) => {
        const o = row.original
        return (
          <span className="tabular-nums">
            {n(value(o.runs ? sumChanges(o.runs) : importChange(o.receipt)))}
          </span>
        )
      },
    })
    return [
      {
        id: 'source',
        header: t('findings.receiptHistory.col.source', 'Source'),
        meta: { kind: 'name', label: t('findings.receiptHistory.col.source', 'Source') },
        cell: ({ row }) => (
          <span className="block min-w-0">
            <span className="block truncate font-medium" dir="auto">
              {toolLabel(row.original.receipt)}
            </span>
            <span className="text-muted-foreground block truncate text-xs">
              {kindLabel(row.original.receipt.source?.kind)}
              {row.original.receipt.released_from_quarantine
                ? `, ${t('findings.receipts.releasedFromQuarantine', 'Released from quarantine')}`
                : ''}
            </span>
          </span>
        ),
      },
      {
        id: 'change',
        header: t('findings.receiptHistory.col.change', 'What changed'),
        meta: {
          kind: 'text',
          label: t('findings.receiptHistory.col.change', 'What changed'),
          // Narrows before the table scrolls sideways and grows into spare
          // width; a longer summary ends in an ellipsis (whole in its title).
          width: 320,
          minWidth: 200,
          maxWidth: 560,
        },
        cell: ({ row }) => changeCell(row.original),
      },
      count(
        'received',
        t('findings.receiptHistory.col.received', 'Received'),
        (c) => c.received,
        RECEIPT_HIDE_BELOW.received
      ),
      count(
        'created',
        t('findings.receiptHistory.col.new', 'New'),
        (c) => c.created,
        RECEIPT_HIDE_BELOW.created
      ),
      count(
        'closed',
        t('findings.receiptHistory.col.closed', 'Resolved'),
        (c) => c.closed,
        RECEIPT_HIDE_BELOW.closed
      ),
      count(
        'not_stored',
        t('findings.receiptHistory.col.notStored', 'Not stored'),
        (c) => c.notStored,
        RECEIPT_HIDE_BELOW.notStored
      ),
      count(
        'updated',
        t('findings.receiptHistory.col.still', 'Still detected'),
        (c) => c.updated,
        RECEIPT_HIDE_BELOW.updated
      ),
      count(
        'reactivated',
        t('findings.receiptHistory.col.reopened', 'Reopened'),
        (c) => c.reactivated,
        RECEIPT_HIDE_BELOW.reactivated
      ),
      count(
        'suppressed',
        t('findings.receiptHistory.col.suppressed', 'Suppressed'),
        (c) => c.suppressed,
        RECEIPT_HIDE_BELOW.suppressed
      ),
      {
        id: 'started',
        header: t('findings.receiptHistory.col.started', 'Started'),
        meta: {
          kind: 'datetime-recent',
          label: t('findings.receiptHistory.col.started', 'Started'),
          hideBelow: RECEIPT_HIDE_BELOW.started,
        },
        cell: ({ row }) => (
          <span title={formatAbsoluteTime(row.original.receipt.started_at, locale)}>
            {formatRelativeTime(row.original.receipt.started_at, locale)}
          </span>
        ),
      },
    ]
  }, [t, locale, n, kindLabel, toolLabel, changeCell])

  // Filters a deep link set (the dashboard figures): removable chips in the toolbar.
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

  const receipts = useMemo(() => data?.data ?? [], [data])
  const rows = useMemo(() => foldNoFindingRuns(receipts), [receipts])
  const openGroup = openId ? (rows.find((r) => r.id === openId && r.runs) ?? null) : null
  const openRuns = openGroup?.runs ?? null
  const openIndex = openId && !openGroup ? receipts.findIndex((r) => r.id === openId) : -1
  const open = openIndex >= 0 ? receipts[openIndex] : null
  const openChange = open ? rowChange({ id: open.id ?? '', receipt: open }) : null
  const closeSheet = useCallback(() => {
    setOpenId(null)
    setBackTo(null)
  }, [])
  const totals = data?.totals

  /** The query of the asset changes over the time of some runs, when they found assets and the reader may look. */
  const assetChangesQuery = useCallback(
    (runs: readonly ReceiptResponse[]) => {
      if (!canOpenAssetChanges || sumChanges(runs).assets === 0) return null
      const ms = runs
        .flatMap((r) => [r.started_at, r.finished_at ?? r.updated_at])
        .map((v) => (v ? Date.parse(v) : NaN))
        .filter((v) => !Number.isNaN(v))
      if (ms.length === 0) return null
      // A run's asset changes are written up to its end: one minute of slack.
      const q = new URLSearchParams({
        from: new Date(Math.min(...ms)).toISOString(),
        to: new Date(Math.max(...ms) + 60_000).toISOString(),
      })
      return q.toString()
    },
    [canOpenAssetChanges]
  )
  const assetsWords = (count: number) =>
    t(
      'findings.receiptHistory.change.assets',
      '{count, plural, one {# asset found} other {# assets found}}',
      { count }
    )
  // `query` is built from two ISO times only; the path is fixed.
  const assetChangesLink = (query: string) => (
    <Link href={`/attack-surface/changes?${query}`} className="text-primary hover:underline">
      {t('findings.receiptHistory.assetChanges', 'See the asset changes')}
    </Link>
  )

  const followLinks = (r: ReceiptResponse) => {
    const assets = assetChangesQuery([r])
    const run = canOpenRuns && r.source?.kind === 'scan_run' && r.source.ref ? r.source.ref : null
    if (!assets && !run) return null
    return (
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
        {run && (
          <Link
            href={`/scans/runs?run=${encodeURIComponent(run)}`}
            className="text-primary hover:underline"
          >
            {t('findings.receiptHistory.openRun', 'Open the run')}
          </Link>
        )}
        {assets && assetChangesLink(assets)}
      </div>
    )
  }

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
          <section
            aria-labelledby="receipt-totals"
            // The list comes first and the totals follow it at every width
            // (above the list they were a row of their own before the data).
            className="order-last rounded-lg border p-3"
          >
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
          initialColumnVisibility={COUNT_COLUMNS_HIDDEN}
          caption={t('findings.receiptHistory.caption', 'Import and run receipts, newest first')}
          toolbarStart={
            <>
              <FilterSelect<ReceiptSourceKind>
                label={t('findings.receiptHistory.col.source', 'Source')}
                value={filters.sourceKind ?? ''}
                options={RECEIPT_SOURCE_KINDS.map((k) => ({ value: k, label: kindLabel(k) }))}
                onChange={(v) => setParams({ source_kind: v || null })}
              />
              {chips.length > 0 && (
                <ContextFilterChips chips={chips} onRemove={(p) => setParams({ [p]: null })} />
              )}
            </>
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
          getRowId={(r) => r.id}
          onRowClick={(r) => {
            setBackTo(null)
            setOpenId(r.id || null)
          }}
          mobileRow={(row) => {
            const { text, quiet } = rowChange(row)
            const r = row.receipt
            return (
              <div data-slot="receipt-card" className="flex min-w-0 flex-col gap-1 px-3 py-3">
                {/* The source and when at the ends of the first line, then
                    what changed (the card's main line, with a status only
                    when it needs a look), then the kind of source. */}
                <div className="flex min-w-0 items-baseline justify-between gap-3">
                  <span
                    data-cut-tooltip
                    title={toolLabel(r)}
                    className="min-w-0 truncate font-medium"
                    dir="auto"
                  >
                    {toolLabel(r)}
                  </span>
                  <span
                    className="text-muted-foreground shrink-0 text-xs"
                    title={formatAbsoluteTime(r.started_at, locale)}
                  >
                    {formatRelativeTime(r.started_at, locale)}
                  </span>
                </div>
                <div data-slot="receipt-change" className="flex min-w-0 items-center gap-2">
                  {issueChip(r, 'shrink-0')}
                  <p
                    className={cn('min-w-0 text-sm tabular-nums', quiet && 'text-muted-foreground')}
                  >
                    {text}
                  </p>
                </div>
                <MetaLine
                  oneLine
                  items={[
                    kindLabel(r.source?.kind),
                    r.released_from_quarantine
                      ? t('findings.receipts.releasedFromQuarantine', 'Released from quarantine')
                      : null,
                  ]}
                />
              </div>
            )
          }}
        />
      </PageStack>

      <DetailSheet
        open={!!open || !!openRuns}
        onOpenChange={(o) => !o && closeSheet()}
        header={
          openGroup && openRuns ? (
            <DetailHeader
              title={<span dir="auto">{toolLabel(openGroup.receipt)}</span>}
              meta={[
                kindLabel(openGroup.receipt.source?.kind),
                t(
                  'findings.receiptHistory.change.runsNoFindings',
                  '{count, plural, one {# run} other {# runs}}, no findings',
                  { count: openRuns.length }
                ),
                t('findings.receiptHistory.latestAt', 'Latest {when}', {
                  when: formatAbsoluteTime(openGroup.receipt.started_at, locale),
                }),
              ]}
              onClose={closeSheet}
            />
          ) : open ? (
            <DetailHeader
              title={<span dir="auto">{toolLabel(open)}</span>}
              badges={issueChip(open) ?? undefined}
              meta={[
                kindLabel(open.source?.kind),
                t('findings.receiptHistory.startedAt', 'Started {when}', {
                  when: formatAbsoluteTime(open.started_at, locale),
                }),
                t('findings.receiptHistory.position', 'Receipt {n} of {total}', {
                  n: n(openIndex + 1),
                  total: n(receipts.length),
                }),
              ]}
              onClose={closeSheet}
            />
          ) : null
        }
      >
        {openGroup && openRuns && (
          <DetailSections>
            <DetailSection title={t('findings.receiptHistory.groupTitle', 'What these runs did')}>
              <p className="text-sm">
                {t(
                  'findings.receiptHistory.groupText',
                  'None of these runs received findings, so they changed no finding. The list keeps them in one row so the runs that did change findings stand out.'
                )}
              </p>
              {sumChanges(openRuns).assets > 0 && (
                <p className="text-sm tabular-nums">
                  {assetsWords(sumChanges(openRuns).assets)}
                  {assetChangesQuery(openRuns) && (
                    <>
                      {', '}
                      {assetChangesLink(assetChangesQuery(openRuns) ?? '')}
                    </>
                  )}
                </p>
              )}
            </DetailSection>
            <DetailSection
              title={t('findings.receiptHistory.runsTitle', 'Runs')}
              count={openRuns.length}
            >
              <ul className="divide-y rounded-md border" data-testid="receipt-group-runs">
                {openRuns.map((r) => (
                  <li key={r.id}>
                    <button
                      type="button"
                      className="hover:bg-muted/50 flex min-h-11 w-full min-w-0 items-center gap-3 px-3 py-2 text-start text-sm"
                      onClick={() => {
                        setBackTo(openGroup.id)
                        setOpenId(r.id ?? null)
                      }}
                    >
                      <span className="min-w-0 flex-1 truncate">
                        {formatAbsoluteTime(r.started_at, locale)}
                      </span>
                      <span className="text-muted-foreground shrink-0 tabular-nums">
                        {assetsWords(importChange(r).assets)}
                      </span>
                      <ChevronRight
                        aria-hidden
                        className="text-muted-foreground size-4 shrink-0 rtl:rotate-180"
                      />
                    </button>
                  </li>
                ))}
              </ul>
            </DetailSection>
          </DetailSections>
        )}
        {open && openChange && (
          <DetailSections>
            {backTo && (
              <button
                type="button"
                className="text-primary self-start text-sm hover:underline"
                onClick={() => {
                  setOpenId(backTo)
                  setBackTo(null)
                }}
              >
                {t('findings.receiptHistory.backToRuns', 'Back to the runs with no findings')}
              </button>
            )}
            <DetailSection title={t('findings.receiptHistory.didTitle', 'What this run did')}>
              <p
                data-testid="receipt-change-words"
                className={cn('text-sm tabular-nums', openChange.quiet && 'text-muted-foreground')}
              >
                {openChange.text}
              </p>
              <ReceiptSummary receipt={open} />
              {followLinks(open)}
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
