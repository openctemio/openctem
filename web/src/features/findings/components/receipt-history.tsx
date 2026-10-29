'use client'

/**
 * Import and run receipts (GET /api/v1/findings/imports): the list the
 * dashboard's intake figures open. The URL carries the same filters as the
 * figure (origin, tool, since), and the totals above the list are the API's
 * sums over every receipt the filter keeps, so they equal the figure that
 * was clicked. A reader without the organization view sees only their own
 * uploads; the API decides.
 */

import { useCallback, useMemo } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { type ColumnDef } from '@tanstack/react-table'
import { X } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable } from '@/features/shared/components/data-table/data-table'
import { DetailStat, DetailStatGrid } from '@/features/shared/components/detail-sheet'
import { ErrorState } from '@/features/shared/components/error-state'
import { PageHeader } from '@/features/shared/components/page-header'
import { PageStack } from '@/features/shared/components/page-stack'
import { TableSkeleton } from '@/components/list-page-parts'
import { formatAbsoluteTime, formatCount, formatRelativeTime } from '@/lib/format-metric'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { tCount } from '@/components/dashboard-kit/flow-parts'
import {
  isReceiptOrigin,
  useReceipts,
  type ReceiptListFilters,
  type ReceiptResponse,
} from '../api/receipts-api'

const PER_PAGE = 50

/** The words of a receipt's source kind (the receipt panels' keys). */
const KIND_KEY: Record<string, string> = {
  upload: 'findings.receipts.kindUpload',
  scan_run: 'findings.receipts.kindScanRun',
  command: 'findings.receipts.kindCommand',
  ci_run: 'findings.receipts.kindCiRun',
  connector: 'findings.receipts.kindConnector',
  sensor: 'findings.receipts.kindSensor',
}

/** The filters of the URL that the list accepts; anything else is ignored. */
export function receiptFiltersOf(params: URLSearchParams): ReceiptListFilters {
  const origin = params.get('origin')
  const tool = params.get('tool')
  const since = params.get('since')
  const page = Number(params.get('page') ?? '1')
  return {
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
  const filters = useMemo(() => receiptFiltersOf(new URLSearchParams(params.toString())), [params])
  const { data, error, isLoading, mutate } = useReceipts(filters)
  const n = useCallback((v: number | undefined) => formatCount(v ?? 0, locale), [locale])

  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params.toString())
    if (value == null) next.delete(key)
    else next.set(key, value)
    if (key !== 'page') next.delete('page')
    const qs = next.toString()
    router.replace(qs ? `${pathname}?${qs}` : pathname)
  }

  const kindLabel = useCallback(
    (kind: string) => {
      const key = KIND_KEY[kind]
      return key ? t(key, kind) : kind
    },
    [t]
  )
  const statusLabel = useCallback(
    (status: string) => t(`findings.receiptHistory.status.${status}`, status),
    [t]
  )

  const columns = useMemo<ColumnDef<ReceiptResponse>[]>(
    () => [
      {
        id: 'started',
        header: t('findings.receiptHistory.col.started', 'Started'),
        cell: ({ row }) => (
          <span title={formatAbsoluteTime(row.original.started_at, locale)}>
            {formatRelativeTime(row.original.started_at, locale)}
          </span>
        ),
      },
      {
        id: 'source',
        header: t('findings.receiptHistory.col.source', 'Source'),
        cell: ({ row }) => (
          <span className="block min-w-0">
            <span className="block truncate font-medium">
              {row.original.tool
                ? toDisplayText(row.original.tool, 80)
                : t('dashboardKit.flow.unnamedTool', 'Unnamed tool')}
            </span>
            <span className="block text-xs text-muted-foreground">
              {kindLabel(row.original.source?.kind ?? '')}
            </span>
          </span>
        ),
      },
      {
        id: 'status',
        header: t('findings.receiptHistory.col.status', 'Status'),
        cell: ({ row }) => (
          <span
            className={cn(
              'inline-flex rounded border px-1.5 py-0.5 text-xs',
              row.original.status === 'failed' && 'border-destructive text-destructive'
            )}
          >
            {statusLabel(row.original.status ?? '')}
          </span>
        ),
      },
      ...(
        [
          [
            'received',
            t('findings.receiptHistory.col.received', 'Received'),
            (r: ReceiptResponse) => r.received,
          ],
          [
            'created',
            t('findings.receiptHistory.col.new', 'New'),
            (r: ReceiptResponse) => r.counts?.created,
          ],
          [
            'updated',
            t('findings.receiptHistory.col.still', 'Still detected'),
            (r: ReceiptResponse) => r.counts?.updated,
          ],
          [
            'reactivated',
            t('findings.receiptHistory.col.reopened', 'Reopened'),
            (r: ReceiptResponse) => r.counts?.reactivated,
          ],
          [
            'closed',
            t('findings.receiptHistory.col.closed', 'Resolved'),
            (r: ReceiptResponse) => r.counts?.closed,
          ],
          [
            'suppressed',
            t('findings.receiptHistory.col.suppressed', 'Suppressed'),
            (r: ReceiptResponse) => r.counts?.suppressed,
          ],
          [
            'not_stored',
            t('findings.receiptHistory.col.notStored', 'Not stored'),
            (r: ReceiptResponse) => (r.counts?.skipped ?? 0) + (r.counts?.failed ?? 0),
          ],
        ] as const
      ).map(([id, header, value]): ColumnDef<ReceiptResponse> => ({
        id,
        header: () => <span className="block text-right">{header}</span>,
        cell: ({ row }) => (
          <span className="block text-right tabular-nums">{n(value(row.original))}</span>
        ),
      })),
    ],
    [t, locale, n, kindLabel, statusLabel]
  )

  const totals = data?.totals
  const chips: Array<{ key: string; label: string }> = []
  if (filters.origin)
    chips.push({
      key: 'origin',
      label: t(`dashboardKit.flow.origin.${filters.origin}`, filters.origin),
    })
  if (filters.tool)
    chips.push({
      key: 'tool',
      label:
        filters.tool === 'unknown'
          ? t('dashboardKit.flow.unnamedTool', 'Unnamed tool')
          : toDisplayText(filters.tool, 80),
    })
  if (filters.since)
    chips.push({
      key: 'since',
      label: t('findings.receiptHistory.since', 'Since {date}', {
        date: formatAbsoluteTime(filters.since, locale),
      }),
    })

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('findings.receiptHistory.title', 'Import and run receipts')}
          description={t(
            'findings.receiptHistory.description',
            "What each upload and run did to the organization's findings. The intake figures on the dashboard open this list with the same source and period."
          )}
        />
        {chips.length > 0 && (
          <ul
            className="flex flex-wrap gap-2"
            aria-label={t('findings.receiptHistory.filters', 'Filters')}
          >
            {chips.map((c) => (
              <li key={c.key}>
                <span className="inline-flex items-center gap-1 rounded-md border py-0.5 ps-2 pe-1 text-xs">
                  {c.label}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-5"
                    aria-label={t('findings.receiptHistory.clearFilter', 'Remove filter {name}', {
                      name: c.label,
                    })}
                    onClick={() => setParam(c.key, null)}
                  >
                    <X className="size-3" aria-hidden />
                  </Button>
                </span>
              </li>
            ))}
          </ul>
        )}
        {totals && (
          <section aria-labelledby="receipt-totals" className="rounded-lg border p-3">
            <h2 id="receipt-totals" className="mb-2 text-xs font-medium text-muted-foreground">
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
        {error ? (
          <ErrorState
            title={t('findings.receiptHistory.title', 'Import and run receipts')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : isLoading && !data ? (
          <TableSkeleton rows={6} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            showSearch={false}
            showColumnToggle={false}
            manualPagination
            pageCount={data?.total_pages ?? 1}
            rowCount={data?.total ?? 0}
            pagination={{ pageIndex: (filters.page ?? 1) - 1, pageSize: PER_PAGE }}
            pageSizeOptions={[PER_PAGE]}
            onPaginationChange={(p) =>
              setParam('page', p.pageIndex > 0 ? String(p.pageIndex + 1) : null)
            }
            getRowId={(r) => r.id ?? ''}
            emptyMessage={
              chips.length > 0
                ? t('findings.receiptHistory.empty', 'No receipts match these filters.')
                : t('findings.receiptHistory.emptyNone', 'No receipts yet.')
            }
            emptyDescription={t(
              'findings.receiptHistory.emptyHint',
              'Run a scan or import a report; each upload and run leaves a receipt here.'
            )}
          />
        )}
      </PageStack>
    </Main>
  )
}
