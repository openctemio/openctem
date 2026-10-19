'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { CheckCircle2, Timer } from 'lucide-react'

import Link from '@/components/link'
import { Main } from '@/components/layout'
import {
  PageHeader,
  MetricStrip,
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  SeverityBadge,
  type MetricStripItem,
} from '@/features/shared'
import { ErrorState } from '@/features/shared/components/error-state'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
import { formatRelative } from '@/lib/format-date'
import { SEVERITY_DOT_COLORS, SEVERITY_ORDER, type SeverityLevel } from '@/lib/severity-colors'

import { useFindingsApi } from '@/features/findings/api/use-findings-api'
import type { ApiFinding } from '@/features/findings/api/finding-api.types'
import { useSlaCompliance } from '@/features/sla/api/use-sla-compliance'
import {
  AGING_BUCKET_KEYS,
  PAST_DUE_STATUSES,
  daysPastDue,
  findingsHref,
  tileFilter,
  type ComplianceTile,
} from '@/features/sla/lib/compliance'

const PAGE_SIZES = [10, 20, 50]

export default function SlaCompliancePage() {
  const { t } = useTranslation()
  const router = useRouter()
  const sla = useSlaCompliance()
  const { pagination, setPagination } = useListParams({
    pageSizes: PAGE_SIZES,
    defaultPageSize: 20,
  })

  // The breached list is a server page over the same filter as the Past due tile.
  const list = useFindingsApi(
    {
      state: 'open',
      sla_statuses: PAST_DUE_STATUSES,
      sort: 'sla_deadline',
      page: pagination.pageIndex + 1,
      per_page: pagination.pageSize,
    },
    { onError: () => undefined }
  )

  const pastDueTotal = sla.tiles.pastDue.data?.total ?? 0
  const failed = Boolean(sla.error || list.error)

  const tileText: Record<ComplianceTile, { label: string; hint: string }> = {
    pastDue: {
      label: t('sla.tile.pastDue', 'Past due'),
      hint: t('sla.tile.pastDueHint', 'Past the SLA deadline'),
    },
    dueSoon: {
      label: t('sla.tile.dueSoon', 'Due soon'),
      hint: t('sla.tile.dueSoonHint', 'Close to the SLA deadline'),
    },
    onTrack: {
      label: t('sla.tile.onTrack', 'On track'),
      hint: t('sla.tile.onTrackHint', 'Within the SLA'),
    },
    open: {
      label: t('sla.tile.open', 'Open findings'),
      hint: t('sla.tile.openHint', 'Everything open in your scope'),
    },
  }

  const items: MetricStripItem[] = (['pastDue', 'dueSoon', 'onTrack', 'open'] as const).map(
    (tile) => {
      const q = sla.tiles[tile]
      return {
        key: tile,
        label: tileText[tile].label,
        // A failed read is "—", never a 0 that looks like good news.
        value: q.data ? q.data.total : '—',
        hint: tileText[tile].hint,
        tone: tile === 'pastDue' ? 'danger' : tile === 'dueSoon' ? 'warning' : 'default',
        onClick: () => router.push(findingsHref(tileFilter(tile))),
      }
    }
  )

  const breachBySeverity = useMemo(
    () =>
      SEVERITY_ORDER.map((sev) => ({ sev, count: sla.bySeverity?.[sev] ?? 0 })).filter(
        (r) => r.count > 0
      ),
    [sla.bySeverity]
  )

  const agingLabel: Record<(typeof AGING_BUCKET_KEYS)[number], string> = {
    upTo7: t('sla.aging.upTo7', 'Up to 7 days'),
    d8to30: t('sla.aging.d8to30', '8-30 days'),
    d31to90: t('sla.aging.d31to90', '31-90 days'),
    over90: t('sla.aging.over90', 'Over 90 days'),
  }

  const columns = useMemo<ColumnDef<ApiFinding>[]>(
    () => [
      {
        accessorKey: 'title',
        enableSorting: false,
        header: () => t('sla.col.finding', 'Finding'),
        cell: ({ row }) => (
          <span className="line-clamp-1 font-medium">
            {row.original.title || row.original.message}
          </span>
        ),
      },
      {
        accessorKey: 'severity',
        enableSorting: false,
        header: () => t('sla.col.severity', 'Severity'),
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
      {
        id: 'asset',
        enableSorting: false,
        header: () => t('sla.col.asset', 'Asset'),
        cell: ({ row }) => (
          <span className="line-clamp-1 text-sm text-muted-foreground">
            {row.original.asset?.name || row.original.asset_id}
          </span>
        ),
      },
      {
        id: 'due',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('sla.col.pastDueBy', 'Past due by')} />
        ),
        cell: ({ row }) => {
          const days = daysPastDue(row.original.sla_deadline)
          return (
            <span className="text-sm tabular-nums text-destructive">
              {days < 1
                ? t('sla.underDay', 'Under a day')
                : t('sla.days', '{n, plural, one {# day} other {# days}}', { n: days })}
            </span>
          )
        },
      },
      {
        id: 'detected',
        enableSorting: false,
        header: () => t('sla.col.detected', 'Detected'),
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatRelative(row.original.first_detected_at)}
          </span>
        ),
      },
    ],
    [t]
  )

  return (
    <Main>
      <PageHeader
        title={t('sla.title', 'SLA compliance')}
        description={t(
          'sla.description',
          'Open findings tracked against their remediation deadlines.'
        )}
      />

      {failed ? (
        <div className="mt-5">
          <ErrorState
            title={t('sla.loadError', 'SLA compliance')}
            error={sla.error ?? list.error}
            onRetry={() => {
              sla.retry()
              void list.mutate()
            }}
          />
        </div>
      ) : null}

      <MetricStrip className="mt-5" loading={sla.isLoading} items={items} />

      <section className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{t('sla.severity.title', 'Past due by severity')}</CardTitle>
            <CardDescription>
              {t('sla.severity.description', 'Open findings past their SLA deadline.')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {sla.isLoading ? (
              <Skeleton className="h-24 w-full" />
            ) : sla.error ? (
              <p className="text-sm text-muted-foreground">—</p>
            ) : breachBySeverity.length === 0 ? (
              <EmptyState
                card={false}
                className="py-6"
                icon={CheckCircle2}
                title={t('sla.severity.empty', 'Nothing is past due')}
              />
            ) : (
              <div className="space-y-3">
                {breachBySeverity.map(({ sev, count }) => (
                  <Link
                    key={sev}
                    href={findingsHref(tileFilter('pastDue'), { severity: sev })}
                    className="flex items-center justify-between rounded-sm hover:underline"
                  >
                    <span className="flex items-center gap-2">
                      <span
                        className={cn(
                          'h-2.5 w-2.5 rounded-full',
                          SEVERITY_DOT_COLORS[sev as SeverityLevel]
                        )}
                      />
                      <span className="text-sm">{t(`severity.${sev}`, sev)}</span>
                    </span>
                    <span className="text-sm font-medium tabular-nums">{count}</span>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t('sla.aging.title', 'How long past due')}</CardTitle>
            <CardDescription>
              {t('sla.aging.description', 'Past due findings by time since their deadline.')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {sla.isLoading ? (
              <Skeleton className="h-24 w-full" />
            ) : (
              <div className="space-y-3">
                {AGING_BUCKET_KEYS.map((key) => (
                  <div key={key} className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">{agingLabel[key]}</span>
                    <span className="text-sm font-medium tabular-nums">
                      {sla.aging[key].data ? sla.aging[key].data.total : '—'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      <section className="mt-5 space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold">{t('sla.list.title', 'Past due findings')}</h2>
            <p className="text-sm text-muted-foreground">
              {t(
                'sla.list.description',
                '{n, plural, one {# finding} other {# findings}} past the SLA deadline, oldest deadline first.',
                { n: list.data?.total ?? pastDueTotal }
              )}
            </p>
          </div>
          <Link
            href={findingsHref(tileFilter('pastDue'))}
            className="text-sm font-medium text-primary hover:underline"
          >
            {t('sla.list.openInFindings', 'Open in Findings')}
          </Link>
        </div>
        {list.isLoading && !list.data ? (
          <Skeleton className="h-64 w-full" />
        ) : list.error ? null : (list.data?.total ?? 0) === 0 ? (
          <EmptyState
            icon={Timer}
            title={t('sla.list.emptyTitle', 'Nothing is past due')}
            description={t(
              'sla.list.emptyDescription',
              'No open finding in your scope is past its remediation deadline.'
            )}
          />
        ) : (
          <DataTable
            columns={columns}
            data={list.data?.data ?? []}
            getRowId={(f) => f.id}
            showSearch={false}
            showColumnToggle={false}
            manualPagination
            rowCount={list.data?.total ?? 0}
            pagination={pagination}
            onPaginationChange={setPagination}
            pageSizeOptions={PAGE_SIZES}
            onRowClick={(row) => router.push(`/findings/${row.id}`)}
          />
        )}
      </section>
    </Main>
  )
}
