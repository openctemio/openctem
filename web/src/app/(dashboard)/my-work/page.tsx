'use client'

import { Suspense, useMemo } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from '@/components/link'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { ArrowRight } from 'lucide-react'
import { Main } from '@/components/layout'
import {
  PageHeader,
  PageStack,
  MetricStrip,
  DataTable,
  DataTableColumnHeader,
  type MetricStripItem,
} from '@/features/shared'
import { ErrorState } from '@/features/shared/components/error-state'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import type { FindingStatus } from '@/features/findings/types'
import { toDisplayText } from '@/lib/untrusted-text'
import { formatCount } from '@/lib/format-metric'
import { MY_WORK_METRIC_FILTERS, findingsDrillUrl } from '@/features/findings/lib/my-work-metrics'
import { slaStateClass } from '@/lib/sla-colors'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { MyTasksQueue, useMyTaskCount } from '@/features/remediation-hub/components/my-tasks-queue'
import { formatRelative } from '@/lib/format-date'
import { useFindingsApi } from '@/features/findings/api/use-findings-api'
import type { ApiFinding, FindingApiFilters } from '@/features/findings/api/finding-api.types'

/** The queue shows the top of the list; "View all" opens Findings filtered to me. */
const QUEUE_SIZE = 15

function findingName(f: ApiFinding): string | undefined {
  return f.title || f.rule_name || f.message || undefined
}

type MyWorkTab = 'findings' | 'tasks'

export default function MyWorkPage() {
  return (
    <Suspense>
      <MyWorkContent />
    </Suspense>
  )
}

function MyWorkContent() {
  const { t, locale } = useTranslation()
  const router = useRouter()
  const params = useSearchParams()
  const { hasPermission } = usePermissions()
  const canSeeTasks = hasPermission(Permission.RemediationRead)
  const tab: MyWorkTab = canSeeTasks && params.get('tab') === 'tasks' ? 'tasks' : 'findings'
  const taskCount = useMyTaskCount(canSeeTasks)
  const setTab = (next: string) => {
    router.replace(next === 'tasks' ? '/my-work?tab=tasks' : '/my-work', { scroll: false })
  }
  const enabled = tab === 'findings'
  const queueFilters: FindingApiFilters = {
    ...MY_WORK_METRIC_FILTERS.open,
    sort: 'priority_class,severity,-created_at',
    per_page: QUEUE_SIZE,
  }
  const {
    data: queue,
    error: queueError,
    isLoading,
    mutate: retryQueue,
  } = useFindingsApi(queueFilters, { enabled })
  const { data: critical, error: criticalError } = useFindingsApi(
    { ...MY_WORK_METRIC_FILTERS.critical, per_page: 1 },
    { enabled }
  )
  const { data: overdue, error: overdueError } = useFindingsApi(
    { ...MY_WORK_METRIC_FILTERS.overdue, per_page: 1 },
    { enabled }
  )

  const openTotal = queue?.total ?? 0
  const rows = useMemo(() => queue?.data ?? [], [queue])

  // A figure whose request is loading or failed shows a dash, never a 0.
  const figure = (total: number | undefined) => (total === undefined ? '—' : total)

  // Each metric opens Findings with the filter that counted it (this page is a
  // read-only queue; the full list and its filters live on Findings).
  const metrics: MetricStripItem[] = [
    {
      key: 'open',
      label: t('myWork.metrics.open'),
      description: t('myWork.description'),
      value: figure(queueError ? undefined : queue?.total),
      onClick: () => router.push(findingsDrillUrl(MY_WORK_METRIC_FILTERS.open)),
    },
    {
      key: 'critical',
      label: t('myWork.metrics.critical'),
      value: figure(criticalError ? undefined : critical?.total),
      tone: 'danger',
      onClick: () => router.push(findingsDrillUrl(MY_WORK_METRIC_FILTERS.critical)),
    },
    {
      key: 'overdue',
      label: t('myWork.metrics.overdue'),
      value: figure(overdueError ? undefined : overdue?.total),
      tone: 'danger',
      onClick: () => router.push(findingsDrillUrl(MY_WORK_METRIC_FILTERS.overdue)),
    },
  ]

  const columns = useMemo<ColumnDef<ApiFinding>[]>(
    () => [
      {
        accessorKey: 'priority_class',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.priority')} />
        ),
        cell: ({ row }) => (
          <PriorityClassBadge
            priorityClass={row.original.priority_class}
            assetId={row.original.asset?.id}
            showWord
          />
        ),
      },
      {
        accessorKey: 'title',
        meta: { primary: true },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.finding')} />
        ),
        cell: ({ row }) => {
          const f = row.original
          return (
            <div className="min-w-0 max-w-[520px]">
              <Link
                href={`/findings/${encodeURIComponent(f.id)}`}
                dir="auto"
                className="block truncate text-sm font-medium [unicode-bidi:isolate] hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                {toDisplayText(findingName(f), 500) || t('myWork.untitled')}
              </Link>
              {f.asset?.name && (
                <p className="truncate text-xs text-muted-foreground">
                  {toDisplayText(f.asset.name, 200)}
                </p>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'severity',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.severity')} />
        ),
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
      {
        accessorKey: 'status',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.status')} />
        ),
        cell: ({ row }) => <FindingStatusBadge status={row.original.status as FindingStatus} />,
      },
      {
        id: 'sla',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.sla')} />
        ),
        cell: ({ row }) => {
          const sla = (row.original.sla_status || '').toLowerCase()
          if (sla === 'overdue' || sla === 'exceeded') {
            return (
              <Badge variant="outline" className={slaStateClass(sla)}>
                {t('myWork.sla.overdue')}
              </Badge>
            )
          }
          if (sla === 'warning') {
            return (
              <Badge variant="outline" className={slaStateClass(sla)}>
                {t('myWork.sla.dueSoon')}
              </Badge>
            )
          }
          return <span className="text-sm text-muted-foreground">—</span>
        },
      },
      {
        accessorKey: 'created_at',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.created')} />
        ),
        cell: ({ row }) => (
          <span className="whitespace-nowrap text-sm text-muted-foreground">
            {formatRelative(row.original.created_at, '—', locale)}
          </span>
        ),
      },
    ],
    [t, locale]
  )

  const findingsPanel = (
    <PageStack>
      <MetricStrip loading={isLoading} items={metrics} />

      <div>
        {queueError ? (
          <ErrorState title={t('myWork.loadError')} onRetry={() => void retryQueue()} />
        ) : isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full" />
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : (
          <DataTable
            columns={columns}
            data={rows}
            showSearch={false}
            showColumnToggle={false}
            showPagination={false}
            pageSize={QUEUE_SIZE}
            getRowId={(f) => f.id}
            onRowClick={(f) => router.push(`/findings/${f.id}`)}
            toolbarStart={
              <span className="text-sm text-muted-foreground">
                {openTotal > rows.length
                  ? t('myWork.topOf', undefined, {
                      shown: rows.length,
                      total: formatCount(openTotal, locale),
                    })
                  : t('myWork.byPriority')}
              </span>
            }
            toolbarEnd={
              <Button variant="outline" size="sm" asChild>
                <Link href={findingsDrillUrl(MY_WORK_METRIC_FILTERS.open)}>
                  {t('myWork.viewAll')}
                  <ArrowRight className="ms-2 h-4 w-4" />
                </Link>
              </Button>
            }
            emptyMessage={t('myWork.emptyTitle')}
            emptyDescription={t('myWork.emptyDescription')}
          />
        )}
      </div>
    </PageStack>
  )

  return (
    <Main>
      <PageStack>
        <PageHeader title={t('myWork.title')} description={t('myWork.description')} />

        {canSeeTasks ? (
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList aria-label={t('myWork.tabs.label')}>
              <TabsTrigger value="findings">{t('myWork.tabs.findings')}</TabsTrigger>
              <TabsTrigger value="tasks">
                {t('myWork.tabs.tasks')}
                {taskCount ? <TabsCount value={taskCount} /> : null}
              </TabsTrigger>
            </TabsList>
            <TabsContent value="findings">{findingsPanel}</TabsContent>
            <TabsContent value="tasks">
              <MyTasksQueue />
            </TabsContent>
          </Tabs>
        ) : (
          findingsPanel
        )}
      </PageStack>
    </Main>
  )
}
