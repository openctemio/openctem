'use client'

import { findingStatusesInCategory } from '@/features/findings/types/finding.types'
import { Suspense, useMemo } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from '@/components/link'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { ArrowRight } from 'lucide-react'
import { Main } from '@/components/layout'
import {
  PageHeader,
  MetricStrip,
  DataTable,
  DataTableColumnHeader,
  type MetricStripItem,
} from '@/features/shared'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { MyTasksQueue, useMyTaskCount } from '@/features/remediation-hub/components/my-tasks-queue'
import { formatRelative } from '@/lib/format-date'
import { useFindingsApi } from '@/features/findings/api/use-findings-api'
import type { ApiFinding, FindingApiFilters } from '@/features/findings/api/finding-api.types'

const OPEN_EXCLUDE = findingStatusesInCategory('closed')

/** The queue shows the top of the list; "View all" opens Findings filtered to me. */
const QUEUE_SIZE = 15

function findingName(f: ApiFinding): string | undefined {
  return f.title || f.rule_name || f.message || undefined
}

function prettyStatus(s: string): string {
  const text = s.replace(/_/g, ' ')
  return text.charAt(0).toUpperCase() + text.slice(1)
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
  const { t } = useTranslation()
  const router = useRouter()
  const params = useSearchParams()
  const { hasPermission } = usePermissions()
  const canSeeTasks = hasPermission(Permission.RemediationRead)
  const tab: MyWorkTab = canSeeTasks && params.get('tab') === 'tasks' ? 'tasks' : 'findings'
  const taskCount = useMyTaskCount(canSeeTasks)
  const setTab = (next: string) => {
    router.replace(next === 'tasks' ? '/my-work?tab=tasks' : '/my-work', { scroll: false })
  }
  const queueFilters: FindingApiFilters = {
    assigned_to_me: true,
    exclude_statuses: OPEN_EXCLUDE,
    sort: 'priority_class,severity,-created_at',
    per_page: QUEUE_SIZE,
  }
  const { data: queue, isLoading } = useFindingsApi(queueFilters, { enabled: tab === 'findings' })
  const { data: critical } = useFindingsApi(
    {
      assigned_to_me: true,
      exclude_statuses: OPEN_EXCLUDE,
      severities: ['critical', 'high'],
      per_page: 1,
    },
    { enabled: tab === 'findings' }
  )
  const { data: overdue } = useFindingsApi(
    {
      assigned_to_me: true,
      exclude_statuses: OPEN_EXCLUDE,
      sla_statuses: ['overdue', 'exceeded'],
      per_page: 1,
    },
    { enabled: tab === 'findings' }
  )

  const openTotal = queue?.total ?? 0
  const rows = useMemo(() => queue?.data ?? [], [queue])

  // Each metric opens Findings with the matching filter (this page is a
  // read-only queue; the full list and its filters live on Findings).
  const metrics: MetricStripItem[] = [
    {
      key: 'open',
      label: t('myWork.metrics.open'),
      value: openTotal,
      onClick: () => router.push('/findings?related_to=me'),
    },
    {
      key: 'critical',
      label: t('myWork.metrics.critical'),
      value: critical?.total ?? 0,
      tone: 'danger',
      onClick: () => router.push('/findings?related_to=me&priority_class=P0'),
    },
    {
      key: 'overdue',
      label: t('myWork.metrics.overdue'),
      value: overdue?.total ?? 0,
      tone: 'danger',
      onClick: () => router.push('/findings?related_to=me&sla_status=overdue'),
    },
  ]

  const columns = useMemo<ColumnDef<ApiFinding>[]>(
    () => [
      {
        accessorKey: 'title',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.finding')} />
        ),
        cell: ({ row }) => {
          const f = row.original
          return (
            <div className="min-w-0 max-w-[520px]">
              <p className="truncate text-sm font-medium">
                {findingName(f) ?? t('myWork.untitled')}
              </p>
              {f.asset?.name && (
                <p className="truncate text-xs text-muted-foreground">{f.asset.name}</p>
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
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {t(`findings.status.${row.original.status}`, prettyStatus(row.original.status))}
          </span>
        ),
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
            return <Badge variant="destructive">{t('myWork.sla.overdue')}</Badge>
          }
          if (sla === 'warning') return <Badge variant="secondary">{t('myWork.sla.dueSoon')}</Badge>
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
            {formatRelative(row.original.created_at)}
          </span>
        ),
      },
    ],
    [t]
  )

  return (
    <Main>
      <PageHeader title={t('myWork.title')} description={t('myWork.description')} />

      {canSeeTasks && (
        <Tabs value={tab} onValueChange={setTab} className="mt-4">
          <TabsList aria-label={t('myWork.tabs.label')}>
            <TabsTrigger value="findings">{t('myWork.tabs.findings')}</TabsTrigger>
            <TabsTrigger value="tasks">
              {t('myWork.tabs.tasks')}
              {taskCount ? (
                <Badge variant="secondary" className="ms-2 px-1.5 tabular-nums">
                  {taskCount.toLocaleString()}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>
        </Tabs>
      )}

      {tab === 'tasks' ? (
        <div className="mt-5">
          <MyTasksQueue />
        </div>
      ) : (
        <>
          <MetricStrip className="mt-5" loading={isLoading} items={metrics} />

          <div className="mt-5">
            {isLoading ? (
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
                          total: openTotal.toLocaleString(),
                        })
                      : t('myWork.byPriority')}
                  </span>
                }
                toolbarEnd={
                  <Button variant="outline" size="sm" asChild>
                    <Link href="/findings?related_to=me">
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
        </>
      )}
    </Main>
  )
}
