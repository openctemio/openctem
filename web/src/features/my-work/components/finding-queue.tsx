'use client'

import { useMemo, type ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import Link from '@/components/link'
import { DataTable, DataTableColumnHeader } from '@/features/shared'
import { ErrorState } from '@/features/shared/components/error-state'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { dateFnsLocaleFor } from '@/features/shared/components/activity-timeline'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import type { FindingStatus } from '@/features/findings/types'
import type { ApiFinding } from '@/features/findings/api/finding-api.types'
import { SlaDueChip } from '@/features/sla/components/sla-due-chip'
import { useTranslation } from '@/context/i18n-provider'
import { FindingTitleCell } from '@/features/findings/components/cells/finding-title-cell'
import { findingLocation } from '@/features/findings/lib/finding-location'
import { QUEUE_SIZE, type FindingQueueTab } from '../lib/queues'

function findingName(f: ApiFinding): string | undefined {
  return f.title || f.rule_name || f.message || undefined
}

/**
 * A finding queue of My Work (Assigned to me, My team, Acceptances
 * expiring): the top of one quick view's list in the queue's order. The rows
 * are the API's own list for the view's params, so the tab count, the rows'
 * total and the Findings page behind "View all" agree.
 */
export function FindingQueue({
  tab,
  rows,
  total,
  isLoading,
  error,
  onRetry,
  toolbarStart,
  toolbarEnd,
  empty,
}: {
  tab: FindingQueueTab
  rows: ApiFinding[]
  total: number
  isLoading: boolean
  error: unknown
  onRetry: () => void
  toolbarStart?: ReactNode
  toolbarEnd?: ReactNode
  empty: ReactNode
}) {
  const { t, locale } = useTranslation()
  const router = useRouter()
  const dateLocale = dateFnsLocaleFor(locale)

  const columns = useMemo<ColumnDef<ApiFinding>[]>(() => {
    const cols: ColumnDef<ApiFinding>[] = [
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
            <Link
              href={`/findings/${encodeURIComponent(f.id)}`}
              className="block max-w-[520px] min-w-0 text-sm hover:[&_p]:underline"
              onClick={(e) => e.stopPropagation()}
            >
              <FindingTitleCell
                title={findingName(f) || t('myWork.untitled')}
                target={findingLocation(f).full}
              />
            </Link>
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
    ]
    if (tab === 'expiring') {
      cols.push({
        id: 'acceptance_end',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.acceptanceEnds')} />
        ),
        cell: ({ row }) => (
          <span className="text-sm whitespace-nowrap text-muted-foreground">
            <RelativeTime date={row.original.acceptance_expires_at} locale={dateLocale} />
          </span>
        ),
      })
    } else {
      cols.push(
        {
          id: 'sla',
          enableSorting: false,
          header: ({ column }) => (
            <DataTableColumnHeader column={column} title={t('myWork.columns.sla')} />
          ),
          cell: ({ row }) => (
            <SlaDueChip
              status={row.original.sla_status}
              deadline={row.original.sla_deadline}
              kevCapped={row.original.sla_kev_capped}
            />
          ),
        },
        {
          accessorKey: 'status',
          enableSorting: false,
          header: ({ column }) => (
            <DataTableColumnHeader column={column} title={t('myWork.columns.status')} />
          ),
          cell: ({ row }) => <FindingStatusBadge status={row.original.status as FindingStatus} />,
        }
      )
    }
    return cols
  }, [t, tab, dateLocale])

  if (error) {
    return <ErrorState title={t('myWork.loadError')} onRetry={onRetry} />
  }
  return (
    <DataTable
      columns={columns}
      data={rows}
      isLoading={isLoading}
      showSearch={false}
      showColumnToggle={false}
      showPagination={false}
      pageSize={QUEUE_SIZE}
      getRowId={(f) => f.id}
      onRowClick={(f) => router.push(`/findings/${encodeURIComponent(f.id)}`)}
      toolbarStart={toolbarStart}
      toolbarEnd={toolbarEnd}
      emptyState={total === 0 ? empty : undefined}
    />
  )
}
