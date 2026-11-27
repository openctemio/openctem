'use client'

import { useMemo, type ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import Link from '@/components/link'
import { DataTable, DataTableColumnHeader } from '@/features/shared'
import { QueueCard } from '@/features/shared/components/queue'
import { ErrorState } from '@/features/shared/components/error-state'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import type { FindingStatus } from '@/features/findings/types'
import type { ApiFinding } from '@/features/findings/api/finding-api.types'
import { SlaDueChip } from '@/features/sla/components/sla-due-chip'
import { useTranslation } from '@/context/i18n-provider'
import { FindingTitleCell } from '@/features/findings/components/cells/finding-title-cell'
import { findingLocation } from '@/features/findings/lib/finding-location'
import { maskSensitiveText } from '@/lib/mask-sensitive'
import { toDisplayText } from '@/lib/untrusted-text'
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
  toolbarBelow,
  toolbarEnd,
  empty,
}: {
  tab: FindingQueueTab
  rows: ApiFinding[]
  total: number
  isLoading: boolean
  error: unknown
  onRetry: () => void
  /** The queue's filter token: the toolbar's start. */
  toolbarStart?: ReactNode
  /** The queue's locked rule and how much is on screen: the line under the toolbar. */
  toolbarBelow?: ReactNode
  toolbarEnd?: ReactNode
  empty: ReactNode
}) {
  const { t } = useTranslation()
  const router = useRouter()

  const columns = useMemo<ColumnDef<ApiFinding>[]>(() => {
    const cols: ColumnDef<ApiFinding>[] = [
      {
        accessorKey: 'priority_class',
        meta: { kind: 'priority' },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('myWork.columns.priority')} />
        ),
        cell: ({ row }) => (
          <PriorityClassBadge
            priorityClass={row.original.priority_class}
            assetId={row.original.asset?.id}
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
        meta: { kind: 'severity' },
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
            <RelativeTime date={row.original.acceptance_expires_at} />
          </span>
        ),
      })
    } else {
      cols.push(
        {
          id: 'sla',
          meta: { kind: 'due' },
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
          // Whole or not at all: below a 700 px frame (a tablet) the column
          // leaves (the finding's page and the phone card show the status).
          meta: { kind: 'status', hideBelow: 700 },
          enableSorting: false,
          header: ({ column }) => (
            <DataTableColumnHeader column={column} title={t('myWork.columns.status')} />
          ),
          cell: ({ row }) => <FindingStatusBadge status={row.original.status as FindingStatus} />,
        }
      )
    }
    return cols
  }, [t, tab])

  // A phone card on the queue card's slots: the title (two lines at most)
  // with the status at its end, then one line of facts (priority, severity,
  // the deadline or the acceptance end, where the finding is) and the
  // chevron to the finding.
  const mobileRow = (f: ApiFinding) => {
    const location = findingLocation(f).full
    const href = `/findings/${encodeURIComponent(f.id)}`
    // Masked and escaped as the table row's FindingTitleCell does: a secret in
    // a scanner title never shows in clear on a phone either.
    const raw = findingName(f)
    const name = raw ? toDisplayText(maskSensitiveText(raw), 500) : ''
    return (
      <QueueCard
        data-testid="my-work-finding-card"
        href={href}
        title={
          <Link href={href} className="block min-w-0 text-sm font-medium hover:underline">
            <span data-cut-tooltip title={name || undefined} className="line-clamp-2 break-words">
              {name || t('myWork.untitled')}
            </span>
          </Link>
        }
        state={
          tab === 'expiring' ? undefined : <FindingStatusBadge status={f.status as FindingStatus} />
        }
        meta={[
          <span key="marks" className="flex items-center gap-1.5">
            <PriorityClassBadge priorityClass={f.priority_class} assetId={f.asset?.id} showWord />
            <SeverityBadge severity={f.severity} />
          </span>,
          tab === 'expiring' ? (
            <span key="due">
              {t('myWork.columns.acceptanceEnds')} <RelativeTime date={f.acceptance_expires_at} />
            </span>
          ) : (
            <SlaDueChip
              key="due"
              status={f.sla_status}
              deadline={f.sla_deadline}
              kevCapped={f.sla_kev_capped}
            />
          ),
          location ? <span key="where">{location}</span> : null,
        ]}
      />
    )
  }

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
      toolbarBelow={toolbarBelow}
      mobileRow={mobileRow}
      emptyState={total === 0 ? empty : undefined}
    />
  )
}
