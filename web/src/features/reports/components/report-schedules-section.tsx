'use client'

import { useCallback, useState } from 'react'
import { toast } from 'sonner'
import type { ColumnDef } from '@tanstack/react-table'
import { AlertCircle, CalendarClock, Trash2 } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { DataTable, EmptyState } from '@/features/shared'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { Can } from '@/lib/permissions'
import { useReportSchedules } from '../hooks/use-report-schedules'
import { humanizeCron } from '../lib/cron'
import { NewScheduleDialog } from './new-schedule-dialog'
import type { ReportSchedule } from '../types'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

const REPORT_TYPE_LABELS: Record<string, string> = {
  executive_summary: 'Executive summary',
  summary: 'Summary digest',
  findings: 'Findings digest',
}

function statusVariant(status?: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  switch (status) {
    case 'completed':
      return 'default'
    case 'failed':
      return 'destructive'
    case 'no_recipients':
    case 'unsupported':
      return 'outline'
    default:
      return 'secondary'
  }
}

function LastRunCell({ schedule }: { schedule: ReportSchedule }) {
  if (!schedule.last_run_at) {
    return <span className="text-muted-foreground">Never</span>
  }
  return (
    <div className="flex flex-col gap-1">
      <RelativeTime date={schedule.last_run_at} className="text-sm" />
      {schedule.last_status && (
        <Badge variant={statusVariant(schedule.last_status)} className="w-fit text-xs">
          {schedule.last_status.replace(/_/g, ' ')}
        </Badge>
      )}
    </div>
  )
}

export function ReportSchedulesSection() {
  const { t } = useTranslation()
  const { schedules, isLoading, error, createSchedule, toggleSchedule, deleteSchedule } =
    useReportSchedules()
  const [pendingToggle, setPendingToggle] = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<ReportSchedule | null>(null)

  const handleToggle = useCallback(
    async (schedule: ReportSchedule) => {
      setPendingToggle(schedule.id)
      try {
        await toggleSchedule(schedule.id, !schedule.is_active)
        toast.success(
          schedule.is_active
            ? t('reports.schedules.paused', 'Schedule paused')
            : t('reports.schedules.activated', 'Schedule activated')
        )
      } catch (err) {
        toast.error(
          err instanceof Error
            ? err.message
            : t('reports.schedules.updateFailed', 'Failed to update schedule')
        )
      } finally {
        setPendingToggle(null)
      }
    },
    [toggleSchedule, t]
  )

  const handleDelete = useCallback(
    async (id: string) => {
      setDeletingId(id)
      try {
        await deleteSchedule(id)
        setPendingDelete(null)
        toast.success(t('reports.schedules.deleted', 'Schedule deleted'))
      } catch (err) {
        toast.error(
          err instanceof Error
            ? err.message
            : t('reports.schedules.deleteFailed', 'Failed to delete schedule')
        )
      } finally {
        setDeletingId(null)
      }
    },
    [deleteSchedule, t]
  )

  const columns: ColumnDef<ReportSchedule>[] = [
    {
      accessorKey: 'name',
      enableSorting: false,
      header: t('reports.schedules.colName', 'Name'),
      cell: ({ row }) => <span className="text-sm font-medium">{row.original.name}</span>,
    },
    {
      id: 'owner',
      enableSorting: false,
      header: t('reports.schedules.colOwner', 'Owner'),
      cell: ({ row }) =>
        row.original.created_by_name ? (
          <span className="text-sm">{row.original.created_by_name}</span>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
    {
      accessorKey: 'report_type',
      enableSorting: false,
      header: t('reports.schedules.colType', 'Type'),
      cell: ({ row }) => (
        <span className="text-sm">
          {REPORT_TYPE_LABELS[row.original.report_type] ?? row.original.report_type}
        </span>
      ),
    },
    {
      id: 'cadence',
      enableSorting: false,
      header: t('reports.schedules.colCadence', 'Cadence'),
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="text-sm">{humanizeCron(row.original.cron_expression)}</span>
          <span className="text-xs text-muted-foreground">{row.original.timezone}</span>
        </div>
      ),
    },
    {
      id: 'recipients',
      enableSorting: false,
      header: t('reports.schedules.colRecipients', 'Recipients'),
      cell: ({ row }) => {
        const s = row.original
        const emails = (s.recipients ?? []).map((r) => r.email).join(', ')
        return (
          <span className="text-sm tabular-nums" title={emails || undefined}>
            {s.recipient_count ?? s.recipients?.length ?? 0}
          </span>
        )
      },
    },
    {
      id: 'active',
      enableSorting: false,
      header: t('reports.schedules.colActive', 'Active'),
      cell: ({ row }) => {
        const schedule = row.original
        // Only the creator or a member who manages reports may pause or
        // resume a schedule; everyone else sees its state.
        if (!schedule.can_manage) {
          return (
            <Badge variant="outline">
              {schedule.is_active
                ? t('reports.schedules.stateActive', 'Active')
                : t('reports.schedules.statePaused', 'Paused')}
            </Badge>
          )
        }
        return (
          <Switch
            checked={schedule.is_active}
            disabled={pendingToggle === schedule.id}
            onCheckedChange={() => handleToggle(schedule)}
            aria-label={
              schedule.is_active
                ? t('reports.schedules.pauseLabel', 'Pause {name}', { name: schedule.name })
                : t('reports.schedules.resumeLabel', 'Resume {name}', { name: schedule.name })
            }
          />
        )
      },
    },
    {
      id: 'last_run',
      enableSorting: false,
      header: t('reports.schedules.colLastRun', 'Last run'),
      cell: ({ row }) => <LastRunCell schedule={row.original} />,
    },
    {
      id: 'next_run',
      enableSorting: false,
      header: t('reports.schedules.colNextRun', 'Next run'),
      cell: ({ row }) =>
        row.original.next_run_at && row.original.is_active ? (
          <RelativeTime date={row.original.next_run_at} className="text-sm" />
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => {
        const schedule = row.original
        if (!schedule.can_manage) return null
        return (
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            disabled={deletingId === schedule.id}
            aria-label={t('confirm.reportSchedule.deleteLabel', 'Delete {name}', {
              name: schedule.name,
            })}
            onClick={() => setPendingDelete(schedule)}
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        )
      },
    },
  ]

  return (
    <section className="space-y-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-base font-semibold">Scheduled reports</h2>
          <p className="text-sm text-muted-foreground">
            {t(
              'reports.schedulesHint',
              'Finding-summary digests emailed to recipients on a schedule.'
            )}
          </p>
        </div>
        {schedules.length > 0 && (
          <Can permission="reports:write">
            <NewScheduleDialog onCreate={createSchedule} />
          </Can>
        )}
      </div>
      {isLoading ? (
        <div className="space-y-px overflow-hidden rounded-xl border">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full rounded-none" />
          ))}
        </div>
      ) : error ? (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Failed to load schedules</AlertTitle>
          <AlertDescription>
            {error instanceof Error ? error.message : 'An unexpected error occurred'}
          </AlertDescription>
        </Alert>
      ) : schedules.length === 0 ? (
        <EmptyState
          icon={CalendarClock}
          title="No scheduled reports yet"
          description="Create a schedule to email a recurring finding-summary digest to your team."
          action={
            <Can permission="reports:write">
              <NewScheduleDialog onCreate={createSchedule} />
            </Can>
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={schedules}
          getRowId={(s) => s.id}
          showSearch={false}
          showColumnToggle={false}
          showPagination={schedules.length > 10}
          emptyMessage="No scheduled reports"
        />
      )}
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        destructive
        title={t('confirm.reportSchedule.deleteTitle', 'Delete the schedule "{name}"?', {
          name: pendingDelete?.name ?? '',
        })}
        desc={t(
          'confirm.reportSchedule.deleteDesc',
          'It stops sending at once. Reports already sent are not affected. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        isLoading={deletingId !== null}
        handleConfirm={() => (pendingDelete ? handleDelete(pendingDelete.id) : undefined)}
      />
    </section>
  )
}
