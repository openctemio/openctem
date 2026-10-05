'use client'

/**
 * One scan (research 20 §4.3): the durable object of the Scans area. The run
 * history is paged on the server; a run opens in the shared run drawer. The
 * configuration and details use the same Detail* vocabulary as the scan
 * drawer, and the numbers the same formulas (lib/format, lib/run-display).
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { toast } from 'sonner'
import {
  AlertTriangle,
  ArrowLeft,
  Pause,
  Play,
  RefreshCw,
  Tag,
  Trash2,
  XCircle,
} from 'lucide-react'

import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  DangerZone,
  DangerZoneItem,
  DataTable,
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
  MetricStrip,
  PageHeader,
  RunStatusBadge,
  StatusBadge,
  TruncatedText,
  type MetricStripItem,
} from '@/features/shared'
import { RunDetailSheet } from '@/features/scans/components/run-detail-sheet'
import { useScanTrigger } from '@/features/scans/hooks/use-scan-trigger'
import { formatScanDate, formatScanDuration } from '@/features/scans/lib/format'
import {
  elapsedMs,
  isRunInProgress,
  runTaskProgress,
  runTriggeredByLabel,
  scanRunCounts,
} from '@/features/scans/lib/run-display'
import { useUrlFilter, useUrlFilterNumber } from '@/hooks/use-url-param'
import { del, post } from '@/lib/api/client'
import { pipelineRunEndpoints, scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import { PIPELINE_TRIGGER_LABELS, type PipelineTriggerType } from '@/lib/api/pipeline-types'
import { invalidateScanConfigsCache, useScanConfig, useScanRuns } from '@/lib/api/scan-hooks'
import {
  SCAN_CONFIG_STATUS_LABELS,
  SCAN_TYPE_LABELS,
  SCHEDULE_TYPE_LABELS,
  SENSOR_PREFERENCE_LABELS,
  type PipelineRun,
  type ScanConfig,
} from '@/lib/api/scan-types'
import { useAssetGroup } from '@/lib/api/security-hooks'
import { Can, Permission } from '@/lib/permissions'
import { SchedulePreview } from '@/features/scans/components/schedule-preview'
import { schedulePreviewRequestFromConfig } from '@/features/scans/lib/schedule-preview'

const TABS = ['runs', 'configuration', 'details'] as const
type Tab = (typeof TABS)[number]

/** Run history page sizes (style contract §3). */
const RUN_PAGE_SIZES = [25, 50, 100]

/** A run's duration, "so far" while it is still going. */
function runDuration(run: PipelineRun): string {
  const ms = elapsedMs(run)
  if (ms === undefined) return run.status === 'pending' ? 'Not started' : '-'
  const label = ms < 1000 ? '<1s' : formatScanDuration(ms)
  return run.completed_at ? label : `${label} so far`
}

function scanStatusBadge(status: ScanConfig['status']) {
  return (
    <StatusBadge
      status={status === 'active' ? 'active' : status === 'paused' ? 'pending' : 'inactive'}
    />
  )
}

/**
 * An asset group by name (scoped read: a group the viewer cannot see shows
 * its short id, never an error).
 */
function AssetGroupName({ id }: { id: string }) {
  const { data } = useAssetGroup(id, { shouldRetryOnError: false, onError: () => {} })
  const name = (data as { name?: string } | undefined)?.name
  return (
    <Badge variant="outline" className="max-w-[16rem]">
      <TruncatedText value={name || `${id.slice(0, 8)}…`} label="Asset group" />
    </Badge>
  )
}

/** Direct targets: the first few, then all of them on request. */
function TargetList({ targets }: { targets: string[] }) {
  const [all, setAll] = useState(false)
  const shown = all ? targets : targets.slice(0, 12)
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {shown.map((target, i) => (
          <Badge key={i} variant="secondary" className="max-w-[20rem] font-normal">
            <TruncatedText value={target} label="Target" />
          </Badge>
        ))}
      </div>
      {targets.length > 12 && (
        <Button variant="link" size="sm" className="h-auto p-0" onClick={() => setAll(!all)}>
          {all ? 'Show fewer' : `Show all ${targets.length}`}
        </Button>
      )}
    </div>
  )
}

export default function ScanDetailPage() {
  const params = useParams()
  const router = useRouter()
  const scanId = params.id as string

  const [tabParam, setTabParam] = useUrlFilter('tab', 'runs')
  const tab: Tab = (TABS as readonly string[]).includes(tabParam) ? (tabParam as Tab) : 'runs'
  // The run history is paged on the server; the page lives in the URL.
  const [runPage, setRunPage] = useUrlFilterNumber('run_page', 1)
  const [runPerPageParam, setRunPerPage] = useUrlFilterNumber('run_per_page', 25)
  const runPerPage = RUN_PAGE_SIZES.includes(runPerPageParam) ? runPerPageParam : 25

  const [isPausing, setIsPausing] = useState(false)
  const [isActivating, setIsActivating] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [stoppingRunId, setStoppingRunId] = useState<string | null>(null)
  const [openRunId, setOpenRunId] = useState<string | null>(null)

  const { data: config, isLoading, error } = useScanConfig(scanId)

  // The latest runs, for the numbers above the tabs (runs still in progress
  // are the newest), whichever history page is open.
  const { data: latestRuns, mutate: refetchLatest } = useScanRuns(scanId, 1, 10, {
    refreshInterval: 10000,
  })
  const {
    data: runsResponse,
    isLoading: isLoadingRuns,
    mutate: refetchRuns,
  } = useScanRuns(scanId, runPage, runPerPage, { refreshInterval: 10000, keepPreviousData: true })
  const runs = useMemo(() => runsResponse?.data ?? [], [runsResponse])
  const refetchAll = () => Promise.all([refetchLatest(), refetchRuns()])

  // Trigger asks first when a run is already in progress and ignores a second
  // click while the first is in flight.
  const {
    trigger: triggerScan,
    isTriggering: isScanTriggering,
    dialog: triggerDialog,
  } = useScanTrigger({ onViewRun: setOpenRunId, onTriggered: () => void refetchAll() })
  const isTriggering = isScanTriggering(scanId)

  // The scan's counters move when a run finishes; the total adds the runs in
  // progress (scanRunCounts). Success rate is null before any run settled.
  const counts = useMemo(
    () => (config ? scanRunCounts(config, latestRuns?.data ?? []) : null),
    [config, latestRuns]
  )
  const activeRun = (latestRuns?.data ?? []).find(isRunInProgress)

  const handleStopRun = async (run: PipelineRun) => {
    setStoppingRunId(run.id)
    try {
      await post(pipelineRunEndpoints.cancel(run.id), {})
      toast.success('Run canceled. In-flight tasks stop at their next heartbeat.')
      await refetchAll()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to cancel run'))
    } finally {
      setStoppingRunId(null)
    }
  }

  const setStatus = async (action: 'pause' | 'activate') => {
    if (!config) return
    const setBusy = action === 'pause' ? setIsPausing : setIsActivating
    setBusy(true)
    try {
      await post(
        action === 'pause' ? scanEndpoints.pause(config.id) : scanEndpoints.activate(config.id),
        {}
      )
      toast.success(`Scan "${config.name}" ${action === 'pause' ? 'paused' : 'activated'}`)
      await invalidateScanConfigsCache()
    } catch (err) {
      toast.error(getErrorMessage(err, `Failed to ${action} scan "${config.name}"`))
    } finally {
      setBusy(false)
    }
  }

  const handleDeleteConfig = async () => {
    if (!config) return
    setIsDeleting(true)
    try {
      await del(scanEndpoints.delete(config.id))
      toast.success(`Scan "${config.name}" deleted`)
      router.push('/scans')
    } catch (err) {
      toast.error(getErrorMessage(err, `Failed to delete scan "${config.name}"`))
    } finally {
      setIsDeleting(false)
      setDeleteConfirmOpen(false)
    }
  }

  // Rebuilt each render: the cancel action reads the in-flight run id. No
  // column sorts: this endpoint lists newest first, and sorting one page of
  // the history would misrepresent the rest.
  const runColumns: ColumnDef<PipelineRun>[] = [
    {
      id: 'started',
      header: 'Started',
      enableSorting: false,
      cell: ({ row }) => (
        <span className="font-medium">
          {formatScanDate(row.original.started_at || row.original.created_at)}
        </span>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      enableSorting: false,
      cell: ({ row }) => (
        <div className="space-y-0.5">
          <RunStatusBadge status={row.original.status} />
          {row.original.error_message && (
            <TruncatedText
              value={row.original.error_message}
              label="Run message"
              className="max-w-[240px] text-xs text-muted-foreground"
            />
          )}
        </div>
      ),
    },
    {
      id: 'trigger',
      header: 'Trigger',
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span>
            {PIPELINE_TRIGGER_LABELS[row.original.trigger_type as PipelineTriggerType] ??
              row.original.trigger_type}
          </span>
          {runTriggeredByLabel(row.original) && (
            <span className="text-xs text-muted-foreground">
              {runTriggeredByLabel(row.original)}
            </span>
          )}
        </div>
      ),
    },
    {
      id: 'tasks',
      header: 'Tasks',
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original
        const progress = runTaskProgress(r.task_summary)
        return (
          <span className="tabular-nums">
            {progress ? progress.label : `${r.completed_steps}/${r.total_steps} steps`}
          </span>
        )
      },
    },
    {
      id: 'findings',
      header: 'Findings',
      enableSorting: false,
      cell: ({ row }) =>
        row.original.total_findings > 0 ? (
          <span className="tabular-nums">{row.original.total_findings}</span>
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      id: 'duration',
      header: 'Duration',
      enableSorting: false,
      cell: ({ row }) => (
        <span className="tabular-nums text-muted-foreground">{runDuration(row.original)}</span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => {
        const run = row.original
        if (!isRunInProgress(run)) return null
        return (
          // POST /pipeline-runs/{id}/cancel needs pipelines:write AND
          // scans:write (D12).
          <Can permission={[Permission.PipelinesWrite, Permission.ScansWrite]} requireAll>
            <Button
              size="sm"
              variant="ghost"
              disabled={stoppingRunId === run.id}
              onClick={() => handleStopRun(run)}
              aria-label={`Cancel run started ${formatScanDate(run.started_at || run.created_at)}`}
            >
              {stoppingRunId === run.id ? (
                <RefreshCw className="me-1 h-4 w-4 animate-spin motion-reduce:animate-none" />
              ) : (
                <XCircle className="me-1 h-4 w-4" />
              )}
              Cancel
            </Button>
          </Can>
        )
      },
    },
  ]

  if (isLoading) {
    return (
      <Main>
        <div className="space-y-5" aria-busy="true" aria-label="Loading scan">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-[400px] w-full" />
        </div>
      </Main>
    )
  }

  if (error || !config) {
    return (
      <Main>
        <PageHeader title="Scan not found" />
        <div className="mt-5 flex flex-col items-start gap-4">
          <p className="text-sm text-muted-foreground">
            This scan does not exist, or you do not have access to it.
          </p>
          <Button asChild variant="outline" size="sm">
            <Link href="/scans">
              <ArrowLeft className="me-2 h-4 w-4" />
              Back to scans
            </Link>
          </Button>
        </div>
      </Main>
    )
  }

  const groupIds =
    config.asset_group_ids && config.asset_group_ids.length > 0
      ? config.asset_group_ids
      : config.asset_group_id
        ? [config.asset_group_id]
        : []
  const targets = config.targets ?? []
  const rate = counts?.successRate ?? null

  const metrics: MetricStripItem[] = [
    {
      key: 'runs',
      label: 'Runs',
      value: counts?.total ?? config.total_runs,
      hint: counts && counts.inProgress > 0 ? `${counts.inProgress} in progress` : undefined,
    },
    {
      key: 'rate',
      label: 'Success rate',
      // A rate needs a settled run: "n/a", never a red 0%.
      value: rate === null ? 'n/a' : `${rate}%`,
      hint: rate === null ? 'No finished run yet' : undefined,
    },
    { key: 'ok', label: 'Successful', value: config.successful_runs },
    { key: 'partial', label: 'Partial', value: config.partial_runs ?? 0, tone: 'warning' },
    { key: 'failed', label: 'Failed', value: config.failed_runs, tone: 'danger' },
    {
      key: 'next',
      label: 'Next run',
      value: config.next_run_at ? formatScanDate(config.next_run_at) : '-',
      hint:
        config.status === 'paused' && config.next_run_at
          ? 'If resumed'
          : config.schedule_type === 'manual'
            ? 'Manual only'
            : undefined,
    },
  ]

  return (
    <Main>
      <Button variant="ghost" size="sm" asChild className="mb-3 -ms-2">
        <Link href="/scans">
          <ArrowLeft className="me-2 h-4 w-4" />
          Scans
        </Link>
      </Button>

      <PageHeader
        title={config.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            {scanStatusBadge(config.status)}
            <span>{SCAN_TYPE_LABELS[config.scan_type]}</span>
            <span aria-hidden="true">·</span>
            <span>{SCHEDULE_TYPE_LABELS[config.schedule_type]}</span>
            {activeRun && (
              <Button
                variant="link"
                size="sm"
                className="h-auto p-0"
                onClick={() => setOpenRunId(activeRun.id)}
              >
                <RefreshCw className="me-1 h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />A
                run is in progress
              </Button>
            )}
          </span>
        }
      >
        {/* The gates mirror the API: trigger needs scans:write AND
            scans:execute; pause, resume and enable need scans:write. */}
        {config.status !== 'disabled' && (
          <Can
            permission={[Permission.ScansWrite, Permission.ScansExecute]}
            requireAll
            mode="disable"
          >
            <Button
              size="sm"
              onClick={() => void triggerScan(config)}
              disabled={isTriggering}
              aria-busy={isTriggering}
            >
              {isTriggering ? (
                <RefreshCw className="me-2 h-4 w-4 animate-spin motion-reduce:animate-none" />
              ) : (
                <Play className="me-2 h-4 w-4" />
              )}
              Trigger
            </Button>
          </Can>
        )}
        <Can permission={Permission.ScansWrite} mode="disable">
          {config.status === 'active' ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => setStatus('pause')}
              disabled={isPausing}
            >
              <Pause className="me-2 h-4 w-4" />
              Pause
            </Button>
          ) : (
            <Button
              size="sm"
              variant={config.status === 'disabled' ? 'default' : 'outline'}
              onClick={() => setStatus('activate')}
              disabled={isActivating}
            >
              <Play className="me-2 h-4 w-4" />
              {config.status === 'disabled' ? 'Enable' : 'Resume'}
            </Button>
          )}
        </Can>
      </PageHeader>

      <MetricStrip className="mt-5" items={metrics} />

      <Tabs value={tab} onValueChange={setTabParam} className="mt-5">
        <TabsList>
          <TabsTrigger value="runs">Runs</TabsTrigger>
          <TabsTrigger value="configuration">Configuration</TabsTrigger>
          <TabsTrigger value="details">Details</TabsTrigger>
        </TabsList>

        <TabsContent value="runs" className="mt-5">
          <DataTable
            columns={runColumns}
            data={runs}
            getRowId={(run) => run.id}
            isLoading={isLoadingRuns && !runsResponse}
            showSearch={false}
            onRowClick={(run) => setOpenRunId(run.id)}
            manualPagination
            rowCount={runsResponse?.total ?? 0}
            pagination={{ pageIndex: runPage - 1, pageSize: runPerPage }}
            onPaginationChange={(next) => {
              if (next.pageSize !== runPerPage) {
                setRunPerPage(next.pageSize)
                setRunPage(1)
              } else {
                setRunPage(next.pageIndex + 1)
              }
            }}
            pageSize={runPerPage}
            pageSizeOptions={RUN_PAGE_SIZES}
            paginationNoun="runs"
            emptyMessage="No runs yet"
            emptyDescription="Trigger this scan to see its first run here."
          />
        </TabsContent>

        <TabsContent value="configuration" className="mt-5">
          <DetailSections>
            <DetailSection title="Schedule">
              <DetailFieldGrid>
                <DetailField label="Frequency">
                  {SCHEDULE_TYPE_LABELS[config.schedule_type]}
                </DetailField>
                {config.schedule_time && (
                  <DetailField label="Time">{config.schedule_time}</DetailField>
                )}
                <DetailField label="Timezone">{config.schedule_timezone}</DetailField>
                {config.next_run_at && (
                  <DetailField label="Next run">{formatScanDate(config.next_run_at)}</DetailField>
                )}
                {config.schedule_rrule && (
                  <DetailField label="Rule" full>
                    <code className="text-xs break-all">{config.schedule_rrule}</code>
                  </DetailField>
                )}
              </DetailFieldGrid>
              <div className="mt-4">
                <SchedulePreview
                  request={schedulePreviewRequestFromConfig(config)}
                  paused={config.status !== 'active'}
                />
              </div>
            </DetailSection>
            <DetailSection title="Execution">
              <DetailFieldGrid>
                <DetailField label="Scan type">{SCAN_TYPE_LABELS[config.scan_type]}</DetailField>
                <DetailField label="Sensor preference">
                  {SENSOR_PREFERENCE_LABELS[config.sensor_preference]}
                </DetailField>
                <DetailField label="Targets per job">{config.targets_per_job}</DetailField>
              </DetailFieldGrid>
            </DetailSection>
            {(groupIds.length > 0 || targets.length > 0) && (
              <DetailSection title="Targets">
                <DetailFieldGrid>
                  {groupIds.length > 0 && (
                    <DetailField
                      label={groupIds.length === 1 ? 'Asset group' : 'Asset groups'}
                      full
                    >
                      <span className="flex flex-wrap gap-1.5">
                        {groupIds.map((id) => (
                          <AssetGroupName key={id} id={id} />
                        ))}
                      </span>
                    </DetailField>
                  )}
                  {targets.length > 0 && (
                    <DetailField label={`Direct targets (${targets.length})`} full>
                      <TargetList targets={targets} />
                    </DetailField>
                  )}
                </DetailFieldGrid>
              </DetailSection>
            )}
            {config.tags && config.tags.length > 0 && (
              <DetailSection title="Tags" count={config.tags.length}>
                <div className="flex flex-wrap gap-1.5">
                  {config.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="max-w-[16rem] gap-1">
                      <Tag className="h-3 w-3 shrink-0" />
                      <TruncatedText value={tag} label="Tag" />
                    </Badge>
                  ))}
                </div>
              </DetailSection>
            )}
          </DetailSections>
        </TabsContent>

        <TabsContent value="details" className="mt-5">
          <DetailSections>
            {config.description && (
              <DetailSection title="Description">
                <p
                  dir="auto"
                  className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground [unicode-bidi:isolate]"
                >
                  {config.description}
                </p>
              </DetailSection>
            )}
            <DetailSection title="Timeline">
              <DetailFieldGrid>
                <DetailField label="Created">{formatScanDate(config.created_at)}</DetailField>
                <DetailField label="Last run">
                  {config.last_run_at ? formatScanDate(config.last_run_at) : 'Never'}
                </DetailField>
                <DetailField label="Status">{SCAN_CONFIG_STATUS_LABELS[config.status]}</DetailField>
              </DetailFieldGrid>
            </DetailSection>
            <DetailSection title="Identity">
              <DetailFieldGrid>
                <DetailField label="Created by">{config.created_by_name || 'System'}</DetailField>
                <DetailField label="Scan ID" full>
                  <DetailCopyId id={config.id} label="Scan ID" />
                </DetailField>
                {config.pipeline_id && (
                  <DetailField label="Pipeline ID" full>
                    <DetailCopyId id={config.pipeline_id} label="Pipeline ID" />
                  </DetailField>
                )}
              </DetailFieldGrid>
            </DetailSection>
            <Can permission={Permission.ScansDelete}>
              <DangerZone>
                <DangerZoneItem
                  title="Delete scan"
                  description="Deletes this scan and its schedule. Past runs and findings stay."
                  action={
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => setDeleteConfirmOpen(true)}
                      disabled={isDeleting}
                    >
                      <Trash2 className="me-2 h-4 w-4" />
                      Delete scan
                    </Button>
                  }
                />
              </DangerZone>
            </Can>
          </DetailSections>
        </TabsContent>
      </Tabs>

      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={setDeleteConfirmOpen}
        title="Delete scan"
        desc={
          <>
            <span className="flex items-center gap-1.5 font-medium text-foreground">
              <AlertTriangle className="h-4 w-4 text-destructive" aria-hidden="true" />
              {config.name}
            </span>
            The scan and its schedule are deleted. Past runs and findings stay. This cannot be
            undone.
          </>
        }
        confirmText={isDeleting ? 'Deleting...' : 'Delete'}
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDeleteConfig}
      />
      {triggerDialog}
      <RunDetailSheet runId={openRunId} onOpenChange={(o) => !o && setOpenRunId(null)} />
    </Main>
  )
}
