'use client'

/**
 * One scan (research 20 §4.3): the durable object of the Scans area. The run
 * history is paged on the server; a run opens in the shared run drawer. The
 * configuration and details use the same Detail* vocabulary as the scan
 * drawer, and the numbers the same formulas (lib/format, lib/run-display).
 */

import { IntensityBadge, IntensityLabel } from '@/features/scans/components/intensity-badge'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useSWRConfig } from 'swr'
import type { ColumnDef } from '@tanstack/react-table'
import { useParams, useRouter } from 'next/navigation'
import Link from '@/components/link'
import { toast } from 'sonner'
import {
  AlertTriangle,
  ArrowLeft,
  Copy,
  Pencil,
  RefreshCw,
  Tag,
  Trash2,
  XCircle,
} from 'lucide-react'

import { Main, useBreadcrumbTitle } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { confirmName } from '@/lib/confirm-name'
import { useTranslation } from '@/context/i18n-provider'
import {
  DangerZone,
  DangerZoneItem,
  DataTable,
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
  ErrorState,
  MetricStrip,
  PageHeader,
  RunStatusBadge,
  TruncatedText,
  type MetricStripItem,
} from '@/features/shared'
import { RunDetailSheet } from '@/features/scans/components/run-detail-sheet'
import { CloneScanDialog, EditScanDialog } from '@/features/scans/components'
import { LastRunCell } from '@/features/scans/components/last-run-cell'
import { ScanControls, scanStateLabel } from '@/features/scans/components/scan-controls'
import { ScanApprovalPanel } from '@/features/scans/components/approval/scan-approval-panel'
import { ScanOwnerBanner } from '@/features/scans/components/scan-owner-banner'
import { LivenessHint } from '@/features/scans/components/liveness-hint'
import { lastRunOf, scanTypeLabel } from '@/features/scans/lib/scan-status'
import { formatScanDate, formatScanDuration } from '@/features/scans/lib/format'
import {
  IDLE_RUN_LIST_REFRESH_MS,
  elapsedMs,
  isRunInProgress,
  liveRunIds,
  runListRefreshInterval,
  runTargetNote,
  runTaskProgress,
  runTriggeredByLabel,
  scanRunCounts,
} from '@/features/scans/lib/run-display'
import { isManagedScan, managedScanLabel } from '@/features/scans/lib/scan-status'
import { ManagedScanBanner } from '@/features/scans/components/managed-scan-banner'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { useRunChannels } from '@/hooks/use-websocket'
import { del, post } from '@/lib/api/client'
import { scanRunEndpoints, scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  SCAN_RUN_TRIGGER_LABELS,
  type ScanWorkflowTriggerType,
} from '@/lib/api/scan-workflow-types'
import { useScanConfig, useScanRuns } from '@/lib/api/scan-hooks'
import {
  SCAN_CONFIG_STATUS_LABELS,
  SCAN_TYPE_LABELS,
  SCHEDULE_TYPE_LABELS,
  type ScanRun,
} from '@/lib/api/scan-types'
import { useAssetGroup } from '@/lib/api/security-hooks'
import { Can, Permission } from '@/lib/permissions'
import { SchedulePreview } from '@/features/scans/components/schedule-preview'
import { schedulePreviewRequestFromConfig } from '@/features/scans/lib/schedule-preview'

type Translate = ReturnType<typeof useTranslation>['t']

const TABS = ['runs', 'configuration', 'details'] as const
type Tab = (typeof TABS)[number]

/** Run history page sizes (style contract §3). */
const RUN_PAGE_SIZES = [25, 50, 100]

/** A run's duration, "so far" while it is still going. */
function runDuration(run: ScanRun, t: Translate): string {
  const ms = elapsedMs(run)
  if (ms === undefined) return run.status === 'pending' ? t('scanDetail.run.notStarted') : '-'
  const label = ms < 1000 ? '<1s' : formatScanDuration(ms)
  return run.completed_at
    ? label
    : t('scanDetail.run.soFar', '{duration} so far', { duration: label })
}

/**
 * An asset group by name (scoped read: a group the viewer cannot see shows
 * its short id, never an error).
 */
function AssetGroupName({ id }: { id: string }) {
  const { t } = useTranslation()
  const { data } = useAssetGroup(id, { shouldRetryOnError: false, onError: () => {} })
  const name = (data as { name?: string } | undefined)?.name
  return (
    <Badge variant="outline" className="max-w-[16rem]">
      <TruncatedText value={name || `${id.slice(0, 8)}…`} label={t('scanDetail.asset.groupAria')} />
    </Badge>
  )
}

/** Direct targets: the first few, then all of them on request. */
function TargetList({ targets }: { targets: string[] }) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const shown = all ? targets : targets.slice(0, 12)
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {shown.map((target, i) => (
          <Badge key={i} variant="secondary" className="max-w-[20rem] font-normal">
            <TruncatedText value={target} label={t('scanDetail.target.label')} />
          </Badge>
        ))}
      </div>
      {targets.length > 12 && (
        <Button variant="link" size="sm" className="h-auto p-0" onClick={() => setAll(!all)}>
          {all
            ? t('scanDetail.target.showFewer')
            : t('scanDetail.target.showAll', 'Show all {count}', { count: targets.length })}
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
  // The run history is an embedded list; its page and size live in the URL
  // (a reload or a shared link keeps them), and "View all runs" opens the
  // Runs list filtered to this scan.
  const runList = useListParams({ pageSizes: RUN_PAGE_SIZES, defaultPageSize: 25 })
  const runPage = runList.page
  const runPerPage = runList.perPage

  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [editOpen, setEditOpen] = useState(false)
  const [cloneOpen, setCloneOpen] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [stoppingRunId, setStoppingRunId] = useState<string | null>(null)
  const [pendingStop, setPendingStop] = useState<ScanRun | null>(null)
  const { t } = useTranslation()
  const [openRunId, setOpenRunId] = useState<string | null>(null)

  const { data: config, isLoading, error, mutate: refetchConfig } = useScanConfig(scanId)
  useBreadcrumbTitle(config?.name)

  // The latest runs, for the numbers above the tabs (runs still in progress
  // are the newest), whichever history page is open.
  // A live run's change notices (run:{id}) refresh both lists; they poll
  // every 10 s only while a run is live and its notices cannot arrive (socket
  // down), and every 2 min otherwise, to notice a run a schedule or someone
  // else starts.
  const [liveIds, setLiveIds] = useState<string[]>([])
  const { mutate: mutateCache } = useSWRConfig()
  const runsPrefix = scanId ? `/api/v1/scans/${scanId}/runs` : ''
  const configKey = scanId ? scanEndpoints.get(scanId) : ''
  // The config key holds the run counters and the next run: refresh it with
  // the runs, or the strip keeps the numbers from before the run.
  const refreshScan = () =>
    void mutateCache(
      (key) => typeof key === 'string' && (key === configKey || key.startsWith(runsPrefix))
    )
  const realtime = useRunChannels(liveIds, refreshScan)
  // History page 1 (25 or more runs) already holds the 10 newest runs, so
  // the latest runs are read from it: one request on load. Only a later
  // page needs its own request for the numbers above the tabs.
  const onFirstPage = runPage === 1
  const { data: otherLatest, mutate: refetchOtherLatest } = useScanRuns(
    onFirstPage ? null : scanId,
    1,
    10,
    {
      refreshInterval: runListRefreshInterval(10000, IDLE_RUN_LIST_REFRESH_MS, realtime),
      onSuccess: (page) => setLiveIds(liveRunIds(page?.data)),
    }
  )
  const otherLive = (otherLatest?.data ?? []).some(isRunInProgress)
  const {
    data: runsResponse,
    isLoading: isLoadingRuns,
    mutate: refetchRuns,
  } = useScanRuns(scanId, runPage, runPerPage, {
    refreshInterval: onFirstPage
      ? runListRefreshInterval(10000, IDLE_RUN_LIST_REFRESH_MS, realtime)
      : otherLive && !realtime
        ? 10000
        : 0,
    keepPreviousData: true,
    onSuccess: (page) => {
      if (onFirstPage) setLiveIds(liveRunIds(page?.data))
    },
  })
  const latestRuns = onFirstPage ? runsResponse : otherLatest
  const latestLive = (latestRuns?.data ?? []).some(isRunInProgress)
  // A run that finishes (noticed by polling when the socket is down) changes
  // the config's counters and status: refetch it on the live to idle edge.
  const wasLive = useRef(false)
  useEffect(() => {
    if (wasLive.current && !latestLive) void refetchConfig()
    wasLive.current = latestLive
  }, [latestLive, refetchConfig])
  const runs = useMemo(() => runsResponse?.data ?? [], [runsResponse])
  const refetchAll = () =>
    Promise.all([onFirstPage ? undefined : refetchOtherLatest(), refetchRuns(), refetchConfig()])

  // The scan's run counts come from its runs (the total includes runs in
  // progress). Success rate is null before any run settled.
  const counts = useMemo(
    () => (config ? scanRunCounts(config, latestRuns?.data ?? []) : null),
    [config, latestRuns]
  )
  const activeRun = (latestRuns?.data ?? []).find(isRunInProgress)

  const handleStopRun = async (run: ScanRun) => {
    setStoppingRunId(run.id)
    try {
      await post(scanRunEndpoints.cancel(run.id), {})
      toast.success(t('scanDetail.cancel.done'))
      setPendingStop(null)
      await refetchAll()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scanDetail.cancel.failed')))
    } finally {
      setStoppingRunId(null)
    }
  }

  const handleDeleteConfig = async () => {
    if (!config) return
    setIsDeleting(true)
    try {
      await del(scanEndpoints.delete(config.id))
      toast.success(t('scanDetail.delete.done', 'Scan "{name}" deleted', { name: config.name }))
      router.push('/scans')
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('scanDetail.delete.failed', 'Failed to delete scan "{name}"', { name: config.name })
        )
      )
    } finally {
      setIsDeleting(false)
      setDeleteConfirmOpen(false)
    }
  }

  // Rebuilt each render: the cancel action reads the in-flight run id. No
  // column sorts: this endpoint lists newest first, and sorting one page of
  // the history would misrepresent the rest.
  const runColumns: ColumnDef<ScanRun>[] = [
    {
      id: 'started',
      header: t('scanDetail.runs.col.started'),
      enableSorting: false,
      cell: ({ row }) => (
        <span className="font-medium">
          {formatScanDate(row.original.started_at || row.original.created_at)}
        </span>
      ),
    },
    {
      id: 'status',
      header: t('scanDetail.runs.col.status'),
      enableSorting: false,
      cell: ({ row }) => (
        <div className="space-y-0.5">
          <RunStatusBadge status={row.original.status} note={runTargetNote(row.original, t)} />
          {row.original.error_message && (
            <TruncatedText
              value={row.original.error_message}
              label={t('scanDetail.runs.message')}
              className="max-w-[240px] text-xs text-muted-foreground"
            />
          )}
        </div>
      ),
    },
    {
      id: 'trigger',
      header: t('scanDetail.runs.col.trigger'),
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex flex-col">
          {row.original.trigger?.type === 'policy' ? (
            // A platform policy's run: "Automatic coverage", not the
            // trigger type word "System".
            <span>{runTriggeredByLabel(row.original, t)}</span>
          ) : (
            <>
              <span>
                {SCAN_RUN_TRIGGER_LABELS[row.original.trigger_type as ScanWorkflowTriggerType] ??
                  row.original.trigger_type}
              </span>
              {runTriggeredByLabel(row.original, t) && (
                <span className="text-xs text-muted-foreground">
                  {runTriggeredByLabel(row.original, t)}
                </span>
              )}
            </>
          )}
        </div>
      ),
    },
    {
      id: 'tasks',
      header: t('scanDetail.runs.col.tasks'),
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original
        const progress = runTaskProgress(r.task_summary)
        return (
          <span className="tabular-nums">
            {progress
              ? progress.label
              : t('scanDetail.runs.steps', '{done}/{total} steps', {
                  done: r.completed_steps,
                  total: r.total_steps,
                })}
          </span>
        )
      },
    },
    {
      id: 'findings',
      header: t('scanDetail.runs.col.findings'),
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
      header: t('scanDetail.runs.col.duration'),
      enableSorting: false,
      cell: ({ row }) => (
        <span className="tabular-nums text-muted-foreground">{runDuration(row.original, t)}</span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => {
        const run = row.original
        if (!isRunInProgress(run)) return null
        return (
          // POST /scan-runs/{id}/cancel needs scans:write (D12).
          <Can permission={Permission.ScansWrite}>
            <Button
              size="sm"
              variant="ghost"
              disabled={stoppingRunId === run.id}
              onClick={() => setPendingStop(run)}
              aria-label={t('scanDetail.cancel.aria', 'Cancel run started {when}', {
                when: formatScanDate(run.started_at || run.created_at),
              })}
            >
              {stoppingRunId === run.id ? (
                <RefreshCw className="me-1 h-4 w-4 animate-spin motion-reduce:animate-none" />
              ) : (
                <XCircle className="me-1 h-4 w-4" />
              )}
              {t('scanDetail.cancel.action')}
            </Button>
          </Can>
        )
      },
    },
  ]

  if (isLoading) {
    return (
      <Main>
        <div className="space-y-5" aria-busy="true" aria-label={t('scanDetail.loading')}>
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-[400px] w-full" />
        </div>
      </Main>
    )
  }

  const status = (error as { statusCode?: number } | undefined)?.statusCode
  if (error && status !== 404 && !config) {
    // A refusal, a 500 or a lost connection is not "not found": say what
    // happened and let the person retry.
    return (
      <Main>
        <PageHeader title={t('scanDetail.error.title')} />
        <div className="mt-5">
          <ErrorState
            title={t('scanDetail.error.title')}
            error={error}
            onRetry={() => void refetchConfig()}
          />
        </div>
      </Main>
    )
  }

  if (status === 404 || !config) {
    return (
      <Main>
        <PageHeader title={t('scanDetail.notFound.title')} />
        <div className="mt-5 flex flex-col items-start gap-4">
          <p className="text-sm text-muted-foreground">{t('scanDetail.notFound.desc')}</p>
          <Button asChild variant="outline" size="sm">
            <Link href="/scans">
              <ArrowLeft className="me-2 h-4 w-4" />
              {t('scanDetail.notFound.back')}
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
  // A platform policy owns the scan: read-only here, listed as System.
  const managed = isManagedScan(config)

  const metrics: MetricStripItem[] = [
    {
      key: 'runs',
      label: t('scanDetail.metric.runs'),
      value: counts?.total ?? config.total_runs,
      hint:
        counts && counts.inProgress > 0
          ? t('scanDetail.metric.inProgress', '{count} in progress', { count: counts.inProgress })
          : undefined,
    },
    {
      key: 'rate',
      label: t('scans.list.successRate'),
      // A rate needs a settled run: "n/a", never a red 0%.
      value: rate === null ? t('scans.list.notAvailable') : `${rate}%`,
      hint: rate === null ? t('scans.list.noFinishedRun') : undefined,
    },
    { key: 'ok', label: t('scanDetail.metric.successful'), value: config.successful_runs },
    {
      key: 'partial',
      label: t('scanDetail.metric.partial'),
      value: config.partial_runs ?? 0,
      tone: 'warning',
    },
    {
      key: 'failed',
      label: t('scanDetail.metric.failed'),
      value: config.failed_runs,
      tone: 'danger',
    },
    {
      key: 'next',
      label: t('scanDetail.metric.nextRun'),
      value: config.next_run_at ? formatScanDate(config.next_run_at) : '-',
      hint: managed
        ? undefined
        : config.status === 'paused' && config.next_run_at
          ? t('scanDetail.metric.ifResumed')
          : config.schedule_type === 'manual'
            ? t('scanDetail.metric.manualOnly')
            : undefined,
    },
  ]

  return (
    <Main>
      <PageHeader
        title={config.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <LastRunCell run={lastRunOf(config)} onOpen={setOpenRunId} />
            <span>{scanTypeLabel(config).label}</span>
            <span aria-hidden="true">·</span>
            {managed ? (
              <>
                <Badge variant="secondary">{t('scans.managed.system')}</Badge>
                <span>{managedScanLabel(config, t)}</span>
              </>
            ) : (
              <>
                <span>{SCHEDULE_TYPE_LABELS[config.schedule_type]}</span>
                <span aria-hidden="true">·</span>
                <span>{scanStateLabel(config)}</span>
              </>
            )}
            {activeRun && (
              <Button
                variant="link"
                size="sm"
                className="h-auto p-0"
                onClick={() => setOpenRunId(activeRun.id)}
              >
                <RefreshCw className="me-1 h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />
                {t('scanDetail.run.inProgress')}
              </Button>
            )}
          </span>
        }
      >
        {/* Run now, schedule on/off, enable: the same controls as the scan
            drawer, gated as the API gates them. */}
        {!managed && (
          <ScanControls
            config={config}
            onViewRun={setOpenRunId}
            onChanged={() => void refetchAll()}
          />
        )}
        <Can permission={Permission.ScansWrite}>
          {!managed && (
            <Button variant="outline" onClick={() => setEditOpen(true)}>
              <Pencil className="me-2 h-4 w-4" />
              {t('scans.page.edit')}
            </Button>
          )}
          <Button variant="outline" onClick={() => setCloneOpen(true)}>
            <Copy className="me-2 h-4 w-4" />
            {managed ? t('scans.managed.clone') : t('scans.page.clone')}
          </Button>
        </Can>
      </PageHeader>

      <EditScanDialog
        scanConfig={config}
        open={editOpen}
        onOpenChange={setEditOpen}
        onSuccess={() => void refetchConfig()}
      />
      <CloneScanDialog
        scan={config}
        open={cloneOpen}
        onOpenChange={setCloneOpen}
        onSuccess={(copy) => router.push(`/scans/${copy.id}`)}
      />

      <MetricStrip className="mt-5" items={metrics} />

      {managed ? (
        <div className="mt-5">
          <ManagedScanBanner config={config} />
        </div>
      ) : (
        <>
          <div className="mt-5 empty:hidden">
            <ScanOwnerBanner config={config} onChanged={() => void refetchConfig()} />
          </div>

          <div className="mt-5 empty:hidden">
            <LivenessHint config={config} onChanged={() => void refetchConfig()} />
          </div>

          <div className="mt-5 empty:hidden">
            <ScanApprovalPanel scanId={config.id} onRan={() => void refetchAll()} />
          </div>
        </>
      )}

      <Tabs value={tab} onValueChange={setTabParam} className="mt-5">
        <TabsList>
          <TabsTrigger value="runs">{t('scanDetail.tab.runs')}</TabsTrigger>
          <TabsTrigger value="configuration">{t('scanDetail.tab.configuration')}</TabsTrigger>
          <TabsTrigger value="details">{t('scanDetail.tab.details')}</TabsTrigger>
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
            pagination={runList.pagination}
            onPaginationChange={runList.setPagination}
            pageSize={runPerPage}
            pageSizeOptions={RUN_PAGE_SIZES}
            paginationNoun={t('scanDetail.runs.noun')}
            emptyMessage={t('scanDetail.runs.emptyTitle')}
            emptyDescription={t('scanDetail.runs.emptyDesc')}
            toolbarEnd={
              <Button variant="outline" size="sm" className="h-9" asChild>
                <Link href={`/scans/runs?scan_id=${encodeURIComponent(scanId)}`}>
                  {t('scanDetail.runs.viewAll')}
                </Link>
              </Button>
            }
          />
        </TabsContent>

        <TabsContent value="configuration" className="mt-5">
          <DetailSections>
            <DetailSection title={t('scanDetail.cfg.schedule')}>
              <DetailFieldGrid>
                <DetailField label={t('scanDetail.cfg.frequency')}>
                  {SCHEDULE_TYPE_LABELS[config.schedule_type]}
                </DetailField>
                {config.schedule_time && (
                  <DetailField label={t('scanDetail.cfg.time')}>{config.schedule_time}</DetailField>
                )}
                <DetailField label={t('scanDetail.cfg.timezone')}>
                  {config.schedule_timezone}
                </DetailField>
                {config.next_run_at && (
                  <DetailField label={t('scanDetail.cfg.nextRun')}>
                    {formatScanDate(config.next_run_at)}
                  </DetailField>
                )}
                {config.schedule_rrule && (
                  <DetailField label={t('scanDetail.cfg.rule')} full>
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
            <DetailSection title={t('scanDetail.cfg.execution')}>
              <DetailFieldGrid>
                <DetailField label={t('scanDetail.cfg.scanType')}>
                  {SCAN_TYPE_LABELS[config.scan_type]}
                </DetailField>
                <DetailField label={<IntensityLabel />}>
                  <IntensityBadge intensity={config.intensity} />
                </DetailField>
                <DetailField label={t('scanDetail.cfg.sensorPreference')}>
                  {t(`scans.sensorPrefRun.${config.sensor_preference || 'auto'}.label`)}
                </DetailField>
                <DetailField label={t('scanDetail.cfg.targetsPerJob')}>
                  {config.targets_per_job}
                </DetailField>
              </DetailFieldGrid>
            </DetailSection>
            {(groupIds.length > 0 || targets.length > 0) && (
              <DetailSection title={t('scanDetail.cfg.assetGroupsTitle')}>
                <DetailFieldGrid>
                  {groupIds.length > 0 && (
                    <DetailField
                      label={
                        groupIds.length === 1
                          ? t('scanDetail.asset.group')
                          : t('scanDetail.asset.groups')
                      }
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
                    <DetailField
                      label={t('scanDetail.cfg.directTargets', 'Direct targets ({count})', {
                        count: targets.length,
                      })}
                      full
                    >
                      <TargetList targets={targets} />
                    </DetailField>
                  )}
                </DetailFieldGrid>
              </DetailSection>
            )}
            {config.tags && config.tags.length > 0 && (
              <DetailSection title={t('scanDetail.cfg.tags')} count={config.tags.length}>
                <div className="flex flex-wrap gap-1.5">
                  {config.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="max-w-[16rem] gap-1">
                      <Tag className="h-3 w-3 shrink-0" />
                      <TruncatedText value={tag} label={t('scanDetail.cfg.tag')} />
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
              <DetailSection title={t('scanDetail.details.description')}>
                <p
                  dir="auto"
                  className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground [unicode-bidi:isolate]"
                >
                  {config.description}
                </p>
              </DetailSection>
            )}
            <DetailSection title={t('scanDetail.details.timeline')}>
              <DetailFieldGrid>
                <DetailField label={t('scanDetail.details.created')}>
                  {formatScanDate(config.created_at)}
                </DetailField>
                <DetailField label={t('scanDetail.details.lastRun')}>
                  {config.last_run_at
                    ? formatScanDate(config.last_run_at)
                    : t('scanDetail.details.never')}
                </DetailField>
                <DetailField label={t('scanDetail.details.status')}>
                  {SCAN_CONFIG_STATUS_LABELS[config.status]}
                </DetailField>
              </DetailFieldGrid>
            </DetailSection>
            <DetailSection title={t('scanDetail.details.identity')}>
              <DetailFieldGrid>
                <DetailField label={t('scanDetail.details.createdBy')}>
                  {config.created_by_name || t('scanDetail.details.system')}
                </DetailField>
                <DetailField label={t('scanDetail.details.scanId')} full>
                  <DetailCopyId id={config.id} label={t('scanDetail.details.scanId')} />
                </DetailField>
                {config.scan_workflow_id && (
                  <DetailField label={t('scanDetail.details.workflow')} full>
                    <div className="flex flex-wrap items-center gap-2">
                      <Can permission={Permission.ScanWorkflowsRead}>
                        <Link
                          href={`/scans/workflows/${encodeURIComponent(config.scan_workflow_id)}`}
                          className="text-primary text-sm font-medium hover:underline"
                        >
                          {t('scanDetail.details.openWorkflow')}
                        </Link>
                      </Can>
                      <DetailCopyId
                        id={config.scan_workflow_id}
                        label={t('scanDetail.details.workflowId')}
                      />
                    </div>
                  </DetailField>
                )}
              </DetailFieldGrid>
            </DetailSection>
            <Can permission={Permission.ScansDelete}>
              {managed ? null : (
                <DangerZone>
                  <DangerZoneItem
                    title={t('scanDetail.danger.action')}
                    description={t('scanDetail.danger.desc')}
                    action={
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setDeleteConfirmOpen(true)}
                        disabled={isDeleting}
                      >
                        <Trash2 className="me-2 h-4 w-4" />
                        {t('scanDetail.danger.action')}
                      </Button>
                    }
                  />
                </DangerZone>
              )}
            </Can>
          </DetailSections>
        </TabsContent>
      </Tabs>

      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={setDeleteConfirmOpen}
        title={t('confirm.scan.deleteTitle', 'Delete scan "{name}"?', { name: config.name })}
        desc={
          <>
            <span className="flex items-center gap-1.5 font-medium text-foreground">
              <AlertTriangle className="h-4 w-4 text-destructive" aria-hidden="true" />
              {config.name}
            </span>
            {t(
              'confirm.scan.deleteDesc',
              'The scan and its schedule are deleted. Past runs and findings stay. This cannot be undone.'
            )}
          </>
        }
        confirmText={isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.scan.deleteBtn')}
        destructive
        isLoading={isDeleting}
        typeToConfirm={confirmName(config.name, config.id)}
        handleConfirm={handleDeleteConfig}
      />
      <ConfirmDialog
        open={pendingStop !== null}
        onOpenChange={(open) => !open && !stoppingRunId && setPendingStop(null)}
        destructive
        title={t('confirm.scan.cancelRunTitle', 'Cancel this run of "{name}"?', {
          name: config.name,
        })}
        desc={t(
          'confirm.scan.cancelRunDesc',
          'No new tasks start and running tasks stop at their next heartbeat. Results already received stay. A canceled run cannot be resumed; start a new run instead.'
        )}
        cancelBtnText={t('confirm.keepRunning', 'Keep running')}
        confirmText={t('confirm.scan.cancelRun', 'Cancel run')}
        isLoading={stoppingRunId !== null}
        handleConfirm={() => (pendingStop ? handleStopRun(pendingStop) : undefined)}
      />
      <RunDetailSheet runId={openRunId} onOpenChange={(o) => !o && setOpenRunId(null)} />
    </Main>
  )
}
