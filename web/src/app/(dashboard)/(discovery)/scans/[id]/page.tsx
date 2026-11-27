'use client'

/**
 * One scan: the durable object of the Scans area, on the shared detail kit
 * (docs/ui-style-contract.md, "Detail pages"): the header with Run now, the
 * facts strip, a run in progress with Cancel run, then the tabs. The run
 * history is paged on the server; a run opens in the shared run drawer. The
 * numbers use the same formulas as the scan drawer (lib/format,
 * lib/run-display).
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import { useSWRConfig } from 'swr'
import type { ColumnDef } from '@tanstack/react-table'
import { useParams, useRouter } from 'next/navigation'
import Link from '@/components/link'
import { ScanRunMobileCard } from '@/features/scans/components/scan-run-mobile-card'
import { seenByFindingsHref } from '@/features/findings/api/receipts-api'
import { toast } from 'sonner'
import { AlertTriangle, ArrowLeft } from 'lucide-react'

import { Main, useBreadcrumbTitle } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { confirmName } from '@/lib/confirm-name'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  ErrorState,
  PageHeader,
  RunStatusBadge,
  TruncatedText,
  PageStack,
} from '@/features/shared'
import {
  LazyCloneScanDialog,
  LazyEditScanDialog,
  LazyRunDetailSheet,
} from '@/features/scans/components/lazy-dialogs'
import { ScanApprovalPanel } from '@/features/scans/components/approval/scan-approval-panel'
import { ScanOwnerBanner } from '@/features/scans/components/scan-owner-banner'
import { LivenessHint } from '@/features/scans/components/liveness-hint'
import { ScanPageHeader } from '@/features/scans/components/detail/scan-page-header'
import {
  ScanActiveRun,
  ScanFacts,
  scanRunsHref,
} from '@/features/scans/components/detail/scan-facts'
import {
  ScanConfigurationTab,
  ScanDetailsTab,
} from '@/features/scans/components/detail/scan-config-tabs'
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
  runTriggerTypeLabel,
  scanRunCounts,
} from '@/features/scans/lib/run-display'
import { isManagedScan, runMessage } from '@/features/scans/lib/scan-status'
import { ManagedScanBanner } from '@/features/scans/components/managed-scan-banner'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { useRunChannels } from '@/hooks/use-websocket'
import { del, post } from '@/lib/api/client'
import { scanRunEndpoints, scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useScanConfig, useScanRuns } from '@/lib/api/scan-hooks'
import { safeHref } from '@/lib/safe-href'
import type { ScanRun } from '@/lib/api/scan-types'

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
  const { t, locale } = useTranslation()
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
  // Memoized: SWR restarts its polling timer when the interval changes identity.
  const latestRunsInterval = useMemo(
    () => runListRefreshInterval(10000, IDLE_RUN_LIST_REFRESH_MS, realtime),
    [realtime]
  )
  const { data: otherLatest, mutate: refetchOtherLatest } = useScanRuns(
    onFirstPage ? null : scanId,
    1,
    10,
    {
      refreshInterval: latestRunsInterval,
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

  // Frame widths (px) under which a run column gives way, so the table fits
  // its frame instead of cutting a header: the trigger, the duration, then
  // the task count (all are on the run's sheet and the phone card).
  const RUN_HIDE_BELOW = { trigger: 1000, duration: 790, tasks: 670 } as const

  // Rebuilt each render: the cancel action reads the in-flight run id. No
  // column sorts: this endpoint lists newest first, and sorting one page of
  // the history would misrepresent the rest.
  const runColumns: ColumnDef<ScanRun>[] = [
    {
      id: 'started',
      header: t('scanDetail.runs.col.started'),
      // The row's name: when the run started (the phone card's title).
      meta: { kind: 'name' },
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
      meta: { kind: 'text', width: 260 },
      enableSorting: false,
      cell: ({ row }) => (
        <div className="space-y-0.5">
          <RunStatusBadge status={row.original.status} note={runTargetNote(row.original, t)} />
          {runMessage(row.original, t, locale) && (
            <TruncatedText
              value={runMessage(row.original, t, locale) ?? ''}
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
      meta: { kind: 'text', width: 200, hideBelow: RUN_HIDE_BELOW.trigger },
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex flex-col">
          {row.original.trigger?.type === 'policy' ? (
            // A platform policy's run: "Automatic coverage", not the
            // trigger type word "System".
            <span>{runTriggeredByLabel(row.original, t)}</span>
          ) : (
            <>
              <span>{runTriggerTypeLabel(row.original.trigger_type, t)}</span>
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
      meta: { kind: 'text', width: 120, hideBelow: RUN_HIDE_BELOW.tasks },
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
      meta: { kind: 'number' },
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
      meta: { kind: 'text', width: 120, hideBelow: RUN_HIDE_BELOW.duration },
      enableSorting: false,
      cell: ({ row }) => (
        <span className="tabular-nums text-muted-foreground">{runDuration(row.original, t)}</span>
      ),
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
        <PageStack>
          <PageHeader title={t('scanDetail.error.title')} />
          <div>
            <ErrorState
              title={t('scanDetail.error.title')}
              error={error}
              onRetry={() => void refetchConfig()}
            />
          </div>
        </PageStack>
      </Main>
    )
  }

  if (status === 404 || !config) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={t('scanDetail.notFound.title')} />
          <div className="flex flex-col items-start gap-4">
            <p className="text-sm text-muted-foreground">{t('scanDetail.notFound.desc')}</p>
            <Button asChild variant="outline" size="sm">
              <Link href="/scans">
                <ArrowLeft className="me-2 h-4 w-4" />
                {t('scanDetail.notFound.back')}
              </Link>
            </Button>
          </div>
        </PageStack>
      </Main>
    )
  }

  // A platform policy owns the scan: read-only here, listed as System.
  const managed = isManagedScan(config)
  const refresh = () => void refetchAll()

  return (
    <Main>
      <PageStack>
        <ScanPageHeader
          config={config}
          onViewRun={setOpenRunId}
          onChanged={refresh}
          onEdit={() => setEditOpen(true)}
          onClone={() => setCloneOpen(true)}
          onDelete={() => setDeleteConfirmOpen(true)}
        />

        <LazyEditScanDialog
          scanConfig={config}
          open={editOpen}
          onOpenChange={setEditOpen}
          onSuccess={() => void refetchConfig()}
        />
        <LazyCloneScanDialog
          scan={config}
          open={cloneOpen}
          onOpenChange={setCloneOpen}
          onSuccess={(copy) => router.push(`/scans/${copy.id}`)}
        />

        <ScanFacts config={config} counts={counts} onViewRun={setOpenRunId} onChanged={refresh} />

        {managed ? (
          <ManagedScanBanner config={config} />
        ) : (
          <>
            <ScanOwnerBanner config={config} onChanged={() => void refetchConfig()} />
            <LivenessHint config={config} onChanged={() => void refetchConfig()} />
            <ScanApprovalPanel scanId={config.id} onRan={refresh} />
          </>
        )}

        {activeRun && (
          <ScanActiveRun
            run={activeRun}
            stopping={stoppingRunId === activeRun.id}
            onOpen={() => setOpenRunId(activeRun.id)}
            onCancel={() => setPendingStop(activeRun)}
          />
        )}

        <Tabs value={tab} onValueChange={setTabParam} className="min-w-0">
          <TabsList>
            <TabsTrigger value="runs">
              {t('scanDetail.tab.runs')}
              <TabsCount value={counts?.total ?? config.total_runs} />
            </TabsTrigger>
            <TabsTrigger value="configuration">{t('scanDetail.tab.configuration')}</TabsTrigger>
            <TabsTrigger value="details">{t('scanDetail.tab.details')}</TabsTrigger>
          </TabsList>

          <TabsContent value="runs">
            <DataTable
              columns={runColumns}
              data={runs}
              getRowId={(run) => run.id}
              isLoading={isLoadingRuns && !runsResponse}
              showSearch={false}
              onRowClick={(run) => setOpenRunId(run.id)}
              // The runs tab's own card, titled by when the run started: the
              // requester wraps in full instead of being cut beside the trigger.
              mobileRow={(run, selection) => (
                <ScanRunMobileCard
                  run={run}
                  selection={selection}
                  onOpen={(r) => setOpenRunId(r.id)}
                  title={formatScanDate(run.started_at || run.created_at)}
                />
              )}
              manualPagination
              rowCount={runsResponse?.total ?? 0}
              pagination={runList.pagination}
              onPaginationChange={runList.setPagination}
              pageSize={runPerPage}
              pageSizeOptions={RUN_PAGE_SIZES}
              paginationNoun={t('scanDetail.runs.noun')}
              emptyMessage={t('scanDetail.runs.emptyTitle')}
              emptyDescription={t('scanDetail.runs.emptyDesc')}
            />
            <div className="mt-3 flex flex-wrap gap-2">
              <Button variant="outline" size="sm" asChild>
                <Link
                  href={seenByFindingsHref('seen_by_scan_id', scanId)}
                  data-testid="scan-reported-findings"
                >
                  {t('scanDetail.runs.reportedFindings', 'Findings this scan reported')}
                </Link>
              </Button>
              <Button variant="outline" size="sm" asChild>
                <Link href={safeHref(scanRunsHref(scanId)) ?? '/scans/runs'}>
                  {t('scanDetail.runs.viewAll')}
                </Link>
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="configuration">
            <ScanConfigurationTab config={config} />
          </TabsContent>

          <TabsContent value="details">
            <ScanDetailsTab config={config} />
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
          confirmText={
            isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.scan.deleteBtn')
          }
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
        <LazyRunDetailSheet runId={openRunId} onOpenChange={(o) => !o && setOpenRunId(null)} />
      </PageStack>
    </Main>
  )
}
