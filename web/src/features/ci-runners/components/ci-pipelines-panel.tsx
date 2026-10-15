'use client'

/**
 * The CI/CD integration page (api RFC-051 §10), also the Sensors page's
 * Runner mode: CI pipelines, one per
 * workflow file of each repository, and their runs. A pipeline is fresh or
 * stale against its own cadence and never offline; archived, retired, revoked
 * and never-run pipelines are hidden until "Show inactive" (nothing is
 * deleted). The Coverage view lists repositories by capability. "Has
 * overrides" (?overrides=1) lists the pipelines whose repository has its own
 * gate settings.
 */

import { useMemo } from 'react'
import { Search, Workflow } from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  DataTable,
  EmptyState,
  ErrorState,
  MetricStrip,
  RelativeTime,
  SegmentedLens,
  StackedCell,
  type MetricStripItem,
} from '@/features/shared'
import { ProviderIcon } from '@/features/scm-connections'
import { useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { cn } from '@/lib/utils'

import { useCIPipelines } from '../api/use-ci'
import { PROVIDER_LABEL } from '../lib/ci'
import {
  INACTIVE_PIPELINE_STATUSES,
  isPipelineStatus,
  repositoryPath,
  workflowFile,
} from '../lib/pipeline'
import type { CIPipeline, CIPipelineStatus } from '../types'
import { GateLabel, PipelineStatusBadge } from './ci-pipeline-cells'
import { CIPipelineSheet } from './ci-pipeline-sheet'
import { CICoverageView } from './ci-coverage-view'
import { CIRunsView } from './ci-runs-view'
import { CISetupEntry } from './ci-setup-wizard'
import { Permission, usePermissions } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

type RunnerView = 'pipelines' | 'runs' | 'coverage'

const QUICK = {
  failing: ['failing'] as CIPipelineStatus[],
  attention: ['degraded', 'stale'] as CIPipelineStatus[],
}

function sameSet(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x) => b.includes(x))
}

type TFn = ReturnType<typeof useTranslation>['t']

export function pipelineColumns(t: TFn): ColumnDef<CIPipeline>[] {
  return [
    {
      id: 'repository',
      header: t('scans.ci.col.repository', 'Repository'),
      cell: ({ row }) => {
        const p = row.original
        return (
          <div className={cn('flex min-w-0 items-center gap-2', p.inactive && 'opacity-60')}>
            <span
              className="shrink-0 text-muted-foreground"
              title={PROVIDER_LABEL[p.provider ?? '']}
            >
              <ProviderIcon provider={p.provider ?? ''} />
              <span className="sr-only">{PROVIDER_LABEL[p.provider ?? ''] ?? p.provider}</span>
            </span>
            <StackedCell
              truncate
              primary={repositoryPath(p.repository)}
              secondary={p.workflow_name || workflowFile(p.workflow_path)}
            />
          </div>
        )
      },
    },
    {
      id: 'status',
      header: t('scans.ci.col.status', 'Status'),
      cell: ({ row }) => (
        <PipelineStatusBadge
          status={row.original.status}
          className={cn(row.original.inactive && 'opacity-60')}
        />
      ),
    },
    {
      id: 'last_run',
      header: t('scans.ci.col.lastRun', 'Last run'),
      cell: ({ row }) => (
        <RelativeTime
          date={row.original.last_run_at}
          className={cn(row.original.inactive && 'opacity-60')}
        />
      ),
    },
    {
      id: 'gate',
      header: t('scans.ci.col.defaultGate', 'Default-branch gate'),
      cell: ({ row }) => <GateLabel gate={row.original.gate} />,
    },
    {
      id: 'version',
      header: t('scans.ci.col.runner', 'Runner'),
      cell: ({ row }) => (
        <span
          className={cn(
            'text-sm tabular-nums',
            row.original.version_status === 'unsupported' ? 'text-warning' : 'text-muted-foreground'
          )}
        >
          {row.original.sensor_version || '—'}
        </span>
      ),
    },
  ]
}

export function CIPipelinesPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.CIWrite)
  const [viewParam, setView] = useUrlFilter('view', 'pipelines')
  const view: RunnerView =
    viewParam === 'runs' || viewParam === 'coverage' ? viewParam : 'pipelines'
  const [q, setQ] = useUrlFilter('q', '')
  const [statusParam, setStatusParam] = useUrlFilterList('pipeline_status')
  const [inactiveParam, setInactiveParam] = useUrlFilter('inactive', '')
  const [overridesParam, setOverridesParam] = useUrlFilter('overrides', '')
  const hasOverrides = overridesParam === '1'
  const [openId, setOpenId] = useUrlFilter('pipeline', '')
  const { pagination, setPagination, setPage } = useListParams({ defaultPageSize: 20 })

  const statuses = useMemo(() => statusParam.filter(isPipelineStatus), [statusParam])
  const includeInactive = inactiveParam === '1'
  const { data, error, isLoading, mutate } = useCIPipelines(
    {
      status: statuses,
      includeInactive,
      hasPolicyOverride: hasOverrides,
      search: q,
      page: pagination.pageIndex + 1,
      perPage: pagination.pageSize,
    },
    { enabled: view === 'pipelines' }
  )
  const counts = data?.counts ?? {}
  const n = (s: CIPipelineStatus) => counts[s] ?? 0
  const inactive = INACTIVE_PIPELINE_STATUSES.reduce((sum, s) => sum + n(s), 0)
  const active = Object.values(counts).reduce((a, b) => a + b, 0) - inactive

  const toggleStatuses = (next: CIPipelineStatus[]) => {
    setStatusParam(sameSet(statuses, next) ? [] : next)
    setPage(1)
  }
  const metrics: MetricStripItem[] = [
    {
      key: 'pipelines',
      label: t('scans.ci.metric.pipelines', 'CI pipelines'),
      value: active,
      hint: t('scans.ci.metric.active', 'active'),
      detail: t('scans.ci.metric.pipelinesDetail', 'one per workflow file of each repository'),
    },
    {
      key: 'fresh',
      label: t('scans.ci.metric.fresh', 'Fresh'),
      value: n('fresh') + n('running'),
      hint: t('scans.ci.metric.ofTotal', 'of {total}', { total: active }),
      detail:
        n('running') > 0
          ? t('scans.ci.metric.runningNow', '{count} running now', { count: n('running') })
          : t('scans.ci.metric.withinCadence', 'ran within their cadence'),
    },
    {
      key: 'failing',
      label: t('scans.ci.metric.failing', 'Failing gate'),
      value: n('failing'),
      tone: 'danger',
      detail: t('scans.ci.metric.failingDetail', 'last default-branch run failed'),
      onClick: () => toggleStatuses(QUICK.failing),
      active: sameSet(statuses, QUICK.failing),
    },
    {
      key: 'attention',
      label: t('scans.ci.metric.attention', 'Stale or degraded'),
      value: n('stale') + n('degraded'),
      tone: 'warning',
      detail: t('scans.ci.metric.attentionDetail', '{stale} stale · {degraded} degraded', {
        stale: n('stale'),
        degraded: n('degraded'),
      }),
      onClick: () => toggleStatuses(QUICK.attention),
      active: sameSet(statuses, QUICK.attention),
    },
    {
      key: 'inactive',
      label: t('scans.ci.metric.inactive', 'Inactive'),
      value: inactive,
      detail: t(
        'scans.ci.metric.inactiveDetail',
        'archived, retired, revoked or never ran; hidden, not deleted'
      ),
      onClick: () => {
        setInactiveParam(includeInactive ? '' : '1')
        setPage(1)
      },
      active: includeInactive,
    },
  ]

  const lens = (
    <SegmentedLens<RunnerView>
      label={t('scans.ci.view.label', 'Runner view')}
      value={view}
      onChange={(v) => {
        setView(v)
        setPage(1)
      }}
      options={[
        {
          value: 'pipelines',
          label: t('scans.ci.view.pipelines', 'Pipelines'),
          description: t('scans.ci.view.pipelinesHint', 'One row per workflow file'),
        },
        {
          value: 'runs',
          label: t('scans.ci.view.runs', 'Runs'),
          description: t('scans.ci.view.runsHint', 'Every run, newest first'),
        },
        {
          value: 'coverage',
          label: t('scans.ci.view.coverage', 'Coverage'),
          description: t(
            'scans.ci.view.coverageHint',
            'Repositories by capability: which are not being looked at'
          ),
        },
      ]}
    />
  )

  if (view === 'coverage') {
    return <CICoverageView toolbarStart={lens} />
  }

  if (view === 'runs') {
    return (
      <div className="mt-5">
        <CIRunsView embedded toolbarStart={lens} />
      </div>
    )
  }

  const empty = !isLoading && !error && active + inactive === 0 && !q && !hasOverrides
  return (
    <div className="mt-5 space-y-5">
      {!empty && <MetricStrip loading={isLoading && !data} items={metrics} />}
      {error ? (
        <ErrorState
          title={t('scans.ci.metric.pipelines', 'CI pipelines')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : empty ? (
        <>
          <div className="flex flex-wrap items-center gap-2">{lens}</div>
          <EmptyState
            icon={Workflow}
            title={
              canWrite
                ? t('scans.ci.noPipelinesTitle', 'No CI pipelines yet')
                : t('scans.ci.noPipelinesScopedTitle', 'No CI pipelines you can see')
            }
            description={
              canWrite
                ? t(
                    'scans.ci.noPipelines',
                    'A pipeline appears after its first run. Add a CI trust configuration, then add the OpenCTEM CI scan to a pipeline.'
                  )
                : t(
                    'scans.ci.noPipelinesScoped',
                    'A pipeline appears after its first run, and you see the pipelines of repositories you have access to. Ask an administrator to connect a pipeline or to give you access to a repository.'
                  )
            }
            action={canWrite ? <CISetupEntry canWrite /> : undefined}
          />
        </>
      ) : (
        <DataTable
          columns={pipelineColumns(t)}
          data={data?.data ?? []}
          isLoading={isLoading}
          manualPagination
          pageCount={data?.total_pages ?? 1}
          rowCount={data?.total ?? 0}
          pagination={pagination}
          onPaginationChange={setPagination}
          getRowId={(p) => p.id ?? ''}
          onRowClick={(p) => setOpenId(p.id ?? '')}
          showSearch={false}
          paginationNoun={t('scans.ci.noun.pipelines', 'pipelines')}
          emptyMessage={t('scans.ci.noPipelineMatches', 'No pipeline matches')}
          emptyDescription={
            hasOverrides
              ? t(
                  'scans.ci.noOverrides',
                  'No repository you can see overrides the gate settings. Turn off Has overrides to see every pipeline.'
                )
              : includeInactive
                ? undefined
                : t(
                    'scans.ci.inactiveHidden',
                    'Inactive pipelines are hidden: turn on Show inactive.'
                  )
          }
          toolbarStart={
            <>
              {lens}
              <div className="relative min-w-0 flex-1 sm:max-w-xs">
                <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder={t('scans.ci.searchPipelines', 'Search repository or workflow…')}
                  aria-label={t('scans.ci.searchPipelinesLabel', 'Search CI pipelines')}
                  value={q}
                  onChange={(e) => {
                    setQ(e.target.value)
                    setPage(1)
                  }}
                  className="h-9 ps-9"
                />
              </div>
            </>
          }
          toolbarEnd={
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <div className="flex items-center gap-2">
                <Switch
                  id="pipelines-overrides"
                  checked={hasOverrides}
                  onCheckedChange={(on) => {
                    setOverridesParam(on ? '1' : '')
                    setPage(1)
                  }}
                />
                <Label htmlFor="pipelines-overrides" className="text-sm font-normal">
                  {t('scans.ci.hasOverrides', 'Has overrides')}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  id="pipelines-inactive"
                  checked={includeInactive}
                  onCheckedChange={(on) => {
                    setInactiveParam(on ? '1' : '')
                    setPage(1)
                  }}
                />
                <Label htmlFor="pipelines-inactive" className="text-sm font-normal">
                  {t('scans.ci.showInactive', 'Show inactive')}
                </Label>
              </div>
            </div>
          }
        />
      )}
      <CIPipelineSheet id={openId || null} onClose={() => setOpenId('')} />
    </div>
  )
}
