'use client'

/**
 * The CI/CD integration page (api RFC-051 §10), also the Sensors page's
 * Runner mode: CI pipelines, one per
 * workflow file of each repository, and their runs. A pipeline is fresh or
 * stale against its own cadence and never offline; archived, retired, revoked
 * and never-run pipelines are hidden until "Show inactive" (nothing is
 * deleted). The Coverage view lists repositories by capability.
 */

import { useMemo } from 'react'
import Link from '@/components/link'
import { Search, Workflow } from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { Button } from '@/components/ui/button'
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

type RunnerView = 'pipelines' | 'runs' | 'coverage'

const QUICK = {
  failing: ['failing'] as CIPipelineStatus[],
  attention: ['degraded', 'stale'] as CIPipelineStatus[],
}

function sameSet(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x) => b.includes(x))
}

export function pipelineColumns(): ColumnDef<CIPipeline>[] {
  return [
    {
      id: 'repository',
      header: 'Repository',
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
      header: 'Status',
      cell: ({ row }) => (
        <PipelineStatusBadge
          status={row.original.status}
          className={cn(row.original.inactive && 'opacity-60')}
        />
      ),
    },
    {
      id: 'last_run',
      header: 'Last run',
      cell: ({ row }) => (
        <RelativeTime
          date={row.original.last_run_at}
          className={cn(row.original.inactive && 'opacity-60')}
        />
      ),
    },
    {
      id: 'gate',
      header: 'Default-branch gate',
      cell: ({ row }) => <GateLabel gate={row.original.gate} />,
    },
    {
      id: 'version',
      header: 'Runner',
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

export interface CIPipelinesPanelProps {
  /** Controls placed first in the toolbar (the page's mode switch). */
  toolbarStart?: React.ReactNode
}

export function CIPipelinesPanel({ toolbarStart }: CIPipelinesPanelProps) {
  const [viewParam, setView] = useUrlFilter('view', 'pipelines')
  const view: RunnerView =
    viewParam === 'runs' || viewParam === 'coverage' ? viewParam : 'pipelines'
  const [runParam] = useUrlFilter('run', '')
  const [q, setQ] = useUrlFilter('q', '')
  const [statusParam, setStatusParam] = useUrlFilterList('pipeline_status')
  const [inactiveParam, setInactiveParam] = useUrlFilter('inactive', '')
  const [openId, setOpenId] = useUrlFilter('pipeline', '')
  const { pagination, setPagination, setPage } = useListParams({ defaultPageSize: 20 })

  const statuses = useMemo(() => statusParam.filter(isPipelineStatus), [statusParam])
  const includeInactive = inactiveParam === '1'
  const { data, error, isLoading, mutate } = useCIPipelines(
    {
      status: statuses,
      includeInactive,
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
      label: 'CI pipelines',
      value: active,
      hint: 'active',
      detail: 'one per workflow file of each repository',
    },
    {
      key: 'fresh',
      label: 'Fresh',
      value: n('fresh') + n('running'),
      hint: `of ${active}`,
      detail: n('running') > 0 ? `${n('running')} running now` : 'ran within their cadence',
    },
    {
      key: 'failing',
      label: 'Failing gate',
      value: n('failing'),
      tone: 'danger',
      detail: 'last default-branch run failed',
      onClick: () => toggleStatuses(QUICK.failing),
      active: sameSet(statuses, QUICK.failing),
    },
    {
      key: 'attention',
      label: 'Stale or degraded',
      value: n('stale') + n('degraded'),
      tone: 'warning',
      detail: `${n('stale')} stale · ${n('degraded')} degraded`,
      onClick: () => toggleStatuses(QUICK.attention),
      active: sameSet(statuses, QUICK.attention),
    },
    {
      key: 'inactive',
      label: 'Inactive',
      value: inactive,
      detail: 'archived, retired, revoked or never ran; hidden, not deleted',
      onClick: () => {
        setInactiveParam(includeInactive ? '' : '1')
        setPage(1)
      },
      active: includeInactive,
    },
  ]

  const lens = (
    <SegmentedLens<RunnerView>
      label="Runner view"
      value={view}
      onChange={(v) => {
        setView(v)
        setPage(1)
      }}
      options={[
        { value: 'pipelines', label: 'Pipelines', description: 'One row per workflow file' },
        { value: 'runs', label: 'Runs', description: 'Every run, newest first' },
        {
          value: 'coverage',
          label: 'Coverage',
          description: 'Repositories by capability: which are not being looked at',
        },
      ]}
    />
  )

  if (view === 'coverage') {
    return (
      <CICoverageView
        toolbarStart={
          <>
            {toolbarStart}
            {lens}
          </>
        }
      />
    )
  }

  if (view === 'runs') {
    return (
      <div className="mt-5">
        <CIRunsView
          embedded
          initialRunId={runParam || null}
          toolbarStart={
            <>
              {toolbarStart}
              {lens}
            </>
          }
        />
      </div>
    )
  }

  const empty = !isLoading && !error && active + inactive === 0 && !q
  return (
    <div className="mt-5 space-y-5">
      {!empty && <MetricStrip loading={isLoading && !data} items={metrics} />}
      {error ? (
        <ErrorState title="CI pipelines" error={error} onRetry={() => mutate()} />
      ) : empty ? (
        <>
          <div className="flex flex-wrap items-center gap-2">
            {toolbarStart}
            {lens}
          </div>
          <EmptyState
            icon={Workflow}
            title="No CI pipelines yet"
            description="A CI pipeline shows up here after its first run: add a CI trust configuration, then run the sensor in a GitHub Actions or GitLab CI job. It proves who it is with the job's OIDC token, so no secret is stored in CI."
            action={
              <Button asChild size="sm">
                <Link href="/ci-cd?tab=setup">Set up CI trust</Link>
              </Button>
            }
          />
        </>
      ) : (
        <DataTable
          columns={pipelineColumns()}
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
          paginationNoun="pipelines"
          emptyMessage="No pipeline matches"
          emptyDescription={
            includeInactive ? undefined : 'Inactive pipelines are hidden: turn on Show inactive.'
          }
          toolbarStart={
            <>
              {toolbarStart}
              {lens}
              <div className="relative min-w-0 flex-1 sm:max-w-xs">
                <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search repository or workflow…"
                  aria-label="Search CI pipelines"
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
                Show inactive
              </Label>
            </div>
          }
        />
      )}
      <CIPipelineSheet id={openId || null} onClose={() => setOpenId('')} />
    </div>
  )
}
