'use client'

/**
 * A CI pipeline's drawer (api RFC-051 §10): its status in three dimensions
 * (freshness, default-branch gate, execution health), its runs (paged), its
 * branches and its gate trend. A pipeline is created by a verified token
 * exchange and revoked with its trust configuration; an administrator can
 * retire it, which closes the findings only it reported (audited).
 */

import { useId, useState } from 'react'
import Link from '@/components/link'
import { Archive, GitBranch, Settings2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import {
  DataTable,
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  DetailTabs,
  EmptyState,
  ErrorState,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { ProviderIcon } from '@/features/scm-connections'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import { Permission, usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import type { ColumnDef } from '@tanstack/react-table'

import { useCIPipeline, useCIRuns, useRetirePipeline } from '../api/use-ci'
import { validRetireReason } from '../lib/coverage'
import { PROVIDER_LABEL, shortSHA } from '../lib/ci'
import { FRESHNESS_LABEL, HEALTH_REASON_LABEL, cadenceLabel, workflowFile } from '../lib/pipeline'
import type { CIPipelineDetail, CIRun } from '../types'
import { FleetModeBadge, GateLabel, PipelineStatusBadge } from './ci-pipeline-cells'
import { CIRunSheet, VerdictBadge } from './ci-runs-view'

type PipelineTab = 'overview' | 'runs' | 'branches'
const TABS: { value: PipelineTab; label: string }[] = [
  { value: 'overview', label: 'Overview' },
  { value: 'runs', label: 'Runs' },
  { value: 'branches', label: 'Branches' },
]

/** The default-branch verdicts, oldest to newest, as small squares. */
export function GateTrend({ points }: { points: CIPipelineDetail['gate_trend'] }) {
  const list = [...(points ?? [])].reverse()
  if (list.length === 0) {
    return <p className="text-sm text-muted-foreground">No default-branch verdict yet.</p>
  }
  const fails = list.filter((p) => p.verdict === 'fail').length
  return (
    <div>
      <div
        role="img"
        aria-label={`${list.length} default-branch verdicts, ${fails} failed`}
        className="flex flex-wrap gap-1"
      >
        {list.map((p) => (
          <span
            key={p.run_id}
            title={`${p.verdict} · ${shortSHA(p.commit_sha)} · ${p.evaluated_at ? new Date(p.evaluated_at).toLocaleString() : ''}`}
            className={cn(
              'size-3 rounded-sm',
              p.verdict === 'fail' ? 'bg-destructive' : 'bg-success'
            )}
          />
        ))}
      </div>
      <p className="mt-1.5 text-xs text-muted-foreground">
        Last {list.length} default-branch runs, oldest first: {list.length - fails} passed, {fails}{' '}
        failed.
      </p>
    </div>
  )
}

function Overview({ p }: { p: CIPipelineDetail }) {
  const reasons = p.health_reasons ?? []
  const cadence = cadenceLabel(p.schedule_interval_seconds || p.median_interval_seconds)
  return (
    <div className="space-y-5">
      {p.status === 'retired' && (
        <DetailCallout tone="info" title="Retired">
          An administrator retired it and the findings only it reported were closed as source
          retired; each can be reopened. The next run brings it back.
        </DetailCallout>
      )}
      {p.status === 'revoked' && (
        <DetailCallout tone="warning" title="Revoked">
          Its trust configuration was disabled, deleted or pointed elsewhere, and its running jobs
          lost their upload tokens. The next run a trust configuration admits brings it back.
        </DetailCallout>
      )}
      {reasons.length > 0 && (
        <DetailCallout tone="warning" title="Execution issues">
          {reasons.map((r) => HEALTH_REASON_LABEL[r] ?? r).join('; ')}.
        </DetailCallout>
      )}
      <DetailStatGrid aria-label="Key numbers">
        <DetailStat
          label="Last run"
          value={p.last_run_at ? <RelativeTime date={p.last_run_at} className="text-base" /> : '—'}
          caption={FRESHNESS_LABEL[p.freshness ?? ''] ?? p.freshness}
        />
        <DetailStat
          label="Expected"
          value={cadence ?? '—'}
          caption={
            p.scheduled
              ? 'from its schedule; stale after two missed runs'
              : 'stale after three usual intervals (7 to 30 days)'
          }
        />
        <DetailStat
          label="Runs"
          value={(p.runs_count ?? 0).toLocaleString()}
          caption={p.last_fork_run_at ? 'own runs; fork runs are not counted' : 'on every branch'}
        />
      </DetailStatGrid>

      <DetailSection title="Default-branch gate">
        <div className="mb-2 flex items-center gap-2 text-sm">
          <GateLabel gate={p.gate} />
          {p.pr_gate && p.pr_gate !== 'none' && (
            <span className="text-muted-foreground">
              · pull requests: <GateLabel gate={p.pr_gate} className="text-xs" />
            </span>
          )}
        </div>
        <GateTrend points={p.gate_trend} />
      </DetailSection>

      <DetailSection title="Identity">
        <DetailFieldGrid>
          <DetailField label="Provider">
            <span className="inline-flex items-center gap-1.5">
              <ProviderIcon provider={p.provider ?? ''} />
              {PROVIDER_LABEL[p.provider ?? ''] ?? p.provider}
            </span>
          </DetailField>
          <DetailField label="Workflow">
            <span className="font-mono text-xs">{p.workflow_path}</span>
          </DetailField>
          {p.workflow_name && <DetailField label="Name">{p.workflow_name}</DetailField>}
          <DetailField label="Default branch">{p.default_branch || '—'}</DetailField>
          <DetailField label="Runner version">
            {p.sensor_version || '—'}
            {p.version_status === 'unsupported' && (
              <span className="ms-1 text-warning">below the minimum</span>
            )}
          </DetailField>
          <DetailField label="Tools">
            {(p.tools ?? []).length > 0
              ? (p.tools ?? [])
                  .map((t) => (t.version ? `${t.name} ${t.version}` : t.name))
                  .join(', ')
              : '—'}
          </DetailField>
          {p.template_ref && (
            <DetailField label="Template" full>
              <span className="break-all font-mono text-xs">{p.template_ref}</span>
            </DetailField>
          )}
          <DetailField label="Repository" full>
            <Link
              href={assetDetailHref(p.repository_asset_id ?? '')}
              className="text-primary hover:underline"
            >
              {p.repository}
            </Link>
          </DetailField>
          {p.legacy && (
            <DetailField label="Identity" full>
              Recorded before pipelines existed; its next run confirms its repository id.
            </DetailField>
          )}
        </DetailFieldGrid>
      </DetailSection>
    </div>
  )
}

function Runs({ pipelineId }: { pipelineId: string }) {
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 10 })
  const [run, setRun] = useState<string | null>(null)
  const { data, error, isLoading } = useCIRuns({
    pipelineId,
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  })
  const columns: ColumnDef<CIRun>[] = [
    {
      id: 'ref',
      header: 'Branch',
      cell: ({ row }) => (
        <StackedCell
          truncate
          primary={
            <span className="inline-flex items-center gap-1">
              <GitBranch className="size-3.5 shrink-0" aria-hidden />
              {row.original.branch || row.original.ref}
              {row.original.pull_request && (
                <span className="text-muted-foreground">#{row.original.pull_request}</span>
              )}
            </span>
          }
          secondary={
            <span className="font-mono">
              {shortSHA(row.original.commit_sha)}
              {row.original.fork ? ' · fork' : ''}
            </span>
          }
        />
      ),
    },
    {
      id: 'verdict',
      header: 'Verdict',
      cell: ({ row }) => <VerdictBadge verdict={row.original.verdict} />,
    },
    {
      id: 'started',
      header: 'Started',
      cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
    },
  ]
  if (error) return <ErrorState title="runs" error={error} />
  return (
    <>
      <DataTable
        columns={columns}
        data={data?.data ?? []}
        isLoading={isLoading}
        manualPagination
        pageCount={data?.total_pages ?? 1}
        rowCount={data?.total ?? 0}
        pagination={pagination}
        onPaginationChange={setPagination}
        getRowId={(r) => r.id ?? ''}
        onRowClick={(r) => setRun(r.id ?? null)}
        showSearch={false}
        showColumnToggle={false}
        pageSizeOptions={[10, 25, 50]}
        paginationNoun="runs"
        emptyMessage="No runs yet"
      />
      <CIRunSheet id={run} onClose={() => setRun(null)} />
    </>
  )
}

function Branches({ p }: { p: CIPipelineDetail }) {
  const branches = p.branches ?? []
  if (branches.length === 0) {
    return (
      <EmptyState
        icon={GitBranch}
        title="No branches yet"
        description="Branches show up after the pipeline runs."
        card={false}
      />
    )
  }
  return (
    <ul className="divide-y rounded-lg border" aria-label="Branches">
      {branches.map((b) => (
        <li key={b.branch} className="flex items-center justify-between gap-3 px-3 py-2.5 text-sm">
          <StackedCell
            truncate
            primary={
              <span>
                {b.branch || '(tag)'}
                {b.is_default_branch && (
                  <span className="ms-1.5 text-xs text-muted-foreground">default</span>
                )}
              </span>
            }
            secondary={`${b.runs} ${b.runs === 1 ? 'run' : 'runs'}`}
          />
          <span className="flex shrink-0 items-center gap-3">
            {b.last_verdict && <VerdictBadge verdict={b.last_verdict} />}
            <RelativeTime date={b.last_run_at} className="text-xs" />
          </span>
        </li>
      ))}
    </ul>
  )
}

/**
 * Retire a pipeline: it is hidden as retired and the open findings only it
 * reported close as "source retired". A reason is required (audited).
 */
export function RetirePipelineDialog({
  pipelineId,
  label,
  open,
  onOpenChange,
  onRetired,
}: {
  pipelineId: string
  label: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onRetired?: () => void
}) {
  const reasonId = useId()
  const [reason, setReason] = useState('')
  const { trigger, isMutating } = useRetirePipeline()
  const ok = validRetireReason(reason)
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (!o) setReason('')
        onOpenChange(o)
      }}
      destructive
      title="Retire this CI pipeline?"
      desc={`${label}: findings that only this pipeline reported and nothing else has seen since close as "source retired". Findings another source still sees are not touched. Each closed finding can be reopened, and the next run of the pipeline brings it back.`}
      confirmText="Retire pipeline"
      disabled={!ok}
      isLoading={isMutating}
      handleConfirm={async () => {
        try {
          const res = await trigger({ id: pipelineId, reason: reason.trim() })
          const n = res?.findings_closed ?? 0
          toast.success(
            `Pipeline retired; ${n} finding${n === 1 ? '' : 's'} closed as source retired`
          )
          setReason('')
          onOpenChange(false)
          onRetired?.()
        } catch (e) {
          toast.error(e instanceof Error ? e.message : 'Could not retire the pipeline')
        }
      }}
    >
      <div className="space-y-2">
        <Label htmlFor={reasonId}>Reason (recorded in the audit log)</Label>
        <Textarea
          id={reasonId}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="The workflow was removed; scanning moved to …"
          maxLength={2000}
          rows={3}
        />
        <p className="text-xs text-muted-foreground">10 to 2,000 characters.</p>
      </div>
    </ConfirmDialog>
  )
}

export function CIPipelineSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data: p, error, mutate } = useCIPipeline(id)
  const [tab, setTab] = useState<PipelineTab>('overview')
  const [retireOpen, setRetireOpen] = useState(false)
  const { can } = usePermissions()
  const canRetire = can(Permission.CIWrite) && !!p && p.status !== 'retired'
  const close = () => {
    setTab('overview')
    onClose()
  }
  return (
    <DetailSheet
      open={!!id}
      onOpenChange={(o) => !o && close()}
      panel={tab}
      header={
        <DetailHeader
          title={p?.repository ?? 'CI pipeline'}
          badges={
            p && (
              <>
                <PipelineStatusBadge status={p.status} />
                <FleetModeBadge mode="runner" />
              </>
            )
          }
          meta={
            p ? [PROVIDER_LABEL[p.provider ?? ''] ?? p.provider, workflowFile(p.workflow_path)] : []
          }
          onClose={close}
          actions={
            <>
              {canRetire && (
                <Button size="sm" variant="outline" onClick={() => setRetireOpen(true)}>
                  <Archive className="h-4 w-4" />
                  Retire
                </Button>
              )}
              <Button asChild size="sm" variant="outline">
                <Link href="/ci-cd?tab=setup">
                  <Settings2 className="h-4 w-4" />
                  CI trust and gate
                </Link>
              </Button>
            </>
          }
        />
      }
      tabs={<DetailTabs tabs={TABS} value={tab} onValueChange={setTab} />}
    >
      {error ? (
        <ErrorState title="the pipeline" error={error} />
      ) : !p ? (
        <div className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : tab === 'overview' ? (
        <Overview p={p} />
      ) : tab === 'runs' ? (
        <Runs pipelineId={p.id ?? ''} />
      ) : (
        <Branches p={p} />
      )}
      {p?.id && (
        <RetirePipelineDialog
          pipelineId={p.id}
          label={`${p.repository ?? ''} ${workflowFile(p.workflow_path)}`.trim()}
          open={retireOpen}
          onOpenChange={setRetireOpen}
          onRetired={() => void mutate()}
        />
      )}
    </DetailSheet>
  )
}
