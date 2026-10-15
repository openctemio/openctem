'use client'

/**
 * A CI pipeline's drawer (api RFC-051 §10): its status in three dimensions
 * (freshness, default-branch gate, execution health), its runs (paged), its
 * branches and its gate trend. A pipeline is created by a verified token
 * exchange and revoked with its trust configuration; an administrator can
 * retire it, which closes the findings only it reported (audited). The
 * Settings tab shows the repository's gate settings and baseline
 * (ci-repo-settings.tsx). The open tab lives in the URL (?pipeline_tab=).
 */

import { useId, useState } from 'react'
import { useUrlFilter } from '@/hooks/use-url-param'
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
import { CIRunSheet, RunAttempt, VerdictBadge } from './ci-runs-view'
import { CIRepositorySettingsTab } from './ci-repo-settings'
import { runAttempts } from '../lib/gate-settings'
import { useTranslation } from '@/context/i18n-provider'

export type PipelineTab = 'overview' | 'runs' | 'branches' | 'settings'
export const PIPELINE_TABS: { value: PipelineTab; label: string }[] = [
  { value: 'overview', label: 'Overview' },
  { value: 'runs', label: 'Runs' },
  { value: 'branches', label: 'Branches' },
  { value: 'settings', label: 'Settings' },
]

/** The drawer tab a URL asks for; anything unknown is Overview. */
export function pipelineTab(raw: string): PipelineTab {
  return PIPELINE_TABS.some((x) => x.value === raw) ? (raw as PipelineTab) : 'overview'
}

/** Pipeline status label and description, translated (scans.ci.status.<status>.*). */
function useStatusText() {
  const { t } = useTranslation()
  return (status: string | undefined, part: 'label' | 'description', fallback: string) =>
    t(`scans.ci.status.${status ?? ''}.${part}`, fallback)
}

/** The default-branch verdicts, oldest to newest, as small squares. */
export function GateTrend({ points }: { points: CIPipelineDetail['gate_trend'] }) {
  const { t } = useTranslation()
  const list = [...(points ?? [])].reverse()
  if (list.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {t('scans.ci.sheet.noVerdict', 'No default-branch verdict yet.')}
      </p>
    )
  }
  const fails = list.filter((p) => p.verdict === 'fail').length
  return (
    <div>
      <div
        role="img"
        aria-label={t(
          'scans.ci.sheet.trendLabel',
          '{count} default-branch verdicts, {fails} failed',
          {
            count: list.length,
            fails,
          }
        )}
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
        {t(
          'scans.ci.sheet.trendSummary',
          'Last {count} default-branch runs, oldest first: {passed} passed, {fails} failed.',
          { count: list.length, passed: list.length - fails, fails }
        )}
      </p>
    </div>
  )
}

function Overview({ p }: { p: CIPipelineDetail }) {
  const { t } = useTranslation()
  const statusText = useStatusText()
  const reasons = p.health_reasons ?? []
  const cadence = cadenceLabel(p.schedule_interval_seconds || p.median_interval_seconds, t)
  return (
    <div className="space-y-5">
      {p.status === 'retired' && (
        <DetailCallout tone="info" title={statusText('retired', 'label', 'Retired')}>
          {t(
            'scans.ci.sheet.retired',
            'An administrator retired it and the findings only it reported were closed as source retired; each can be reopened. The next run brings it back.'
          )}
        </DetailCallout>
      )}
      {p.status === 'revoked' && (
        <DetailCallout tone="warning" title={statusText('revoked', 'label', 'Revoked')}>
          {t(
            'scans.ci.sheet.revoked',
            'Its trust configuration was disabled, deleted or pointed elsewhere, and its running jobs lost their upload tokens. The next run a trust configuration admits brings it back.'
          )}
        </DetailCallout>
      )}
      {reasons.length > 0 && (
        <DetailCallout tone="warning" title={t('scans.ci.sheet.issues', 'Execution issues')}>
          {reasons
            .map((r) =>
              HEALTH_REASON_LABEL[r] ? t(`scans.ci.health.${r}`, HEALTH_REASON_LABEL[r]) : r
            )
            .join('; ')}
          .
        </DetailCallout>
      )}
      <DetailStatGrid aria-label={t('scans.ci.sheet.keyNumbers', 'Key numbers')}>
        <DetailStat
          label={t('scans.ci.col.lastRun', 'Last run')}
          value={p.last_run_at ? <RelativeTime date={p.last_run_at} className="text-base" /> : '—'}
          caption={
            FRESHNESS_LABEL[p.freshness ?? '']
              ? statusText(p.freshness, 'label', FRESHNESS_LABEL[p.freshness ?? ''])
              : p.freshness
          }
        />
        <DetailStat
          label={t('scans.ci.coverage.expected', 'Expected')}
          value={cadence ?? '—'}
          caption={
            p.scheduled
              ? t('scans.ci.sheet.fromSchedule', 'from its schedule; stale after two missed runs')
              : t(
                  'scans.ci.sheet.fromIntervals',
                  'stale after three usual intervals (7 to 30 days)'
                )
          }
        />
        <DetailStat
          label={t('scans.ci.view.runs', 'Runs')}
          value={(p.runs_count ?? 0).toLocaleString()}
          caption={
            p.last_fork_run_at
              ? t('scans.ci.sheet.ownRuns', 'own runs; fork runs are not counted')
              : t('scans.ci.sheet.everyBranch', 'on every branch')
          }
        />
      </DetailStatGrid>

      <DetailSection title={t('scans.ci.col.defaultGate', 'Default-branch gate')}>
        <div className="mb-2 flex items-center gap-2 text-sm">
          <GateLabel gate={p.gate} />
          {p.pr_gate && p.pr_gate !== 'none' && (
            <span className="text-muted-foreground">
              · {t('scans.ci.sheet.pullRequests', 'pull requests:')}{' '}
              <GateLabel gate={p.pr_gate} className="text-xs" />
            </span>
          )}
        </div>
        <GateTrend points={p.gate_trend} />
      </DetailSection>

      <DetailSection title={t('scans.ci.sheet.identity', 'Identity')}>
        <DetailFieldGrid>
          <DetailField label={t('scans.ci.col.provider', 'Provider')}>
            <span className="inline-flex items-center gap-1.5">
              <ProviderIcon provider={p.provider ?? ''} />
              {PROVIDER_LABEL[p.provider ?? ''] ?? p.provider}
            </span>
          </DetailField>
          <DetailField label={t('scans.ci.sheet.workflow', 'Workflow')}>
            <span className="font-mono text-xs">{p.workflow_path}</span>
          </DetailField>
          {p.workflow_name && (
            <DetailField label={t('scans.ci.trust.name', 'Name')}>{p.workflow_name}</DetailField>
          )}
          <DetailField label={t('scans.ci.col.defaultBranch', 'Default branch')}>
            {p.default_branch || '—'}
          </DetailField>
          <DetailField label={t('scans.ci.sheet.runnerVersion', 'Runner version')}>
            {p.sensor_version || '—'}
            {p.version_status === 'unsupported' && (
              <span className="ms-1 text-warning">
                {t('scans.ci.sheet.belowMinimum', 'below the minimum')}
              </span>
            )}
          </DetailField>
          <DetailField label={t('scans.ci.sheet.tools', 'Tools')}>
            {(p.tools ?? []).length > 0
              ? (p.tools ?? [])
                  .map((tool) => (tool.version ? `${tool.name} ${tool.version}` : tool.name))
                  .join(', ')
              : '—'}
          </DetailField>
          {p.template_ref && (
            <DetailField label={t('scans.ci.sheet.template', 'Template')} full>
              <span className="break-all font-mono text-xs">{p.template_ref}</span>
            </DetailField>
          )}
          <DetailField label={t('scans.ci.col.repository', 'Repository')} full>
            <Link
              href={assetDetailHref(p.repository_asset_id ?? '')}
              className="text-primary hover:underline"
            >
              {p.repository}
            </Link>
          </DetailField>
          {p.legacy && (
            <DetailField label={t('scans.ci.sheet.identity', 'Identity')} full>
              {t(
                'scans.ci.sheet.legacy',
                'Recorded before pipelines existed; its next run confirms its repository id.'
              )}
            </DetailField>
          )}
        </DetailFieldGrid>
      </DetailSection>
    </div>
  )
}

function Runs({ pipelineId }: { pipelineId: string }) {
  const { t } = useTranslation()
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 10 })
  const [run, setRun] = useState<string | null>(null)
  const { data, error, isLoading } = useCIRuns({
    pipelineId,
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  })
  const attempts = runAttempts(data?.data ?? [])
  const columns: ColumnDef<CIRun>[] = [
    {
      id: 'ref',
      header: t('scans.ci.preview.field.branch', 'Branch'),
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
              {row.original.fork ? ` · ${t('scans.ci.fork', 'fork')}` : ''}
              <RunAttempt attempt={attempts.get(row.original.id ?? '')} />
            </span>
          }
        />
      ),
    },
    {
      id: 'verdict',
      header: t('scans.ci.col.verdict', 'Verdict'),
      cell: ({ row }) => <VerdictBadge verdict={row.original.verdict} />,
    },
    {
      id: 'started',
      header: t('scans.ci.col.started', 'Started'),
      cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
    },
  ]
  if (error) return <ErrorState title={t('scans.ci.sheet.runs', 'runs')} error={error} />
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
        paginationNoun={t('scans.ci.noun.runs', 'runs')}
        emptyMessage={t('scans.ci.sheet.noRuns', 'No runs yet')}
      />
      <CIRunSheet id={run} onClose={() => setRun(null)} />
    </>
  )
}

function Branches({ p }: { p: CIPipelineDetail }) {
  const { t } = useTranslation()
  const branches = p.branches ?? []
  if (branches.length === 0) {
    return (
      <EmptyState
        icon={GitBranch}
        title={t('scans.ci.sheet.noBranchesTitle', 'No branches yet')}
        description={t('scans.ci.sheet.noBranches', 'Branches show up after the pipeline runs.')}
        card={false}
      />
    )
  }
  return (
    <ul
      className="divide-y rounded-lg border"
      aria-label={t('scans.ci.sheet.branches', 'Branches')}
    >
      {branches.map((b) => (
        <li key={b.branch} className="flex items-center justify-between gap-3 px-3 py-2.5 text-sm">
          <StackedCell
            truncate
            primary={
              <span>
                {b.branch || t('scans.ci.sheet.tag', '(tag)')}
                {b.is_default_branch && (
                  <span className="ms-1.5 text-xs text-muted-foreground">
                    {t('scans.ci.sheet.default', 'default')}
                  </span>
                )}
              </span>
            }
            secondary={
              b.runs === 1
                ? t('scans.ci.sheet.oneRun', '1 run')
                : t('scans.ci.sheet.runsCount', '{count} runs', { count: b.runs ?? 0 })
            }
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
  const { t } = useTranslation()
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
      title={t('confirm.ciPipeline.retireTitle', 'Retire the CI pipeline {name}?', { name: label })}
      desc={t(
        'confirm.ciPipeline.retireDesc',
        'Findings that only this pipeline reported and nothing else has seen since close as "source retired". Findings another source still sees are not touched. Each closed finding can be reopened, and the next run of the pipeline brings it back.'
      )}
      confirmText={t('confirm.ciPipeline.retire', 'Retire pipeline')}
      disabled={!ok}
      isLoading={isMutating}
      handleConfirm={async () => {
        try {
          const res = await trigger({ id: pipelineId, reason: reason.trim() })
          const n = res?.findings_closed ?? 0
          toast.success(
            t(
              'scans.ci.sheet.retiredToast',
              'Pipeline retired; {count} finding(s) closed as source retired',
              { count: n }
            )
          )
          setReason('')
          onOpenChange(false)
          onRetired?.()
        } catch (e) {
          toast.error(
            e instanceof Error
              ? e.message
              : t('scans.ci.sheet.retireFailed', 'Could not retire the pipeline')
          )
        }
      }}
    >
      <div className="space-y-2">
        <Label htmlFor={reasonId}>
          {t('scans.ci.sheet.retireReason', 'Reason (recorded in the audit log)')}
        </Label>
        <Textarea
          id={reasonId}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={t(
            'scans.ci.sheet.retirePlaceholder',
            'The workflow was removed; scanning moved to …'
          )}
          maxLength={2000}
          rows={3}
        />
        <p className="text-xs text-muted-foreground">
          {t('scans.ci.sheet.retireLength', '10 to 2,000 characters.')}
        </p>
      </div>
    </ConfirmDialog>
  )
}

export function CIPipelineSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { t } = useTranslation()
  const { data: p, error, mutate } = useCIPipeline(id)
  const [tabParam, setTabParam] = useUrlFilter('pipeline_tab', 'overview')
  const tab = pipelineTab(tabParam)
  const setTab = (v: PipelineTab) => setTabParam(v)
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
          title={p?.repository ?? t('scans.ci.mode.ciPipeline', 'CI pipeline')}
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
                  {t('scans.ci.sheet.retire', 'Retire')}
                </Button>
              )}
              <Button asChild size="sm" variant="outline">
                <Link href="/ci-cd?tab=setup">
                  <Settings2 className="h-4 w-4" />
                  {t('scans.ci.trustAndGateLink', 'CI trust and gate')}
                </Link>
              </Button>
            </>
          }
        />
      }
      tabs={
        <DetailTabs
          tabs={PIPELINE_TABS.map((x) => ({
            ...x,
            label: t(`scans.ci.sheet.tab.${x.value}`, x.label),
          }))}
          value={tab}
          onValueChange={setTab}
        />
      }
    >
      {error ? (
        <ErrorState title={t('scans.ci.sheet.thePipeline', 'the pipeline')} error={error} />
      ) : !p ? (
        <div className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : tab === 'overview' ? (
        <Overview p={p} />
      ) : tab === 'runs' ? (
        <Runs pipelineId={p.id ?? ''} />
      ) : tab === 'settings' ? (
        p.repository_asset_id ? (
          <CIRepositorySettingsTab repositoryAssetId={p.repository_asset_id} />
        ) : (
          <EmptyState
            icon={Settings2}
            title={t('scans.ci.repoSettings.noRepoTitle', 'No repository yet')}
            description={t(
              'scans.ci.repoSettings.noRepo',
              "Gate settings belong to a repository; this pipeline's next run confirms its repository."
            )}
            card={false}
          />
        )
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
