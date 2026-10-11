'use client'

/**
 * CI runs: the executions of CI pipelines (api RFC-051). A run is not a
 * sensor row: it has no heartbeat; it belongs to a pipeline (listed on the
 * Sensors page in runner mode) and a repository asset, and carries its
 * commit, branch, pull request, pipeline and actor from the CI provider's
 * verified token. Shown on the CI/CD integration page, under Runs.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { ExternalLink, GitBranch, GitPullRequest, Workflow } from 'lucide-react'
import { PageHeader, EmptyState, ErrorState } from '@/features/shared'
import { useListParams } from '@/hooks/use-list-params'
import { SafeExternalLink } from '@/components/safe-external-link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetBody,
} from '@/components/ui/sheet'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useCIRun, useCIRuns } from '../api/use-ci'
import { PROVIDER_LABEL, REASON_LABEL, shortSHA } from '../lib/ci'
import type { CIRun, CIVerdictFilter } from '../types'
import { useTranslation } from '@/context/i18n-provider'

export function VerdictBadge({ verdict, wouldFail }: { verdict?: string; wouldFail?: boolean }) {
  const { t } = useTranslation()
  if (verdict === 'fail')
    return <Badge variant="destructive">{t('scans.ci.verdict.fail', 'Fail')}</Badge>
  if (verdict === 'pass' && wouldFail)
    return (
      <Badge variant="outline">
        {t('scans.ci.verdict.passOverride', 'Pass (override or warn)')}
      </Badge>
    )
  if (verdict === 'pass')
    return <Badge variant="default">{t('scans.ci.verdict.pass', 'Pass')}</Badge>
  return <Badge variant="secondary">{t('scans.ci.verdict.none', 'No verdict')}</Badge>
}

function RefCell({ run }: { run: CIRun }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className="flex items-center gap-1 truncate text-sm">
        {run.pull_request ? (
          <GitPullRequest className="size-3.5 shrink-0" aria-hidden />
        ) : (
          <GitBranch className="size-3.5 shrink-0" aria-hidden />
        )}
        <span className="truncate">{run.branch || run.ref}</span>
        {run.pull_request && <span className="text-muted-foreground">#{run.pull_request}</span>}
      </span>
      <span className="font-mono text-xs text-muted-foreground">{shortSHA(run.commit_sha)}</span>
    </div>
  )
}

export interface CIRunsViewProps {
  /** Inside another page (the Sensors page): no page header of its own. */
  embedded?: boolean
  /** A run to open on mount (links from a verdict: /ci-runners/{id}). */
  initialRunId?: string | null
  /** Controls placed before the verdict filter (the page's own switches). */
  toolbarStart?: React.ReactNode
}

const VERDICTS: readonly CIVerdictFilter[] = ['pass', 'fail', 'none']

/** A verdict filter from the URL; anything unknown is no filter. */
function asVerdict(raw: string): CIVerdictFilter {
  return VERDICTS.includes(raw as CIVerdictFilter) ? (raw as CIVerdictFilter) : ''
}

export function CIRunsView({
  embedded = false,
  initialRunId = null,
  toolbarStart,
}: CIRunsViewProps) {
  const { t } = useTranslation()
  const list = useListParams({ filters: { verdict: '' } })
  const { page, setPage } = list
  const verdict = asVerdict(list.filters.verdict)
  const [selected, setSelected] = useState<string | null>(initialRunId)
  const { data, error, isLoading, mutate } = useCIRuns({ verdict, page })
  const runs = data?.data ?? []
  const totalPages = data?.total_pages ?? 1

  return (
    <div className="space-y-4">
      {!embedded && (
        <PageHeader
          title={t('scans.ci.runsTitle', 'CI runs')}
          description={t(
            'scans.ci.runsDescription',
            'Runs of CI pipelines that sent results, each judged by the CI gate.'
          )}
        >
          <Button asChild variant="outline" size="sm">
            <Link href="/ci-cd?tab=setup">
              {t('scans.ci.trustAndGateLink', 'CI trust and gate')}
            </Link>
          </Button>
        </PageHeader>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {toolbarStart}
        <Select
          value={verdict || 'all'}
          onValueChange={(v) => {
            list.setFilter('verdict', v === 'all' ? '' : asVerdict(v))
          }}
        >
          <SelectTrigger className="w-44" aria-label={t('scans.ci.col.verdict', 'Verdict')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('scans.ci.verdict.all', 'All verdicts')}</SelectItem>
            <SelectItem value="fail">{t('scans.ci.verdict.failed', 'Failed')}</SelectItem>
            <SelectItem value="pass">{t('scans.ci.verdict.passed', 'Passed')}</SelectItem>
            <SelectItem value="none">{t('scans.ci.verdict.none', 'No verdict')}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {error ? (
        <ErrorState
          title={t('scans.ci.runsTitle', 'CI runs')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : isLoading ? (
        <Card>
          <CardContent className="space-y-2 p-4">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </CardContent>
        </Card>
      ) : runs.length === 0 ? (
        <EmptyState
          icon={Workflow}
          title={t('scans.ci.noRunsTitle', 'No CI runs yet')}
          description={t(
            'scans.ci.noRuns',
            'Add a CI trust configuration, then add the OpenCTEM CI scan to a pipeline.'
          )}
          action={
            <Button asChild size="sm">
              <Link href="/ci-cd?tab=setup">{t('scans.ci.setUpTrust', 'Set up CI trust')}</Link>
            </Button>
          }
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('scans.ci.col.repository', 'Repository')}</TableHead>
                  <TableHead>{t('scans.ci.col.ref', 'Ref')}</TableHead>
                  <TableHead>{t('scans.ci.col.verdict', 'Verdict')}</TableHead>
                  <TableHead>{t('scans.ci.col.findings', 'Findings')}</TableHead>
                  <TableHead>{t('scans.ci.col.actor', 'Actor')}</TableHead>
                  <TableHead>{t('scans.ci.col.started', 'Started')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runs.map((run) => (
                  <TableRow
                    key={run.id}
                    className="cursor-pointer"
                    onClick={() => setSelected(run.id ?? null)}
                    data-testid="ci-run-row"
                  >
                    <TableCell className="max-w-64">
                      <div className="flex flex-col">
                        <span className="truncate font-medium">{run.repository}</span>
                        <span className="text-xs text-muted-foreground">
                          {PROVIDER_LABEL[run.provider ?? ''] ?? run.provider}
                          {run.fork ? ` · ${t('scans.ci.fork', 'fork')}` : ''}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="max-w-56">
                      <RefCell run={run} />
                    </TableCell>
                    <TableCell>
                      <VerdictBadge verdict={run.verdict} />
                    </TableCell>
                    <TableCell>{run.findings_count ?? 0}</TableCell>
                    <TableCell className="text-sm">{run.actor}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {run.created_at ? new Date(run.created_at).toLocaleString() : ''}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-end gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage(page - 1)}
          >
            {t('components.pager.previous', 'Previous')}
          </Button>
          <span className="text-sm text-muted-foreground">
            {t('scans.ci.pageOf', 'Page {page} of {pages}', { page, pages: totalPages })}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= totalPages}
            onClick={() => setPage(page + 1)}
          >
            {t('components.pager.next', 'Next')}
          </Button>
        </div>
      )}

      <CIRunSheet id={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

export function CIRunSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { t } = useTranslation()
  const { data: run, error } = useCIRun(id)
  const v = run?.verdict_detail
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>{run?.repository ?? t('scans.ci.run', 'CI run')}</SheetTitle>
          <SheetDescription>
            {run
              ? t('scans.ci.refAtCommit', '{ref} at {commit}', {
                  ref: run.branch || run.ref || '',
                  commit: shortSHA(run.commit_sha),
                })
              : ''}
          </SheetDescription>
        </SheetHeader>
        <SheetBody className="p-0">
          {error ? (
            <div className="p-4">
              <ErrorState title={t('scans.ci.theRun', 'the run')} error={error} />
            </div>
          ) : !run ? (
            <div className="space-y-2 p-4">
              <Skeleton className="h-6 w-1/2" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : (
            <div className="space-y-5 p-4 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <VerdictBadge verdict={run.verdict} wouldFail={v?.would_fail} />
                {v?.policy?.source && (
                  <span className="text-muted-foreground">
                    {t('scans.ci.policySource', 'policy: {source}', { source: v.policy.source })}
                  </span>
                )}
                {run.pipeline_url && (
                  <SafeExternalLink
                    href={run.pipeline_url}
                    urlOptions={{ allowRelative: false }}
                    className="inline-flex items-center gap-1 text-primary underline-offset-4 hover:underline"
                  >
                    {t('scans.ci.pipeline', 'Pipeline')}{' '}
                    <ExternalLink className="size-3.5" aria-hidden />
                  </SafeExternalLink>
                )}
              </div>
              <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1">
                <dt className="text-muted-foreground">{t('scans.ci.col.provider', 'Provider')}</dt>
                <dd>{PROVIDER_LABEL[run.provider ?? ''] ?? run.provider}</dd>
                <dt className="text-muted-foreground">{t('scans.ci.col.event', 'Event')}</dt>
                <dd>{run.event}</dd>
                <dt className="text-muted-foreground">{t('scans.ci.col.actor', 'Actor')}</dt>
                <dd>{run.actor}</dd>
                <dt className="text-muted-foreground">
                  {t('scans.ci.col.defaultBranch', 'Default branch')}
                </dt>
                <dd>{run.default_branch}</dd>
                {run.environment && (
                  <>
                    <dt className="text-muted-foreground">
                      {t('scans.ci.col.environment', 'Environment')}
                    </dt>
                    <dd>{run.environment}</dd>
                  </>
                )}
                <dt className="text-muted-foreground">{t('scans.ci.col.reports', 'Reports')}</dt>
                <dd>{run.reports_count ?? 0}</dd>
              </dl>
              {v?.summary && (
                <p className="text-muted-foreground">
                  {t(
                    'scans.ci.verdictSummary',
                    '{evaluated} findings judged: {new} new, {pre} already on {branch}, {accepted} accepted, {blocking} blocking.',
                    {
                      evaluated: v.summary.evaluated ?? 0,
                      new: v.summary.new ?? 0,
                      pre: v.summary.pre_existing ?? 0,
                      branch:
                        v.baseline?.branch || t('scans.ci.theDefaultBranch', 'the default branch'),
                      accepted: v.summary.accepted ?? 0,
                      blocking: v.summary.blocking ?? 0,
                    }
                  )}
                </p>
              )}
              {v?.reasons && v.reasons.length > 0 && (
                <ul className="space-y-2" aria-label={t('scans.ci.reasons', 'Reasons')}>
                  {v.reasons.map((r, i) => (
                    <li key={`${r.code}-${r.fingerprint ?? i}`} className="rounded-md border p-2">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">{REASON_LABEL[r.code ?? ''] ?? r.code}</Badge>
                        {r.severity && <span className="text-muted-foreground">{r.severity}</span>}
                      </div>
                      <p className="mt-1">{r.title || r.message}</p>
                      {r.title && <p className="text-muted-foreground">{r.message}</p>}
                      {r.file && (
                        <p className="font-mono text-xs text-muted-foreground">
                          {r.file}
                          {r.line ? `:${r.line}` : ''}
                        </p>
                      )}
                      {r.finding_id && (
                        <Link
                          href={`/findings/${r.finding_id}`}
                          className="text-xs text-primary hover:underline"
                        >
                          {t('scans.ci.openFinding', 'Open finding')}
                        </Link>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </SheetBody>
      </SheetContent>
    </Sheet>
  )
}
