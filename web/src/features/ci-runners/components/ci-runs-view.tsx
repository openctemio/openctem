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
import {
  ExternalLink,
  GitBranch,
  GitPullRequest,
  Plug,
  ShieldAlert,
  ShieldCheck,
  Workflow,
} from 'lucide-react'
import { PageHeader, EmptyState, ErrorState, RelativeTime } from '@/features/shared'
import { dateFnsLocaleFor } from '@/features/shared/components/activity-timeline'
import { useListParams } from '@/hooks/use-list-params'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Permission, usePermissions } from '@/lib/permissions'
import { safeHref } from '@/lib/safe-href'
import { ApiClientError } from '@/lib/api/error-handler'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
import { baselineCounts, missingCodeHost, runAttempts } from '../lib/gate-settings'
import { INFO_REASON_CODES, PROVIDER_LABEL, REASON_LABEL, shortSHA } from '../lib/ci'
import type { CIGateReason, CIRun, CIVerdictFilter } from '../types'
import { useTranslation } from '@/context/i18n-provider'
import { CIOverrideDialog } from './ci-override-dialog'
import { CISetupEntry } from './ci-setup-wizard'

/** Whether a load error is a 404: the run is missing or out of the caller's data scope. */
function isNotFound(error: unknown): boolean {
  if (error instanceof ApiClientError) return error.isNotFoundError()
  return (error as { statusCode?: number } | null)?.statusCode === 404
}

export function VerdictBadge({
  verdict,
  wouldFail,
  status,
}: {
  verdict?: string
  wouldFail?: boolean
  status?: string
}) {
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
  if (status === 'running')
    return <Badge variant="secondary">{t('scans.ci.verdict.running', 'Running')}</Badge>
  return <Badge variant="secondary">{t('scans.ci.verdict.none', 'No verdict')}</Badge>
}

/**
 * The run's findings link from the verdict, as a console path: the API
 * builds it on the console's base URL; only a path on this console is
 * followed.
 */
export function consolePath(url?: string): string | null {
  if (!url) return null
  if (url.startsWith('/') && !url.startsWith('//')) return url
  try {
    const u = new URL(url)
    if (typeof window !== 'undefined' && u.origin !== window.location.origin) return null
    return u.pathname + u.search
  } catch {
    return null
  }
}

/** "Attempt 2 of 3" for a retried commit; nothing for a single run. */
export function RunAttempt({ attempt }: { attempt?: { attempt: number; of: number } }) {
  const { t } = useTranslation()
  if (!attempt) return null
  return (
    <span className="font-sans text-muted-foreground" data-testid="ci-run-attempt">
      {' · '}
      {t('scans.ci.runAttempt', 'Attempt {attempt} of {of}', {
        attempt: attempt.attempt,
        of: attempt.of,
      })}
    </span>
  )
}

function RefCell({ run, attempt }: { run: CIRun; attempt?: { attempt: number; of: number } }) {
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
      <span className="font-mono text-xs text-muted-foreground">
        {shortSHA(run.commit_sha)}
        <RunAttempt attempt={attempt} />
      </span>
    </div>
  )
}

export interface CIRunsViewProps {
  /** Inside another page (the Sensors page): no page header of its own. */
  embedded?: boolean
  /** Controls placed before the verdict filter (the page's own switches). */
  toolbarStart?: React.ReactNode
}

const VERDICTS: readonly CIVerdictFilter[] = ['pass', 'fail', 'none']

/** A verdict filter from the URL; anything unknown is no filter. */
function asVerdict(raw: string): CIVerdictFilter {
  return VERDICTS.includes(raw as CIVerdictFilter) ? (raw as CIVerdictFilter) : ''
}

export function CIRunsView({ embedded = false, toolbarStart }: CIRunsViewProps) {
  const { t, locale } = useTranslation()
  const list = useListParams({ filters: { verdict: '' } })
  const { page, setPage } = list
  const verdict = asVerdict(list.filters.verdict)
  // The open run lives in the URL (?run=), so a run can be linked and shared
  // (verdict links from the API land here).
  const [runParam, setRunParam] = useUrlFilter('run', '')
  const selected = runParam || null
  const setSelected = (id: string | null) => setRunParam(id ?? '')
  const { data, error, isLoading, mutate } = useCIRuns({ verdict, page })
  const { can } = usePermissions()
  const canWrite = can(Permission.CIWrite)
  const runs = data?.data ?? []
  const attempts = runAttempts(runs)
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
      ) : runs.length === 0 && verdict ? (
        <EmptyState
          icon={Workflow}
          title={t('scans.ci.noRunsFilteredTitle', 'No runs with this verdict')}
          description={t(
            'scans.ci.noRunsFiltered',
            'Choose another verdict, or all verdicts, to see the other runs.'
          )}
        />
      ) : runs.length === 0 && !canWrite ? (
        <EmptyState
          icon={Workflow}
          title={t('scans.ci.noRunsScopedTitle', 'No CI runs you can see')}
          description={t(
            'scans.ci.noRunsScoped',
            'You see the runs of repositories you have access to. If a pull request check links here, ask an administrator for access to its repository.'
          )}
        />
      ) : runs.length === 0 ? (
        <EmptyState
          icon={Workflow}
          title={t('scans.ci.noRunsTitle', 'No CI runs yet')}
          description={t(
            'scans.ci.noRuns',
            'Add a CI trust configuration, then add the {product} CI scan to a pipeline.'
          )}
          action={<CISetupEntry canWrite={canWrite} />}
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('scans.ci.col.repository', 'Repository')}</TableHead>
                  <TableHead>{t('scans.ci.col.verdict', 'Verdict')}</TableHead>
                  <TableHead>{t('scans.ci.col.ref', 'Ref')}</TableHead>
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
                    <TableCell>
                      <VerdictBadge
                        verdict={run.verdict}
                        wouldFail={run.would_fail}
                        status={run.status}
                      />
                    </TableCell>
                    <TableCell className="max-w-56">
                      <RefCell run={run} attempt={attempts.get(run.id ?? '')} />
                    </TableCell>
                    <TableCell>{run.findings_count ?? 0}</TableCell>
                    <TableCell className="text-sm">{run.actor}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      <RelativeTime date={run.created_at} locale={dateFnsLocaleFor(locale)} />
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

const DECORATION_LABEL: Record<string, string> = {
  pending: 'Waiting to post',
  posting: 'Posting',
  posted: 'Posted',
  skipped: 'Not posted',
  failed: 'Failed',
}

function ReasonList({ reasons, label }: { reasons: CIGateReason[]; label: string }) {
  const { t } = useTranslation()
  return (
    <ul className="space-y-2" aria-label={label}>
      {reasons.map((r, i) => (
        <li key={`${r.code}-${r.fingerprint ?? i}`} className="rounded-md border p-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline">
              {REASON_LABEL[r.code ?? '']
                ? t(`scans.ci.reason.${r.code}`, REASON_LABEL[r.code ?? ''])
                : r.code}
            </Badge>
            {r.severity && (
              <span className="text-muted-foreground">
                {t(`severity.${r.severity}`, r.severity)}
              </span>
            )}
          </div>
          <p className="mt-1 break-words">{r.title || r.message}</p>
          {r.title && <p className="break-words text-muted-foreground">{r.message}</p>}
          {r.file && (
            <p className="break-all font-mono text-xs text-muted-foreground">
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
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </>
  )
}

export function CIRunSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { t, locale } = useTranslation()
  const { can } = usePermissions()
  const canOverride = can(Permission.CIOverride)
  // Code-host connections are managed with scans:ci:write (Pull request feedback).
  const canConnect = can(Permission.CIWrite)
  const [overrideOpen, setOverrideOpen] = useState(false)
  const { data: run, error, mutate } = useCIRun(id)
  const v = run?.verdict_detail
  const dfLocale = dateFnsLocaleFor(locale)
  const reasons = v?.reasons ?? []
  const isInfo = (r: CIGateReason) => INFO_REASON_CODES.includes(r.code ?? '')
  const blocking = reasons.filter((r) => r.mode !== 'comment' && !isInfo(r))
  const commentOnly = reasons.filter((r) => r.mode === 'comment' && !isInfo(r))
  const notes = reasons.filter(isInfo)
  const findingsPath = safeHref(consolePath(v?.links?.findings))
  const codeHost =
    run?.decoration_state === 'skipped' ? missingCodeHost(run.decoration_detail) : null
  const counts = baselineCounts(v)
  const override = run?.override
  // A break-glass covers a commit the provider signed, and only a failed one
  // needs it; the API is the authority (permission and step-up).
  const offerOverride = run?.verdict === 'fail' && run.commit_verified && !!run.repository_asset_id
  const tools = (run?.tools ?? [])
    .map((tl) => (tl.version ? `${tl.name} ${tl.version}` : tl.name))
    .filter(Boolean)
    .join(', ')
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-xl">
        <SheetHeader>
          <SheetTitle className="break-words">
            {run?.repository ?? t('scans.ci.run', 'CI run')}
          </SheetTitle>
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
          {error && isNotFound(error) ? (
            <div className="p-4">
              <EmptyState
                icon={ShieldAlert}
                title={t('scans.ci.runNotFoundTitle', 'This run is not available to you')}
                description={t(
                  'scans.ci.runNotFound',
                  'The run does not exist, or its repository is not in your access. The comment on the pull or merge request lists what blocked it; ask an administrator for access to the repository to see the details here.'
                )}
              />
            </div>
          ) : error ? (
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
                <VerdictBadge
                  verdict={run.verdict}
                  wouldFail={run.would_fail ?? v?.would_fail}
                  status={run.status}
                />
                {v?.policy?.source && (
                  <span className="text-muted-foreground">
                    {t('scans.ci.policySource', 'policy: {source}', {
                      source: t(`scans.ci.policySourceName.${v.policy.source}`, v.policy.source),
                    })}
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
                {findingsPath && (
                  <Link href={findingsPath} className="text-primary hover:underline">
                    {t('scans.ci.runFindings', "View the run's findings")}
                  </Link>
                )}
              </div>

              {override && (
                <Alert data-testid="ci-run-override">
                  <ShieldAlert className="size-4" aria-hidden />
                  <AlertTitle>
                    {t('scans.ci.runDetail.overrideTitle', 'Passed through a break-glass override')}
                  </AlertTitle>
                  <AlertDescription>
                    <p className="break-words">
                      {t('scans.ci.runDetail.overrideBody', '{who}: {reason}', {
                        who:
                          override.created_by ||
                          t('scans.ci.breakGlass.anAdmin', 'an administrator'),
                        reason: override.reason ?? '',
                      })}
                    </p>
                    {override.expires_at && (
                      <p className="text-xs">
                        {t('scans.ci.runDetail.overrideExpires', 'Expires')}{' '}
                        <RelativeTime date={override.expires_at} locale={dfLocale} />
                      </p>
                    )}
                  </AlertDescription>
                </Alert>
              )}

              <dl className="grid grid-cols-[minmax(6rem,8rem)_1fr] gap-x-3 gap-y-1">
                <Row label={t('scans.ci.col.provider', 'Provider')}>
                  {PROVIDER_LABEL[run.provider ?? ''] ?? run.provider}
                </Row>
                <Row label={t('scans.ci.col.event', 'Event')}>{run.event}</Row>
                <Row label={t('scans.ci.col.actor', 'Actor')}>{run.actor}</Row>
                <Row label={t('scans.ci.col.defaultBranch', 'Default branch')}>
                  {run.default_branch}
                </Row>
                {run.environment && (
                  <Row label={t('scans.ci.col.environment', 'Environment')}>{run.environment}</Row>
                )}
                <Row label={t('scans.ci.runDetail.commit', 'Commit')}>
                  <span className="font-mono">{shortSHA(run.commit_sha)}</span>{' '}
                  <span className="text-muted-foreground">
                    {run.commit_verified
                      ? t('scans.ci.runDetail.commitVerified', '(signed by the CI provider)')
                      : t('scans.ci.runDetail.commitReported', '(reported by the job)')}
                  </span>
                </Row>
                <Row label={t('scans.ci.col.reports', 'Reports')}>{run.reports_count ?? 0}</Row>
                {tools && <Row label={t('scans.ci.runDetail.tools', 'Tools')}>{tools}</Row>}
                {run.scan_failures != null && (
                  <Row label={t('scans.ci.runDetail.scanFailures', 'Scan failures')}>
                    <span className={run.scan_failures > 0 ? 'text-destructive' : undefined}>
                      {run.scan_failures}
                    </span>
                  </Row>
                )}
                {v?.repo_file && (
                  <Row label={t('scans.ci.runDetail.repoFile', '.openctem.yml')}>
                    {v.repo_file === 'applied'
                      ? t('scans.ci.runDetail.repoFileApplied', 'Applied (tightened the policy)')
                      : t('scans.ci.runDetail.repoFileIgnored', 'Ignored (not allowed by policy)')}
                  </Row>
                )}
                {run.evaluated_at && (
                  <Row label={t('scans.ci.runDetail.evaluated', 'Judged')}>
                    <RelativeTime date={run.evaluated_at} locale={dfLocale} />
                  </Row>
                )}
                {run.decoration_state && (
                  <Row label={t('scans.ci.runDetail.decoration', 'Check and comment')}>
                    <span data-testid="ci-run-decoration">
                      <Badge
                        variant={run.decoration_state === 'failed' ? 'destructive' : 'outline'}
                      >
                        {t(
                          `scans.ci.decoration.${run.decoration_state}`,
                          DECORATION_LABEL[run.decoration_state] ?? run.decoration_state
                        )}
                      </Badge>
                      {run.decoration_detail && (
                        <span className="ml-2 text-muted-foreground">{run.decoration_detail}</span>
                      )}
                      {codeHost && canConnect && (
                        <Button
                          asChild
                          size="sm"
                          variant="outline"
                          className="mt-1.5 flex w-fit"
                          data-testid="ci-run-connect-host"
                        >
                          <Link href="/ci-cd?tab=setup&section=feedback">
                            <Plug className="size-3.5" aria-hidden />
                            {codeHost === 'gitlab'
                              ? t('scans.ci.runDetail.connectGitLab', 'Connect GitLab')
                              : t('scans.ci.runDetail.installGitHub', 'Install the GitHub App')}
                          </Link>
                        </Button>
                      )}
                      {codeHost && !canConnect && (
                        <span className="mt-1 block text-xs text-muted-foreground">
                          {t(
                            'scans.ci.runDetail.askConnect',
                            'An administrator can connect the code host under CI trust and gate, Pull request feedback.'
                          )}
                        </span>
                      )}
                    </span>
                  </Row>
                )}
              </dl>

              {v?.baseline?.established && (
                <Alert data-testid="ci-run-baseline-established">
                  <ShieldCheck className="size-4" aria-hidden />
                  <AlertTitle className="line-clamp-none">
                    {t(
                      'scans.ci.runDetail.baselineEstablished',
                      'First run: {count} existing findings recorded as the baseline',
                      { count: v.summary?.pre_existing ?? 0 }
                    )}
                  </AlertTitle>
                  <AlertDescription>
                    {t(
                      'scans.ci.runDetail.baselineEstablishedBody',
                      'They do not block pipelines; new findings do. Manage the baseline in the pipeline’s Settings tab.'
                    )}
                  </AlertDescription>
                </Alert>
              )}

              {counts && (
                <p className="font-medium" data-testid="ci-run-baseline-counts">
                  {t(
                    'scans.ci.runDetail.baselineCounts',
                    '{baseline} baseline (not blocking) · {new} new',
                    {
                      baseline: counts.baseline,
                      new: counts.fresh,
                    }
                  )}
                  {v?.baseline?.due_at && (
                    <span className="ms-1 font-normal text-muted-foreground">
                      {t('scans.ci.runDetail.baselineDue', '· baseline blocks again from {date}', {
                        date: new Date(v.baseline.due_at).toLocaleDateString(),
                      })}
                    </span>
                  )}
                </p>
              )}

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
                  {(v.summary.monitored ?? 0) > 0 &&
                    ' ' +
                      t(
                        'scans.ci.runDetail.monitored',
                        '{count} more in monitor mode (recorded, not listed).',
                        { count: v.summary.monitored ?? 0 }
                      )}
                </p>
              )}

              {blocking.length > 0 && (
                <section className="space-y-2">
                  <h3 className="font-medium">{t('scans.ci.runDetail.blocking', 'Blocking')}</h3>
                  <ReasonList
                    reasons={blocking}
                    label={t('scans.ci.runDetail.blocking', 'Blocking')}
                  />
                </section>
              )}
              {commentOnly.length > 0 && (
                <section className="space-y-2">
                  <h3 className="font-medium">
                    {t('scans.ci.runDetail.commentOnly', 'Comment only (does not block)')}
                  </h3>
                  <ReasonList
                    reasons={commentOnly}
                    label={t('scans.ci.runDetail.commentOnly', 'Comment only (does not block)')}
                  />
                </section>
              )}

              {notes.length > 0 && (
                <section className="space-y-2">
                  <h3 className="font-medium">{t('scans.ci.runDetail.notes', 'Notes')}</h3>
                  <ReasonList reasons={notes} label={t('scans.ci.runDetail.notes', 'Notes')} />
                </section>
              )}

              {offerOverride && canOverride && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOverrideOpen(true)}
                  data-testid="ci-run-break-glass"
                >
                  <ShieldAlert className="size-4" aria-hidden />{' '}
                  {t('scans.ci.runDetail.breakGlass', 'Break-glass this commit')}
                </Button>
              )}
            </div>
          )}
        </SheetBody>
      </SheetContent>
      {run && offerOverride && canOverride && (
        <CIOverrideDialog
          open={overrideOpen}
          onOpenChange={setOverrideOpen}
          initialAssetId={run.repository_asset_id ?? ''}
          initialSha={run.commit_sha ?? ''}
          onCreated={() => void mutate?.()}
        />
      )}
    </Sheet>
  )
}
