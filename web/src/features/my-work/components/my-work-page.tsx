'use client'

/**
 * My Work (research 229 §8.5, api/docs/architecture/my-work.md): what waits
 * on the signed-in person, their team, and their requests, one tab per job.
 * Every tab is a view on the caller's own rows through a caller-scoped
 * endpoint, and its count is the total of the list it opens.
 */

import { useCallback, useMemo, type ReactNode } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { ArrowRight, CheckCircle2, RefreshCw, Timer } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { PageHeader, PageStack } from '@/features/shared'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { LockedChip } from '@/features/shared/components/filter-chips-row'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useFindingQuickViews } from '@/features/findings/api/use-quick-views'
import { quickViewHref } from '@/features/findings/lib/quick-views'
import { startSession, triageHref } from '@/features/findings/lib/triage-session'
import { MyTasksQueue, useMyTaskCount } from '@/features/remediation-hub/components/my-tasks-queue'
import { useApprovalQueue, useFindingQueue } from '../api/use-my-work'
import {
  DUE_SOON_VIEW,
  FINDING_QUEUE_SORT,
  FINDING_QUEUE_VIEW,
  MY_WORK_TABS,
  NEEDS_TRIAGE_VIEW,
  isApprovalQueueTab,
  isFindingQueueTab,
  parseTab,
  viewOf,
  type MyWorkTab,
} from '../lib/queues'
import { FindingQueue } from './finding-queue'
import { ReviewQueue } from './review-queue'
import { RequestedQueue } from './requested-queue'

/** Requests shown at once in an approval queue. */
const APPROVAL_PAGE = 25

/** English fallbacks; the keys are myWork.tabs.<tab> and myWork.explain.<tab>. */
const TAB_LABELS: Record<MyWorkTab, string> = {
  assigned: 'Assigned to me',
  team: 'My team',
  review: 'Awaiting my review',
  requested: 'Requested by me',
  expiring: 'Acceptances expiring',
  tasks: 'My tasks',
}
const TAB_EXPLAIN: Record<MyWorkTab, string> = {
  assigned:
    'Open findings assigned to you or your groups, or on assets you own, the nearest deadline first.',
  team: 'Open findings held by the people who share a group with you, or by the group.',
  review:
    'Decisions other people asked you to make. You never approve your own request, and a risk acceptance always needs a second person.',
  requested:
    'Your false positive and risk acceptance requests, waiting for someone else to decide.',
  expiring:
    'Accepted risks on your findings that end within 30 days, when the finding reopens. Fix them or renew the acceptance in time.',
  tasks:
    'Open remediation tasks assigned to you or to one of your groups, the earliest deadline first.',
}

export function MyWorkPage() {
  const { t } = useTranslation()
  const router = useRouter()
  const params = useSearchParams()
  const { hasPermission } = usePermissions()
  const canApprove = hasPermission(Permission.FindingsApprove)
  const canSeeTasks = hasPermission(Permission.RemediationRead)
  const canTriage = hasPermission(Permission.FindingsStatus)
  const canSeeApprovalRules = hasPermission(Permission.SettingsRead)

  const available = useMemo(
    () =>
      MY_WORK_TABS.filter(
        (tab) => (tab !== 'review' || canApprove) && (tab !== 'tasks' || canSeeTasks)
      ),
    [canApprove, canSeeTasks]
  )
  const tab = parseTab(params.get('tab'), available)
  const dueSoon = tab === 'assigned' && params.get('due') === '72h'

  const setQuery = useCallback(
    (next: { tab?: MyWorkTab; due?: boolean }) => {
      const q = new URLSearchParams()
      const nextTab = next.tab ?? tab
      if (nextTab !== available[0]) q.set('tab', nextTab)
      if (nextTab === 'assigned' && next.due) q.set('due', '72h')
      const qs = q.toString()
      router.replace(qs ? `/my-work?${qs}` : '/my-work', { scroll: false })
    },
    [router, tab, available]
  )

  // Counts: the quick views (finding queues), one approval queue call (both
  // queues' counts), the task count. Then the open tab's rows.
  const views = useFindingQuickViews(true)
  const viewList = views.data?.views
  const include = views.data?.include_informational ?? false
  const findingView = isFindingQueueTab(tab)
    ? viewOf(viewList, dueSoon ? DUE_SOON_VIEW : FINDING_QUEUE_VIEW[tab])
    : undefined
  const findingRows = useFindingQueue(
    findingView?.params,
    isFindingQueueTab(tab) ? FINDING_QUEUE_SORT[tab] : '',
    isFindingQueueTab(tab)
  )
  // Any approval queue page carries both queues' counts: off the approval
  // tabs one row of Requested by me serves them (review counts nothing
  // without findings:approve, so the call does not depend on the permission).
  const approvalTab = isApprovalQueueTab(tab) ? tab : 'requested'
  const approvals = useApprovalQueue(approvalTab, isApprovalQueueTab(tab) ? APPROVAL_PAGE : 1)
  const taskCount = useMyTaskCount(canSeeTasks)

  const count = (key: string) => viewOf(viewList, key)?.count
  const counts: Record<MyWorkTab, number | undefined> = {
    assigned: count(FINDING_QUEUE_VIEW.assigned),
    team: count(FINDING_QUEUE_VIEW.team),
    review: approvals.data?.queue_counts?.review,
    requested: approvals.data?.queue_counts?.requested,
    expiring: count(FINDING_QUEUE_VIEW.expiring),
    tasks: taskCount,
  }
  const dueSoonCount = count(DUE_SOON_VIEW)
  const triageView = viewOf(viewList, NEEDS_TRIAGE_VIEW)

  const openTriage = useCallback(
    (viewParams: string, viewKey: string) => {
      startSession(viewParams, quickViewHref(viewParams, include), viewKey)
      router.push(triageHref(viewParams))
    },
    [router, include]
  )

  const refresh = useCallback(() => {
    void views.mutate()
    void approvals.mutate()
    if (isFindingQueueTab(tab)) void findingRows.mutate()
  }, [views, approvals, findingRows, tab])

  // ---- Next steps for an empty queue: one primary move, one secondary. ----
  const goTab = (next: MyWorkTab, due = false) => setQuery({ tab: next, due })
  const nextStep = (): ReactNode => {
    if ((dueSoonCount ?? 0) > 0 && tab !== 'assigned') {
      return (
        <Button size="sm" onClick={() => goTab('assigned', true)}>
          {t('myWork.next.dueSoon', 'Next: review {count} findings due in 72 hours', {
            count: dueSoonCount ?? 0,
          })}
          <ArrowRight className="ms-2 size-4" aria-hidden="true" />
        </Button>
      )
    }
    if (canTriage && triageView && triageView.count > 0) {
      return (
        <Button size="sm" onClick={() => openTriage(triageView.params, NEEDS_TRIAGE_VIEW)}>
          {t('myWork.next.triage', 'Next: triage {count} new findings', {
            count: triageView.count,
          })}
          <ArrowRight className="ms-2 size-4" aria-hidden="true" />
        </Button>
      )
    }
    if (tab !== 'assigned' && (counts.assigned ?? 0) > 0) {
      return (
        <Button size="sm" onClick={() => goTab('assigned')}>
          {t('myWork.next.assigned', 'Next: work your {count} findings', {
            count: counts.assigned ?? 0,
          })}
          <ArrowRight className="ms-2 size-4" aria-hidden="true" />
        </Button>
      )
    }
    return (
      <Button size="sm" variant="outline" asChild>
        <Link href="/findings">{t('myWork.next.allFindings', 'Open all findings')}</Link>
      </Button>
    )
  }
  const emptyFor = (which: MyWorkTab, secondary?: ReactNode) => (
    <EmptyState
      card={false}
      icon={CheckCircle2}
      title={t(`myWork.empty.${which}.title`)}
      description={t(`myWork.empty.${which}.description`)}
      action={
        <div className="flex flex-wrap justify-center gap-2">
          {nextStep()}
          {secondary}
        </div>
      }
    />
  )

  // ---- The open tab ----
  const lockedChip = (which: MyWorkTab) => (
    <LockedChip hint={t('myWork.locked.hint', 'Set by this queue; it cannot be removed.')}>
      {t(`myWork.locked.${which}`)}
    </LockedChip>
  )

  const findingPanel = (which: 'assigned' | 'team' | 'expiring') => {
    const rows = findingRows.data?.data ?? []
    const total = findingRows.data?.total ?? findingView?.count ?? 0
    const viewParams = findingView?.params
    const viewKey = dueSoon ? DUE_SOON_VIEW : FINDING_QUEUE_VIEW[which]
    return (
      <FindingQueue
        tab={which}
        rows={rows}
        total={total}
        isLoading={(views.isLoading || findingRows.isLoading) && !findingRows.data}
        error={views.error ?? findingRows.error}
        onRetry={refresh}
        toolbarStart={
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            {lockedChip(which)}
            {which === 'assigned' && dueSoonCount !== undefined && (
              <button
                type="button"
                aria-pressed={dueSoon}
                onClick={() => setQuery({ tab: 'assigned', due: !dueSoon })}
                className={cn(
                  'inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                  dueSoon
                    ? 'border-warning bg-accent text-foreground'
                    : 'border-warning/60 text-foreground hover:bg-accent'
                )}
              >
                <Timer className="size-3.5" aria-hidden="true" />
                {t('myWork.chip.dueSoon', 'SLA due in 72 hours')}
                <span className="tabular-nums">{dueSoonCount}</span>
              </button>
            )}
            <span className="text-meta text-muted-foreground tabular-nums" aria-live="polite">
              {total > rows.length
                ? t('myWork.topOf', 'Top {shown} of {total}', { shown: rows.length, total })
                : t('myWork.results', '{count} results', { count: total })}
            </span>
          </div>
        }
        toolbarEnd={
          viewParams !== undefined && total > 0 ? (
            <div className="flex flex-wrap items-center gap-2">
              {canTriage && which !== 'expiring' && (
                <Button size="sm" variant="outline" onClick={() => openTriage(viewParams, viewKey)}>
                  {t('myWork.triageThese', 'Triage these')}
                </Button>
              )}
              <Button size="sm" variant="outline" asChild>
                <Link href={quickViewHref(viewParams, include)}>
                  {t('myWork.viewAll', 'View all')}
                  <ArrowRight className="ms-2 size-4" aria-hidden="true" />
                </Link>
              </Button>
            </div>
          ) : null
        }
        empty={emptyFor(
          which,
          which === 'expiring' ? (
            <Button size="sm" variant="ghost" asChild>
              <Link
                href={quickViewHref(
                  viewOf(viewList, 'accepted_expiring')?.params ?? 'status=accepted',
                  include
                )}
              >
                {t('myWork.next.allAccepted', 'All accepted risks ending soon')}
              </Link>
            </Button>
          ) : dueSoon ? (
            <Button size="sm" variant="ghost" onClick={() => setQuery({ tab: 'assigned' })}>
              {t('myWork.next.clearDueSoon', 'Show all your findings')}
            </Button>
          ) : undefined
        )}
      />
    )
  }

  const approvalPanel = (which: 'review' | 'requested') => {
    if (approvals.error) {
      return <ErrorState title={t('myWork.loadErrorRequests', 'your requests')} onRetry={refresh} />
    }
    if (!approvals.data) {
      return (
        <div className="space-y-2" aria-busy="true">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-20 animate-pulse rounded-lg bg-muted" />
          ))}
        </div>
      )
    }
    const rows = approvals.data.data ?? []
    const total = approvals.data.queue_counts?.[which] ?? approvals.data.total
    const toolbar = (
      <>
        {lockedChip(which)}
        <LockedChip>{t('myWork.locked.pending', 'Pending')}</LockedChip>
      </>
    )
    if (which === 'review') {
      return (
        <ReviewQueue
          rows={rows}
          total={total}
          onChanged={refresh}
          toolbar={toolbar}
          empty={emptyFor(
            'review',
            canSeeApprovalRules ? (
              <Button size="sm" variant="ghost" asChild>
                <Link href="/settings/finding-approvals">
                  {t('myWork.next.approvalRules', 'Set up approval rules')}
                </Link>
              </Button>
            ) : undefined
          )}
        />
      )
    }
    return (
      <RequestedQueue
        rows={rows}
        total={total}
        onChanged={refresh}
        toolbar={toolbar}
        empty={emptyFor('requested')}
      />
    )
  }

  const asOf = views.data?.as_of
  return (
    <Main>
      <PageStack>
        <PageHeader title={t('myWork.title')} description={t('myWork.description')}>
          <>
            {asOf && (
              <span className="hidden text-meta text-muted-foreground sm:inline">
                {t('myWork.updated', 'Updated')} <RelativeTime date={asOf} />
              </span>
            )}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  size="icon"
                  variant="outline"
                  onClick={refresh}
                  aria-label={t('myWork.refresh', 'Refresh')}
                >
                  <RefreshCw className="size-4" aria-hidden="true" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>{t('myWork.refresh', 'Refresh')}</TooltipContent>
            </Tooltip>
            {canTriage && triageView && (
              <Button
                onClick={() =>
                  triageView.count > 0
                    ? openTriage(triageView.params, NEEDS_TRIAGE_VIEW)
                    : router.push(quickViewHref(triageView.params, include))
                }
              >
                {t('myWork.triage', 'Triage')}
                {triageView.count > 0 && (
                  <span className="ms-1.5 tabular-nums">{triageView.count}</span>
                )}
              </Button>
            )}
          </>
        </PageHeader>

        <Tabs value={tab} onValueChange={(v) => setQuery({ tab: v as MyWorkTab })}>
          <TabsList aria-label={t('myWork.tabs.label')}>
            {available.map((key) => (
              <TabsTrigger key={key} value={key}>
                {t(`myWork.tabs.${key}`, TAB_LABELS[key])}
                <TabsCount value={counts[key]} />
              </TabsTrigger>
            ))}
          </TabsList>
          <p className="text-meta text-muted-foreground">
            {t(`myWork.explain.${tab}`, TAB_EXPLAIN[tab])}
          </p>
          {available.map((key) => (
            <TabsContent key={key} value={key} className="mt-1">
              {key === tab &&
                (isFindingQueueTab(key) ? (
                  findingPanel(key)
                ) : isApprovalQueueTab(key) ? (
                  approvalPanel(key)
                ) : (
                  <MyTasksQueue />
                ))}
            </TabsContent>
          ))}
        </Tabs>
      </PageStack>
    </Main>
  )
}
