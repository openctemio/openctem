'use client'

/**
 * My Work (research 229 §8.5, server/docs/architecture/my-work.md): what waits
 * on the signed-in person, their team, and their requests, one tab per job.
 * Every tab is a view on the caller's own rows through a caller-scoped
 * endpoint, and its count is the total of the list it opens.
 */

import { useCallback, useMemo, type ReactNode } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { ArrowRight, CheckCircle2, Info, MoreHorizontal, Timer } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { RefreshButton } from '@/components/list-page-parts'
import { useIsMobile } from '@/hooks/use-mobile'
import { ActionMenu } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader, PageStack } from '@/features/shared'
import { ListTitleRow } from '@/features/shared/components/list-title-row'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { FilterChipsRow, LockedChip } from '@/features/shared/components/filter-chips-row'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
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
  QUEUE_SIZE,
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
  // While a count is on its way its tab shows "…" (the kit's loading count),
  // so the tabs after it do not move when it arrives.
  const viewsPending = !views.data && !views.error
  const approvalsPending = !approvals.data && !approvals.error
  const pending: Record<MyWorkTab, boolean> = {
    assigned: viewsPending,
    team: viewsPending,
    expiring: viewsPending,
    review: approvalsPending,
    requested: approvalsPending,
    tasks: canSeeTasks && taskCount === undefined,
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
  // The selected tab is the queue's scope (its name and count), so no chip
  // repeats it; a locked chip states only a rule the tab does not say.

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
        // The queue's one filter token (due in 72 hours) is the toolbar's
        // start: a toggle at the row's control height (the kit button,
        // pressed while the queue shows only what falls due). On a phone it
        // is the timer and the count, named in full, so the toolbar's start
        // and end share one line without cutting it. (Page workaround: the
        // kit's phone toolbar cuts its start instead of wrapping; when the
        // kit handles that, the isPhone branch here can go.)
        toolbarStart={
          which === 'assigned' && dueSoonCount !== undefined ? (
            <Button
              size="sm"
              variant={dueSoon ? 'secondary' : 'outline'}
              aria-pressed={dueSoon}
              aria-label={
                isPhone
                  ? t('myWork.chip.dueSoonNamed', 'SLA due in 72 hours: {count}', {
                      count: dueSoonCount,
                    })
                  : undefined
              }
              onClick={() => setQuery({ tab: 'assigned', due: !dueSoon })}
            >
              <Timer className="me-2 size-4" aria-hidden="true" />
              {!isPhone && t('myWork.chip.dueSoon', 'SLA due in 72 hours')}
              <span className={isPhone ? 'tabular-nums' : 'ms-2 tabular-nums'}>{dueSoonCount}</span>
            </Button>
          ) : undefined
        }
        // Line 2, the kit's chips row, from md: how much of the queue is on
        // screen ("Top 25 of 40"). On a phone the tab's count and View all
        // say that, and the toolbar keeps its one line. The row is there as
        // soon as the count says the queue is longer than one page, so the
        // rows arriving do not move the list.
        toolbarBelow={
          !isPhone && total > QUEUE_SIZE ? (
            <FilterChipsRow
              data-testid="my-work-chips"
              chips={[]}
              trailing={
                <span className="text-meta whitespace-nowrap text-muted-foreground tabular-nums">
                  {rows.length > 0 &&
                    t('myWork.topOf', 'Top {shown} of {total}', { shown: rows.length, total })}
                </span>
              }
            />
          ) : undefined
        }
        // The toolbar's end: the queue's one main action, everything else
        // under More (View all opens the same list on Findings). While the
        // views load, More is there disabled, so the toolbar line is drawn
        // from the first paint and does not push the list down later.
        toolbarEnd={
          viewParams === undefined && viewsPending ? (
            <Button
              size="icon-sm"
              variant="outline"
              disabled
              aria-label={t('myWork.more', 'More for this queue')}
            >
              <MoreHorizontal aria-hidden="true" />
            </Button>
          ) : viewParams !== undefined && total > 0 ? (
            <div className="flex shrink-0 items-center gap-2">
              {canTriage && which !== 'expiring' && (
                <Button size="sm" onClick={() => openTriage(viewParams, viewKey)}>
                  {t('myWork.triageThese', 'Triage these')}
                </Button>
              )}
              <ActionMenu
                title={t(`myWork.tabs.${which}`, TAB_LABELS[which])}
                label={t('myWork.more', 'More for this queue')}
                items={[
                  {
                    id: 'view-all',
                    label: t('myWork.viewAll', 'View all'),
                    icon: ArrowRight,
                    href: quickViewHref(viewParams, include),
                  },
                ]}
                trigger={
                  <Button
                    size="icon-sm"
                    variant="outline"
                    aria-label={t('myWork.more', 'More for this queue')}
                  >
                    <MoreHorizontal aria-hidden="true" />
                  </Button>
                }
              />
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
    // Only the rule the tab does not say: requests still waiting.
    const toolbar = (
      <LockedChip hint={t('myWork.locked.hint', 'Set by this queue; it cannot be removed.')}>
        {t('myWork.locked.pending', 'Pending')}
      </LockedChip>
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
  const explain = t(`myWork.explain.${tab}`, TAB_EXPLAIN[tab])
  const isPhone = useIsMobile()
  // Triage of everything new is a secondary control (outline): the open
  // queue's "Triage these" is the screen's one main action. It stays on the
  // title's line, with its count, because what waits for triage is worth
  // seeing at a glance; under a More it would be hidden.
  // Shown (disabled) while the views load, so its arrival does not move the
  // title's line or what is under it.
  const triageButton =
    canTriage && (triageView || viewsPending) ? (
      <Button
        variant="outline"
        disabled={!triageView}
        onClick={() => {
          if (!triageView) return
          if (triageView.count > 0) openTriage(triageView.params, NEEDS_TRIAGE_VIEW)
          else router.push(quickViewHref(triageView.params, include))
        }}
      >
        {t('myWork.triage', 'Triage')}
        {triageView && triageView.count > 0 && (
          <span className="ms-1.5 tabular-nums">{triageView.count}</span>
        )}
      </Button>
    ) : null
  return (
    <Main>
      <PageStack>
        {/* Triage (with what waits) sits on the title's line: right after
            the title on a phone (the kit's title action, so it never drops
            to a line of its own), at the end of the row from md. The page
            sentence shows from md; on a phone each tab says what it holds
            behind its info mark. Refresh belongs to the list, in its title
            row. */}
        <PageHeader
          title={t('myWork.title')}
          description={<span className="hidden md:inline">{t('myWork.description')}</span>}
          titleAction={
            isPhone && triageButton ? <span className="ms-2">{triageButton}</span> : undefined
          }
        >
          {isPhone ? null : triageButton}
        </PageHeader>

        <Tabs value={tab} onValueChange={(v) => setQuery({ tab: v as MyWorkTab })}>
          <TabsList aria-label={t('myWork.tabs.label')}>
            {available.map((key) => (
              <TabsTrigger key={key} value={key}>
                {t(`myWork.tabs.${key}`, TAB_LABELS[key])}
                <TabsCount value={counts[key] ?? (pending[key] ? '…' : undefined)} />
              </TabsTrigger>
            ))}
          </TabsList>
          {/* The list's title row: the selected tab already shows the
              queue's name and its count (said once), so the row names it for
              assistive technology only and shows what it holds (a sentence
              on one line from md, behind the info mark on a phone) and
              Refresh. */}
          <ListTitleRow
            className="mt-3"
            title={t(`myWork.tabs.${tab}`, TAB_LABELS[tab])}
            titleHidden
            data-testid="my-work-title-row"
            start={
              <>
                <p
                  data-slot="my-work-hint"
                  className="hidden min-w-0 truncate text-meta text-muted-foreground md:block"
                  title={explain}
                >
                  {explain}
                </p>
                <Popover>
                  <PopoverTrigger asChild>
                    <Button
                      size="icon-sm"
                      variant="ghost"
                      className="shrink-0 md:hidden"
                      aria-label={t('myWork.about', 'About this list')}
                    >
                      <Info aria-hidden="true" />
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="text-sm">{explain}</PopoverContent>
                </Popover>
              </>
            }
          >
            {asOf && (
              // On a phone and from lg; at md the row's sentence needs the room.
              <span className="text-meta whitespace-nowrap text-muted-foreground md:max-lg:hidden">
                {t('myWork.updated', 'Updated')} <RelativeTime date={asOf} />
              </span>
            )}
            <RefreshButton onClick={refresh} label={t('myWork.refresh', 'Refresh')} />
          </ListTitleRow>
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
