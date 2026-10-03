'use client'

/**
 * Finding detail page.
 *
 * Answers, in the first screen: what it is (header), how bad it is for us and
 * why (Why it matters), how to fix it (Fix), and who owns it by when (the
 * properties rail). Everything else is one tab away. Design and research:
 * web/docs/finding-detail.md.
 *
 *   ┌──────────────────────────────────────┬────────────────┐
 *   │ header: type · CVE · title · actions  │ properties     │
 *   │ SLA callout (when overdue)            │ (sticky rail)  │
 *   │ Why it matters                        │                │
 *   │ Fix                                   │                │
 *   │ Overview | Evidence | … | Activity    │                │
 *   └──────────────────────────────────────┴────────────────┘
 *
 * Below `lg` the rail sits between the header and "Why it matters", so status
 * and owner stay near the top on a phone.
 */

import { useParams, useRouter } from 'next/navigation'
import { useSWRConfig } from 'swr'
import { toast } from 'sonner'
import { AlertTriangle, Wifi, WifiOff } from 'lucide-react'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DetailCallout } from '@/features/shared/components/detail-sheet'
import { useDetailTab } from '@/features/shared/components/detail-sheet-layout'
import { csrfFetch } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { getTriageCacheKey } from '@/features/ai-triage/api'
import { useFindingApi, useAddFindingCommentApi } from '@/features/findings/api/use-findings-api'
import { useFindingActivitiesInfinite } from '@/features/findings/api/use-finding-activities-api'
import { useActivityStream } from '@/features/findings/hooks/use-activity-stream'
import { useFindingTriage } from '@/features/findings/hooks/use-finding-triage'
import type { ActivityType, FindingDetail } from '@/features/findings/types'
import { mergeFindingActivities } from '@/features/findings/lib/finding-activities'
import { toFindingDetail, findingShortName } from '@/features/findings/lib/finding-detail'
import { isBreach, daysUntil } from '@/features/sla/lib/sla'
import {
  ActivityPanel,
  DataFlowTab,
  EvidenceTab,
  FindingFixCard,
  FindingHeader,
  FindingProperties,
  FindingRetestSection,
  FindingWhyItMatters,
  OverviewTab,
  RelatedTab,
  RemediationTab,
} from '@/features/findings/components/detail'
import { PentestDetailsTab } from '@/features/findings/components/detail/pentest-details-tab'
import { getSourceLayout, getOrderedTabs } from '@/features/findings/config/source-layout'
import '@/features/findings/config/register-layouts'

const TRIAGE_ACTIVITY: ActivityType[] = ['ai_triage', 'ai_triage_failed']
const CLOSED = new Set([
  'resolved',
  'verified',
  'false_positive',
  'accepted',
  'accepted_risk',
  'duplicate',
])

const TAB_LABEL: Record<string, string> = {
  overview: 'Overview',
  evidence: 'Evidence',
  remediation: 'Remediation',
  'attack-path': 'Attack path',
  pentest: 'Pentest details',
  related: 'Related',
  activity: 'Activity',
}

function evidenceCount(f: FindingDetail) {
  return (
    (f.contextSnippet || f.snippet ? 1 : 0) +
    (f.stacks?.length || 0) +
    (f.relatedLocations?.length || 0) +
    (f.attachments?.length || 0)
  )
}

function dataFlowCount(f: FindingDetail) {
  return (
    (f.dataFlow?.sources?.length || 0) +
    (f.dataFlow?.intermediates?.length || 0) +
    (f.dataFlow?.sinks?.length || 0)
  )
}

/** Same grid as the page, so nothing jumps when the data arrives. */
function LoadingSkeleton() {
  return (
    <div className="grid gap-x-8 gap-y-5 lg:grid-cols-[minmax(0,1fr)_19rem]" aria-busy>
      <div className="space-y-5">
        <div className="space-y-3">
          <div className="flex gap-1.5">
            <Skeleton className="h-5 w-12" />
            <Skeleton className="h-5 w-28" />
          </div>
          <Skeleton className="h-8 w-3/4" />
          <div className="flex gap-2">
            <Skeleton className="h-8 w-24" />
            <Skeleton className="h-8 w-24" />
          </div>
        </div>
        <Skeleton className="h-36 w-full rounded-lg" />
        <Skeleton className="h-28 w-full rounded-lg" />
        <Skeleton className="h-9 w-80" />
        <Skeleton className="h-40 w-full" />
      </div>
      <div className="space-y-3 rounded-lg border p-4">
        {Array.from({ length: 9 }).map((_, i) => (
          <div key={i} className="grid grid-cols-[6.5rem_1fr] items-center gap-3">
            <Skeleton className="h-3.5 w-16" />
            <Skeleton className="h-6 w-full" />
          </div>
        ))}
      </div>
    </div>
  )
}

export default function FindingDetailPage() {
  const params = useParams()
  const router = useRouter()
  const id = params.id as string
  const { mutate } = useSWRConfig()

  const { data: apiFinding, error, isLoading, mutate: mutateFinding } = useFindingApi(id)
  const { trigger: addComment } = useAddFindingCommentApi(id)
  const {
    activities: apiActivities,
    total: activitiesTotal,
    isLoadingMore,
    isReachingEnd,
    loadMore,
    mutate: mutateActivities,
  } = useFindingActivitiesInfinite(id)

  const handleTriageCompleted = () => {
    if (id) mutate(getTriageCacheKey(id))
    mutateFinding()
    mutateActivities()
  }

  const {
    realtimeActivities,
    status: streamStatus,
    clearActivities,
  } = useActivityStream(id, {
    onActivity: (activity) => {
      mutateActivities()
      if (TRIAGE_ACTIVITY.includes(activity.type)) handleTriageCompleted()
    },
  })

  const finding = apiFinding ? toFindingDetail(apiFinding) : null
  useBreadcrumbTitle(finding ? findingShortName(finding) : null)

  const triage = useFindingTriage(
    finding ?? { id, status: 'new', severity: 'medium', assignee: undefined },
    { onStatusChange: () => void mutateFinding(), onAssigneeChange: () => void mutateFinding() }
  )

  // Tabs: the source layout decides order and which apply; Activity is always
  // last but one, before Related.
  const layout = finding ? getSourceLayout(finding) : {}
  const baseTabs = getOrderedTabs(layout).filter(
    (t) => t !== 'attack-path' || (finding ? dataFlowCount(finding) > 0 : false)
  )
  const tabs = [...baseTabs.filter((t) => t !== 'related'), 'activity', 'related']
  const [tab, setTab] = useDetailTab('tab', tabs)

  const { activities: allActivities, count: activityCount } = mergeFindingActivities({
    fetched: apiActivities,
    fetchedTotal: activitiesTotal,
    realtime: realtimeActivities,
    fromFinding: finding?.activities,
  })

  const commentRequest = async (url: string, init: RequestInit, done: string, failed: string) => {
    try {
      const res = await csrfFetch(url, { credentials: 'include', ...init })
      if (!res.ok) throw new Error(failed)
      await mutateActivities()
      clearActivities()
      toast.success(done)
    } catch (e) {
      toast.error(getErrorMessage(e, failed))
    }
  }

  const handleAddComment = async (content: string) => {
    if (!content.trim()) return
    try {
      await addComment({ content })
      await mutateActivities()
      clearActivities()
      toast.success('Comment added')
    } catch (e) {
      toast.error(getErrorMessage(e, 'Failed to add comment'))
    }
  }

  if (isLoading) {
    return (
      <Main>
        <LoadingSkeleton />
      </Main>
    )
  }

  if (error || !finding) {
    return (
      <Main>
        <div className="flex h-[50vh] items-center justify-center">
          <div className="text-center">
            <h1 className="text-2xl font-semibold">Finding not found</h1>
            <p className="mt-2 text-muted-foreground">
              It does not exist, or you do not have access to it.
            </p>
            <Button className="mt-4" onClick={() => router.push('/findings')}>
              Back to findings
            </Button>
          </div>
        </div>
      </Main>
    )
  }

  const slaDays = daysUntil(finding.slaDeadline)
  const slaLate =
    !CLOSED.has(triage.status) && (isBreach(finding.slaStatus) || (slaDays !== null && slaDays < 0))

  return (
    <Main>
      <div className="grid gap-x-8 gap-y-5 lg:grid-cols-[minmax(0,1fr)_19rem] lg:grid-rows-[auto_auto_auto_1fr]">
        <div className="min-w-0 lg:col-start-1">
          <FindingHeader
            finding={finding}
            status={triage.status}
            onTriageCompleted={handleTriageCompleted}
          />
        </div>

        <aside
          aria-label="Finding properties"
          className="min-w-0 lg:sticky lg:top-4 lg:col-start-2 lg:row-span-4 lg:row-start-1 lg:self-start"
        >
          <div className="rounded-lg border bg-card p-3 lg:p-4">
            <FindingProperties finding={finding} triage={triage} />
          </div>
          <FindingRetestSection
            finding={{ ...finding, status: triage.status }}
            className="mt-4 rounded-lg border bg-card p-3 lg:p-4"
          />
        </aside>

        <div className="min-w-0 space-y-4 lg:col-start-1">
          {slaLate && (
            <DetailCallout
              tone="destructive"
              icon={AlertTriangle}
              title={
                slaDays !== null && slaDays < 0
                  ? `SLA overdue by ${Math.abs(slaDays)} day${Math.abs(slaDays) === 1 ? '' : 's'}`
                  : 'SLA breached'
              }
            >
              {finding.priorityClass
                ? `${finding.priorityClass} findings must be fixed within the SLA; this one is past its deadline.`
                : 'This finding is past its remediation deadline.'}
            </DetailCallout>
          )}
          <FindingWhyItMatters finding={finding} />
          <FindingFixCard finding={finding} onOpenPlan={() => setTab('remediation')} />
        </div>

        <div className="min-w-0 lg:col-start-1">
          <Tabs value={tab} onValueChange={(v) => setTab(v)}>
            <div className="-mx-1 overflow-x-auto px-1">
              <TabsList>
                {tabs.map((t) => (
                  <TabsTrigger key={t} value={t}>
                    {TAB_LABEL[t] ?? t}
                    {t === 'evidence' && evidenceCount(finding) > 0 && (
                      <TabsCount value={evidenceCount(finding)} />
                    )}
                    {t === 'attack-path' && <TabsCount value={dataFlowCount(finding)} />}
                    {t === 'activity' && <TabsCount value={activityCount} />}
                  </TabsTrigger>
                ))}
              </TabsList>
            </div>

            <TabsContent value="overview" className="mt-5">
              <OverviewTab finding={finding} activities={allActivities} />
            </TabsContent>
            <TabsContent value="evidence" className="mt-5">
              <EvidenceTab evidence={finding.evidence} finding={finding} />
            </TabsContent>
            <TabsContent value="remediation" className="mt-5">
              <RemediationTab remediation={finding.remediation} finding={finding} />
            </TabsContent>
            <TabsContent value="attack-path" className="mt-5">
              <DataFlowTab finding={finding} />
            </TabsContent>
            <TabsContent value="pentest" className="mt-5">
              <PentestDetailsTab finding={finding} />
            </TabsContent>
            <TabsContent value="activity" className="mt-5">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-sm font-semibold">Activity ({activityCount})</h2>
                <span
                  className="flex items-center gap-1 text-xs text-muted-foreground"
                  title={
                    streamStatus === 'connected'
                      ? 'Live updates on'
                      : streamStatus === 'connecting'
                        ? 'Connecting'
                        : 'Live updates off'
                  }
                >
                  {streamStatus === 'connected' ? (
                    <Wifi className="h-3.5 w-3.5 text-success" aria-hidden />
                  ) : (
                    <WifiOff className="h-3.5 w-3.5" aria-hidden />
                  )}
                  {streamStatus === 'connected' ? 'Live' : 'Offline'}
                </span>
              </div>
              <div className="rounded-lg border">
                <ActivityPanel
                  activities={allActivities}
                  onAddComment={(c) => void handleAddComment(c)}
                  onEditComment={(cid, content) =>
                    void commentRequest(
                      `/api/v1/findings/${id}/comments/${cid}`,
                      {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ content }),
                      },
                      'Comment updated',
                      'Failed to update comment'
                    )
                  }
                  onDeleteComment={(cid) =>
                    void commentRequest(
                      `/api/v1/findings/${id}/comments/${cid}`,
                      { method: 'DELETE' },
                      'Comment deleted',
                      'Failed to delete comment'
                    )
                  }
                  total={activitiesTotal}
                  hasMore={!isReachingEnd}
                  isLoadingMore={isLoadingMore}
                  onLoadMore={loadMore}
                />
              </div>
            </TabsContent>
            <TabsContent value="related" className="mt-5">
              <RelatedTab finding={finding} />
            </TabsContent>
          </Tabs>
        </div>
      </div>
      {triage.dialogs}
    </Main>
  )
}
