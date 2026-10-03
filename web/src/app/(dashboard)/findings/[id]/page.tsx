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
 *   │ Fix                                   │ Activity · N ▸ │
 *   │ Overview | Evidence | … | Related     │                │
 *   └──────────────────────────────────────┴────────────────┘
 *
 * Below `lg` the rail sits between the header and "Why it matters", so status
 * and owner stay near the top on a phone.
 *
 * Activity is not a tab: the rail's "Activity · N comments" summary opens the
 * shared ActivityPanel (a sheet, `?activity=open`; old `?tab=activity` links
 * open it too). See web/docs/ui/activity-panel.md.
 */

import { useParams, useRouter } from 'next/navigation'
import { useSWRConfig } from 'swr'
import { AlertTriangle } from 'lucide-react'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DetailCallout } from '@/features/shared/components/detail-sheet'
import { useDetailTab } from '@/features/shared/components/detail-sheet-layout'
import { getTriageCacheKey } from '@/features/ai-triage/api'
import { useFindingApi } from '@/features/findings/api/use-findings-api'
import { useFindingActivityFeed } from '@/features/findings/hooks/use-finding-activity-feed'
import { useFindingTriage } from '@/features/findings/hooks/use-finding-triage'
import type { FindingDetail } from '@/features/findings/types'
import { toFindingDetail, findingShortName } from '@/features/findings/lib/finding-detail'
import { FindingActivityView } from '@/features/findings/components/finding-activity'
import { isBreach, daysUntil } from '@/features/sla/lib/sla'
import {
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

  const handleTriageCompleted = () => {
    if (id) mutate(getTriageCacheKey(id))
    mutateFinding()
  }

  const finding = apiFinding ? toFindingDetail(apiFinding) : null
  useBreadcrumbTitle(finding ? findingShortName(finding) : null)

  // Activity and comments: the rail's summary and the shared panel. The feed
  // also gives the Overview its latest AI triage.
  const feed = useFindingActivityFeed(id, {
    fromFinding: finding?.activities,
    onTriageActivity: handleTriageCompleted,
  })

  const triage = useFindingTriage(
    finding ?? { id, status: 'new', severity: 'medium', assignee: undefined },
    { onStatusChange: () => void mutateFinding(), onAssigneeChange: () => void mutateFinding() }
  )

  // Tabs: the source layout decides order and which apply; Related is last.
  // Activity is not a tab (it opens the ActivityPanel); `?tab=activity` links
  // open the panel instead (useActivityPanel's legacy tab).
  const layout = finding ? getSourceLayout(finding) : {}
  const baseTabs = getOrderedTabs(layout).filter(
    (t) => t !== 'attack-path' || (finding ? dataFlowCount(finding) > 0 : false)
  )
  const tabs = [...baseTabs.filter((t) => t !== 'related'), 'related']
  const [tab, setTab] = useDetailTab('tab', tabs)

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
          <FindingActivityView
            className="mt-3"
            feed={feed}
            findingId={id}
            subject={finding.title}
            shortcut
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
                  </TabsTrigger>
                ))}
              </TabsList>
            </div>

            <TabsContent value="overview" className="mt-5">
              <OverviewTab finding={finding} activities={feed.activities} />
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
