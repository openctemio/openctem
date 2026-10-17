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

import { useTranslation } from '@/context/i18n-provider'
import { findingStatusesInCategory } from '@/features/findings/types/finding.types'
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
  FindingTenableRescanSection,
  FindingWhyItMatters,
  OverviewTab,
  RelatedTab,
  RemediationTab,
} from '@/features/findings/components/detail'
import { FindingTaskBand } from '@/features/remediation-hub/components/finding-task-band'
import { PentestDetailsTab } from '@/features/findings/components/detail/pentest-details-tab'
import { getSourceLayout, getOrderedTabs } from '@/features/findings/config/source-layout'
import '@/features/findings/config/register-layouts'

const CLOSED = new Set<string>(findingStatusesInCategory('closed'))

/**
 * Tab labels: English fallbacks of findings.detail.tab.<key>. The keys are the
 * `?tab=` values; `attack-path` stays as the data-flow tab's key so existing
 * links keep opening it.
 */
const TAB_LABEL: Record<string, string> = {
  overview: 'Overview',
  evidence: 'Evidence',
  remediation: 'Remediation',
  'attack-path': 'Data flow',
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
  return f.dataFlow?.steps.length ?? 0
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
  const { t } = useTranslation()
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
    (key) => key !== 'attack-path' || (finding ? dataFlowCount(finding) > 0 : false)
  )
  const tabs = [...baseTabs.filter((key) => key !== 'related'), 'related']
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
            <h1 className="text-2xl font-semibold">
              {t('findings.detail.notFound.title', 'Finding not found')}
            </h1>
            <p className="mt-2 text-muted-foreground">
              {t(
                'findings.detail.notFound.description',
                'It does not exist, or you do not have access to it.'
              )}
            </p>
            <Button className="mt-4" onClick={() => router.push('/findings')}>
              {t('findings.detail.notFound.back', 'Back to findings')}
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
          aria-label={t('findings.detail.propertiesAria', 'Finding properties')}
          className="min-w-0 lg:sticky lg:top-4 lg:col-start-2 lg:row-span-4 lg:row-start-1 lg:self-start"
        >
          <div className="rounded-lg border bg-card p-3 lg:p-4">
            <FindingProperties finding={finding} triage={triage} />
          </div>
          <FindingRetestSection
            finding={{ ...finding, status: triage.status }}
            className="mt-4 rounded-lg border bg-card p-3 lg:p-4"
          />
          <FindingTenableRescanSection
            finding={finding}
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
                  ? Math.abs(slaDays) === 1
                    ? t('findings.detail.sla.overdueOne', 'SLA overdue by 1 day')
                    : t('findings.detail.sla.overdueMany', 'SLA overdue by {n} days', {
                        n: Math.abs(slaDays),
                      })
                  : t('findings.detail.sla.breached', 'SLA breached')
              }
            >
              {finding.priorityClass
                ? t(
                    'findings.detail.sla.classPastDeadline',
                    '{class} findings must be fixed within the SLA; this one is past its deadline.',
                    { class: finding.priorityClass }
                  )
                : t(
                    'findings.detail.sla.pastDeadline',
                    'This finding is past its remediation deadline.'
                  )}
            </DetailCallout>
          )}
          <FindingWhyItMatters finding={finding} />
          <FindingTaskBand findingId={finding.id} />
          <FindingFixCard finding={finding} onOpenPlan={() => setTab('remediation')} />
        </div>

        <div className="min-w-0 lg:col-start-1">
          <Tabs value={tab} onValueChange={(v) => setTab(v)}>
            <div className="-mx-1 overflow-x-auto px-1">
              <TabsList>
                {tabs.map((key) => (
                  <TabsTrigger key={key} value={key}>
                    {TAB_LABEL[key] ? t(`findings.detail.tab.${key}`, TAB_LABEL[key]) : key}
                    {key === 'evidence' && evidenceCount(finding) > 0 && (
                      <TabsCount value={evidenceCount(finding)} />
                    )}
                    {key === 'attack-path' && <TabsCount value={dataFlowCount(finding)} />}
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
