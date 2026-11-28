'use client'

/**
 * Finding detail page, on the shared detail kit (docs/ui-style-contract.md,
 * "Detail pages"). Design and research: web/docs/finding-detail.md.
 *
 *   header: chips, place in the list, title, [More] [secondary] [primary]
 *   tabs:   Overview | Evidence | Validation | Remediation | … | Related | Details
 *   ┌──────────────────────────────────────┬────────────────┐
 *   │ bands (approval, SLA overdue, task)  │ properties     │
 *   │ the tab's panel                      │ (sticky rail)  │
 *   │                                      │ Activity N ▸   │
 *   └──────────────────────────────────────┴────────────────┘
 *
 * The first screen answers: what it is (header), how bad it is for us and
 * why, how to fix it and what proves the fix (Overview), and who owns it by
 * when (the properties). Below 1280 px the properties sit under the header
 * (two columns while there is room), then the tabs; on a phone the bands come
 * first, so an overdue deadline is the first thing read.
 *
 * Activity is not a tab: the rail's "Activity, N comments" summary opens the
 * shared ActivityPanel (a sheet, `?activity=open`; old `?tab=activity` links
 * open it too). See web/docs/ui/activity-panel.md.
 */

import { FindingHowWeFoundThis } from '@/features/exploration/components/how-we-found-this'
import { useTranslation } from '@/context/i18n-provider'
import { findingStatusesInCategory } from '@/features/findings/types/finding.types'
import { useParams, useRouter } from 'next/navigation'
import { useSWRConfig } from 'swr'
import { useMemo } from 'react'
import { cn } from '@/lib/utils'
import {
  AlertTriangle,
  FlaskConical,
  Info,
  LayoutGrid,
  Link2,
  NotebookText,
  ScanSearch,
  Workflow,
  Wrench,
  type LucideIcon,
} from 'lucide-react'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import { SettleGroup } from '@/features/shared/components/settle-group'
import { PageStack } from '@/features/shared/components/page-stack'
import {
  DETAIL_GRID,
  DETAIL_MAIN,
  DETAIL_RAIL,
  DETAIL_STRIP,
  DetailSectionBlock,
  DetailSectionList,
} from '@/features/shared/components/detail'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DetailCallout, DetailSections } from '@/features/shared/components/detail-sheet'
import { useDetailTab } from '@/features/shared/components/detail-sheet-layout'
import { getTriageCacheKey } from '@/features/ai-triage/api'
import {
  useFindingPageApi,
  useFindingValidationEvidenceApi,
} from '@/features/findings/api/use-findings-api'
import {
  planMethod,
  useFindingVerificationPlan,
} from '@/features/findings/api/use-finding-verification'
import { useFindingActivityFeed } from '@/features/findings/hooks/use-finding-activity-feed'
import { useFindingTriage } from '@/features/findings/hooks/use-finding-triage'
import { useFindingEvidenceCount } from '@/features/findings/hooks/use-finding-evidence-count'
import type { FindingDetail } from '@/features/findings/types'
import { toFindingDetail, findingShortName } from '@/features/findings/lib/finding-detail'
import { showsProofOfFix } from '@/features/findings/lib/closure'
import { FindingActivityView } from '@/features/findings/components/finding-activity'
import { isBreach, daysUntil } from '@/features/sla/lib/sla'
import {
  DataFlowTab,
  EvidenceTab,
  FindingApprovalBand,
  FindingFixCard,
  FindingHeader,
  FindingProperties,
  FindingRetestSection,
  FindingRetestCheckSection,
  FindingScannerOutput,
  FindingTenableRescanSection,
  FindingImportHistory,
  FindingSeenBy,
  FindingSourceRecords,
  FindingWhyItMatters,
  OverviewTab,
  RelatedTab,
  RemediationTab,
  ValidationEvidencePanel,
  VerificationPanel,
} from '@/features/findings/components/detail'
import { FromTaskCrumb } from '@/features/remediation-hub/components/from-task-crumb'
import { FindingTaskBand } from '@/features/remediation-hub/components/finding-task-band'
import { isLoadFailure } from '@/features/findings/components/detail/section-load-error'
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
  validation: 'Validation',
  details: 'Details',
}

/** One icon per tab: what the tab holds (ui-style-contract, "Tab icons"). */
const TAB_ICON: Record<string, LucideIcon> = {
  overview: LayoutGrid,
  evidence: ScanSearch,
  validation: FlaskConical,
  remediation: Wrench,
  'attack-path': Workflow,
  pentest: NotebookText,
  related: Link2,
  details: Info,
}

function dataFlowCount(f: FindingDetail) {
  return f.dataFlow?.steps.length ?? 0
}

/**
 * Same blocks and order as the page (header, tab strip, properties, panel),
 * so the swap to the real page moves nothing.
 */
function LoadingSkeleton() {
  return (
    <PageStack aria-busy data-testid="finding-detail-skeleton">
      <div className="space-y-2">
        <div className="flex gap-1.5">
          <Skeleton className="h-6 w-28" />
          <Skeleton className="h-6 w-28" />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Skeleton className="h-8 w-3/5" />
          <div className="flex gap-2">
            <Skeleton className="h-8 w-24" />
            <Skeleton className="h-8 w-28" />
          </div>
        </div>
      </div>
      <div className={cn(DETAIL_GRID, 'gap-page')}>
        <div className={cn(DETAIL_RAIL, 'space-y-2')}>
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="grid grid-cols-[6.75rem_1fr] items-center gap-3">
              <Skeleton className="h-4 w-16" />
              <Skeleton className="h-6 w-full" />
            </div>
          ))}
        </div>
        <div className={DETAIL_STRIP}>
          <Skeleton className="h-10 w-full max-w-xl" />
        </div>
        <div className={DETAIL_MAIN}>
          <Skeleton className="h-36 w-full" />
          <Skeleton className="h-28 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      </div>
    </PageStack>
  )
}

export default function FindingDetailPage() {
  const { t } = useTranslation()
  const params = useParams()
  const router = useRouter()
  const id = params.id as string
  const { mutate } = useSWRConfig()

  // The page renders its own error state, so the generic error toast is off
  // (a bad link must not also pop a raw error). 4xx is never retried.
  const {
    data: apiFinding,
    error,
    isLoading,
    mutate: mutateFinding,
  } = useFindingPageApi(id, { onError: () => {} })

  const handleTriageCompleted = () => {
    if (id) mutate(getTriageCacheKey(id))
    mutateFinding()
  }

  // Stable identity: children and the activity feed memoise on this object.
  const finding = useMemo(() => (apiFinding ? toFindingDetail(apiFinding) : null), [apiFinding])
  useBreadcrumbTitle(finding ? findingShortName(finding) : null)

  // Activity and comments: the rail's summary and the shared panel. The feed
  // also gives the Overview its latest AI triage.
  const feed = useFindingActivityFeed(id, {
    fromFinding: finding?.activities,
    // Nothing else is requested until the finding itself loaded: a bad link
    // costs one request, not three.
    enabled: !!finding,
    onTriageActivity: handleTriageCompleted,
  })

  const triage = useFindingTriage(
    finding ?? { id, status: 'new', severity: 'medium', assignee: undefined },
    { onStatusChange: () => void mutateFinding(), onAssigneeChange: () => void mutateFinding() }
  )

  // The Evidence tab's number counts every source the tab shows.
  const evidenceTabCount = useFindingEvidenceCount(finding)

  // Tabs: the source layout decides order and which apply; Related is last.
  // Activity is not a tab (it opens the ActivityPanel); `?tab=activity` links
  // open the panel instead (useActivityPanel's legacy tab).
  const layout = finding ? getSourceLayout(finding) : {}
  const baseTabs = getOrderedTabs(layout).filter(
    (key) => key !== 'attack-path' || (finding ? dataFlowCount(finding) > 0 : false)
  )
  // Validation results have their own tab, shown when there is a result or a
  // reachability check the viewer could run (the requests are the panel's own).
  const { data: validation } = useFindingValidationEvidenceApi(finding?.id ?? null)
  const { data: plan } = useFindingVerificationPlan(finding?.id ?? null)
  const validationCount = validation?.evidence?.length ?? 0
  const hasValidation = validationCount > 0 || !!planMethod(plan, 'safe_check')?.available
  // A key without a label is not a tab (no raw key as a tab name). Evidence is
  // followed by Validation; Related and Details close the strip.
  const tabs = [
    ...baseTabs
      .filter((key) => key !== 'related')
      .flatMap((key) => (key === 'evidence' && hasValidation ? [key, 'validation'] : [key])),
    'related',
    'details',
  ].filter((key) => TAB_LABEL[key])
  const [tab, setTab] = useDetailTab('tab', tabs)

  if (isLoading) {
    return (
      <Main>
        <LoadingSkeleton />
      </Main>
    )
  }

  // A server or network failure is retryable and must not read as "not found".
  // Missing and refused ids share one copy, so the page gives no oracle.
  if (error && !finding && isLoadFailure(error)) {
    return (
      <Main>
        <div
          className="flex h-[50vh] items-center justify-center"
          data-testid="finding-load-failed"
        >
          <div className="text-center">
            <h1 className="text-2xl font-semibold">
              {t('findings.detail.loadFailed.title', 'Could not load this finding')}
            </h1>
            <p className="mt-2 text-muted-foreground">
              {t(
                'findings.detail.loadFailed.description',
                'Something went wrong on our side or the connection dropped. Try again.'
              )}
            </p>
            <div className="mt-4 flex justify-center gap-2">
              <Button onClick={() => void mutateFinding()}>{t('common.retry', 'Retry')}</Button>
              <Button variant="outline" onClick={() => router.push('/findings')}>
                {t('findings.detail.notFound.back', 'Back to findings')}
              </Button>
            </div>
          </div>
        </div>
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
      {/* The bands and side panels load their own data: show the page once
          they answered (at most 1.5 s), so nothing pushes the content down. */}
      <SettleGroup fallback={<LoadingSkeleton />}>
        <PageStack>
          <FromTaskCrumb />
          <FindingHeader
            finding={finding}
            status={triage.status}
            onTriageCompleted={handleTriageCompleted}
            onStatusMove={triage.changeStatus}
          />
          <Tabs value={tab} onValueChange={(v) => setTab(v)} className={DETAIL_GRID}>
            <aside
              aria-label={t('findings.detail.propertiesAria', 'Finding properties')}
              className={DETAIL_RAIL}
            >
              <div className="max-md:rounded-lg max-md:border max-md:bg-card max-md:px-3">
                <FindingProperties finding={finding} triage={triage} />
              </div>
              <FindingActivityView
                className="mt-4"
                feed={feed}
                findingId={id}
                subject={finding.title}
                shortcut
              />
            </aside>

            <div className={DETAIL_STRIP}>
              <TabsList>
                {tabs.map((key) => {
                  const Icon = TAB_ICON[key]
                  return (
                    <TabsTrigger key={key} value={key}>
                      <Icon aria-hidden />
                      {t(`findings.detail.tab.${key}`, TAB_LABEL[key])}
                      {key === 'evidence' && evidenceTabCount - validationCount > 0 && (
                        <TabsCount value={evidenceTabCount - validationCount} />
                      )}
                      {key === 'validation' && validationCount > 0 && (
                        <TabsCount value={validationCount} />
                      )}
                      {key === 'attack-path' && <TabsCount value={dataFlowCount(finding)} />}
                    </TabsTrigger>
                  )
                })}
              </TabsList>
            </div>

            <div className={DETAIL_MAIN}>
              {/* The bands load their own data and render nothing without it. */}
              <div
                data-slot="finding-bands"
                className="flex min-w-0 flex-col gap-3 empty:hidden max-xl:order-1"
              >
                <FindingApprovalBand findingId={finding.id} onDecided={() => mutateFinding()} />
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
                <FindingTaskBand findingId={finding.id} />
              </div>

              <div data-slot="finding-panel" className="min-w-0 max-xl:order-4">
                <TabsContent value="overview">
                  <DetailSectionList>
                    <FindingWhyItMatters finding={finding} flat />
                    <FindingFixCard
                      finding={finding}
                      flat
                      onOpenPlan={() => setTab('remediation')}
                    />
                    <FindingScannerOutput finding={finding} />
                    {/* Only where a fix can be proven: not on a false positive, an
                        accepted risk, a duplicate or a resolve that was no fix. */}
                    {showsProofOfFix(triage.status, finding.closureReason) && (
                      <DetailSectionBlock
                        title={t('findings.detail.proofOfFix', 'Proof of fix')}
                        className="has-[[data-slot=finding-proof]:empty]:hidden"
                      >
                        {/* The ways to prove the fix side by side once each has 28rem:
                            one column up to 1440 px, two at 1920, three at 2560. */}
                        <div
                          data-slot="finding-proof"
                          className="grid min-w-0 grid-cols-[repeat(auto-fit,minmax(min(100%,28rem),1fr))] items-start gap-x-8 gap-y-5"
                        >
                          <VerificationPanel findingId={finding.id} />
                          <FindingRetestSection finding={{ ...finding, status: triage.status }} />
                          <FindingRetestCheckSection finding={finding} />
                          <FindingTenableRescanSection finding={finding} />
                        </div>
                      </DetailSectionBlock>
                    )}
                  </DetailSectionList>
                </TabsContent>
                <TabsContent value="evidence">
                  <EvidenceTab evidence={finding.evidence} finding={finding} validation={false} />
                </TabsContent>
                <TabsContent value="validation">
                  <ValidationEvidencePanel findingId={finding.id} />
                </TabsContent>
                <TabsContent value="remediation">
                  <RemediationTab remediation={finding.remediation} finding={finding} />
                </TabsContent>
                <TabsContent value="attack-path">
                  <DataFlowTab finding={finding} />
                </TabsContent>
                <TabsContent value="pentest">
                  <PentestDetailsTab finding={finding} />
                </TabsContent>
                <TabsContent value="related">
                  <RelatedTab finding={finding} />
                </TabsContent>
                <TabsContent value="details">
                  <DetailSections>
                    <OverviewTab finding={finding} scannerOutput={false} />
                    <FindingHowWeFoundThis findingId={finding.id} />
                    <FindingSourceRecords findingId={finding.id} />
                    <FindingSeenBy findingId={finding.id} />
                    <FindingImportHistory findingId={finding.id} />
                  </DetailSections>
                </TabsContent>
              </div>
            </div>
          </Tabs>
        </PageStack>
        {triage.dialogs}
      </SettleGroup>
    </Main>
  )
}
