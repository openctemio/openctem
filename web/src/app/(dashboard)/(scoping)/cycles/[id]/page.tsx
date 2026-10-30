'use client'

/**
 * One CTEM cycle: its charter, the scope it froze, the attackers it assumes
 * and its outcome, with the next lifecycle step as the primary action. The
 * cycle is the program's scope object (docs/ui/scoping-ia-2026-10.md, C12).
 */

import { Suspense, useState } from 'react'
import { useParams } from 'next/navigation'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import {
  ErrorState,
  MetricStrip,
  PageHeader,
  PageStack,
  type MetricStripItem,
} from '@/features/shared'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useTranslation } from '@/context/i18n-provider'
import { CharterEditorSheet, summarizeEvaluation } from '@/features/cycles'
import { cycleTimeline } from '@/features/cycles/cycle-format'
import { useCycle, useCycleProfiles, useCycleScope } from '@/features/cycles/api'
import { CycleStatusBadge } from '@/features/cycles/components/cycle-status-badge'
import { CycleLifecycleAction } from '@/features/cycles/components/cycle-lifecycle-actions'
import {
  CycleCharterTab,
  CycleOutcomeTab,
  CycleProfilesTab,
  CycleScopeTab,
} from '@/features/cycles/components/cycle-detail-tabs'

const TABS = ['charter', 'scope', 'profiles', 'outcome'] as const
type CycleTab = (typeof TABS)[number]

function CycleDetail() {
  const params = useParams<{ id: string }>()
  const id = params?.id ?? null
  const { data: cycle, error, isLoading, mutate } = useCycle(id)
  useBreadcrumbTitle(cycle?.name)
  const frozen = cycle && cycle.status !== 'planning'
  const { t, locale } = useTranslation()
  const { data: scope, error: scopeError } = useCycleScope(frozen ? (id ?? null) : null)
  const { data: profiles, error: profilesError } = useCycleProfiles(id)
  const [tabParam, setTab] = useUrlFilter('tab', 'charter')
  const tab: CycleTab = (TABS as readonly string[]).includes(tabParam)
    ? (tabParam as CycleTab)
    : 'charter'
  const [charterOpen, setCharterOpen] = useState(false)

  if (error) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={t('scoping.cycleDetail.title', 'Cycle')} />
          <ErrorState
            title={t('scoping.cycleDetail.loadError', 'this cycle')}
            error={error}
            onRetry={() => mutate()}
          />
        </PageStack>
      </Main>
    )
  }
  if (isLoading || !cycle) {
    return (
      <Main>
        <PageStack>
          <Skeleton className="h-9 w-64" />
          <Skeleton className="h-[68px] w-full rounded-xl" />
          <Skeleton className="h-64 w-full" />
        </PageStack>
      </Main>
    )
  }

  const charter = cycle.charter ?? {}
  const when = cycleTimeline(cycle, t, locale)
  const profileCount = profiles?.data?.length
  const criteria = charter.success_criteria?.length ?? 0
  const metrics: MetricStripItem[] = [
    {
      key: 'timeline',
      label: t('scoping.cycleDetail.timeline', 'Timeline'),
      value: when.value,
      hint: when.hint,
    },
    {
      key: 'scope',
      label: t('scoping.cycleDetail.assetsInScope', 'Assets in scope'),
      value: frozen ? (scope?.length ?? (scopeError ? '—' : '…')) : '—',
      hint:
        frozen && scopeError
          ? t('scope.cycles.scopeLoadFailed', 'Scope could not be loaded.')
          : frozen
            ? t('scoping.cycleDetail.frozenOnActivate', 'Frozen on Activate')
            : t(
                'scoping.cycleDetail.inScopeServices',
                '{n, plural, one {# in-scope service} other {# in-scope services}}',
                { n: charter.in_scope_services?.length ?? 0 }
              ),
      onClick: () => setTab('scope'),
      active: tab === 'scope',
    },
    {
      key: 'profiles',
      label: t('scoping.cycleDetail.attackerProfiles', 'Attacker profiles'),
      value: profileCount ?? (profilesError ? '—' : '…'),
      hint: profilesError
        ? t('scope.cycles.profilesLoadFailed', 'Attacker profiles could not be loaded.')
        : undefined,
      onClick: () => setTab('profiles'),
      active: tab === 'profiles',
    },
    {
      key: 'criteria',
      label: t('scoping.cycleDetail.successCriteria', 'Success criteria'),
      value: summarizeEvaluation(cycle.charter_evaluation, t) ?? criteria,
      hint: cycle.charter_evaluation
        ? undefined
        : t('scoping.cycleDetail.evaluatedAtClose', 'Evaluated at close'),
      onClick: () => setTab('outcome'),
      active: tab === 'outcome',
    },
  ]

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader
            title={cycle.name}
            description={
              cycle.description ||
              t('scoping.cycleDetail.description', 'A CTEM cycle: its charter, scope and outcome.')
            }
          >
            <CycleStatusBadge status={cycle.status} />
            <CycleLifecycleAction
              cycle={cycle}
              onDone={(updated, action) => {
                void mutate(updated, { revalidate: true })
                if (action === 'close') setTab('outcome')
                if (action === 'activate') setTab('scope')
              }}
            />
          </PageHeader>

          <MetricStrip items={metrics} />

          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="charter">
                {t('scoping.cycleDetail.tab.charter', 'Charter')}
              </TabsTrigger>
              <TabsTrigger value="scope">
                {t('scoping.cycleDetail.tab.scope', 'Scope')}{' '}
                {frozen && <TabsCount value={scope?.length} />}
              </TabsTrigger>
              <TabsTrigger value="profiles">
                {t('scoping.cycleDetail.tab.profiles', 'Attacker profiles')}{' '}
                <TabsCount value={profileCount} />
              </TabsTrigger>
              <TabsTrigger value="outcome">
                {t('scoping.cycleDetail.tab.outcome', 'Outcome')}
              </TabsTrigger>
            </TabsList>
            <TabsContent value="charter">
              <CycleCharterTab cycle={cycle} onEdit={() => setCharterOpen(true)} />
            </TabsContent>
            <TabsContent value="scope">
              <CycleScopeTab cycle={cycle} />
            </TabsContent>
            <TabsContent value="profiles">
              <CycleProfilesTab cycle={cycle} />
            </TabsContent>
            <TabsContent value="outcome">
              <CycleOutcomeTab cycle={cycle} onSaved={() => void mutate()} />
            </TabsContent>
          </Tabs>
        </PageStack>
      </Main>

      <CharterEditorSheet
        cycle={cycle}
        open={charterOpen}
        onOpenChange={setCharterOpen}
        onSaved={() => void mutate()}
      />
    </>
  )
}

export default function CycleDetailPage() {
  // useSearchParams (the tab in the URL) needs a Suspense boundary.
  return (
    <Suspense
      fallback={
        <Main>
          <Skeleton className="h-9 w-64" />
        </Main>
      }
    >
      <CycleDetail />
    </Suspense>
  )
}
