'use client'

import { Main } from '@/components/layout'
import { PageHeader, PageStack } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useModuleEnabled, useTenantModules } from '@/features/integrations/api/use-tenant-modules'
import {
  useAdaptedCampaigns,
  useAdaptedPentestFindingPage,
  RETEST_PENDING_STATUSES,
} from '@/features/pentest/api/use-pentest-api'
import { useFindingsCount } from '@/features/findings/api/use-findings-count'
import { useReadyToCloseCount } from '@/features/closure-review/api'
import { useHasPermission, Permission } from '@/lib/permissions'
import {
  REOPENED_RECENTLY,
  STILL_REPRODUCES,
  VALIDATED_RECENTLY,
  awaitingValidationQuery,
  findingsHref,
  switchedOffModules,
} from '@/features/validation/lib/overview-queries'
import {
  CoverageSummary,
  ModulesOffHint,
  OutcomesList,
  WaitingForYou,
  type StartLink,
  type WaitingItem,
} from '@/features/validation/components/validation-overview'

/**
 * Validation › Overview (research/370): what is waiting for me, how much of
 * the closed P0/P1 work is proven, and what the latest re-checks said.
 *
 * Every figure is a findings list (or the coverage KPI, the definition the
 * CTEM cycle's close gate uses) read through the ordinary API, so the server
 * applies the viewer's tenant and data scope. A module the organization
 * switched off leaves the page without a request to its API; owners and
 * admins get one quiet line pointing at Settings › Modules.
 */
export default function ValidationOverviewPage() {
  const { t } = useTranslation()
  const canPentest = useHasPermission(Permission.PentestRead)
  const canVerify = useHasPermission(Permission.FindingsVerify)
  const canManageModules = useHasPermission(Permission.TeamUpdate)
  const pentestOn = useModuleEnabled('pentest') && canPentest
  const simOn = useModuleEnabled('attack_simulation') && canPentest
  const controlsOn = useModuleEnabled('control_testing') && canPentest
  const { moduleIds, notEntitledModuleIds, isLoading: modulesLoading } = useTenantModules()

  const awaitingQuery = awaitingValidationQuery(pentestOn)
  const awaiting = useFindingsCount({ extra: awaitingQuery })
  const readyToClose = useReadyToCloseCount(canVerify)
  // Counted on the server over every pentest finding the viewer may see.
  const { data: retestsDueData } = useAdaptedPentestFindingPage(
    pentestOn ? { statuses: RETEST_PENDING_STATUSES, perPage: 1 } : null
  )
  // null skips the request when the pentest module is off (no 403 noise).
  const { data: campaignsData } = useAdaptedCampaigns(pentestOn ? undefined : null)
  const openCampaigns = pentestOn
    ? (campaignsData?.data ?? []).filter(
        (c) => c.status === 'in_progress' || c.status === 'planning'
      ).length
    : undefined

  const validated = useFindingsCount({ extra: VALIDATED_RECENTLY })
  const stillReproduces = useFindingsCount({ extra: STILL_REPRODUCES })
  const reopened = useFindingsCount({ extra: REOPENED_RECENTLY })

  const waiting: WaitingItem[] = [
    {
      key: 'awaiting',
      count: awaiting,
      title: t('validation.overview.waiting.awaiting.title', 'Fixes waiting for validation'),
      reason: t(
        'validation.overview.waiting.awaiting.reason',
        'Marked fixed; no re-check has confirmed it yet.'
      ),
      action: t('validation.overview.waiting.awaiting.action', 'Validate'),
      href: findingsHref(awaitingQuery),
    },
    ...(pentestOn
      ? [
          {
            key: 'retests',
            count: retestsDueData?.total,
            title: t('validation.overview.waiting.retests.title', 'Pentest retests due'),
            reason: t(
              'validation.overview.waiting.retests.reason',
              'Being fixed or fixed, waiting for a retest, across campaigns.'
            ),
            action: t('validation.overview.waiting.retests.action', 'Open retest queue'),
            href: '/validation/retests',
          },
        ]
      : []),
    ...(canVerify
      ? [
          {
            key: 'ready',
            count: readyToClose,
            title: t('validation.overview.waiting.ready.title', 'Ready to close'),
            reason: t(
              'validation.overview.waiting.ready.reason',
              'Closes waiting for a verifier, and recent closes made by the platform.'
            ),
            action: t('validation.overview.waiting.ready.action', 'Review'),
            href: '/findings/ready-to-close',
          },
        ]
      : []),
    ...(pentestOn
      ? [
          {
            key: 'campaigns',
            count: openCampaigns,
            title: t('validation.overview.waiting.campaigns.title', 'Open campaigns'),
            reason: t(
              'validation.overview.waiting.campaigns.reason',
              'In planning or in progress.'
            ),
            action: t('validation.overview.waiting.campaigns.action', 'Open campaigns'),
            href: '/pentest/campaigns',
          },
        ]
      : []),
  ]

  const starts: StartLink[] = [
    pentestOn && {
      href: '/pentest/campaigns',
      label: t('validation.overview.start.pentest', 'Pentest campaigns'),
    },
    simOn && {
      href: '/attack-simulation',
      label: t('validation.overview.start.simulation', 'Attack simulation'),
    },
    controlsOn && {
      href: '/control-testing',
      label: t('validation.overview.start.controls', 'Control testing'),
    },
  ].filter(Boolean) as StartLink[]

  const off = canManageModules
    ? switchedOffModules(moduleIds, notEntitledModuleIds ?? [], modulesLoading)
    : []

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('validation.overview.title', 'Validation')}
          description={t(
            'validation.overview.description',
            'Whether fixes hold and controls work, and what is waiting for you.'
          )}
        />
        <WaitingForYou items={waiting} starts={starts} />
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <CoverageSummary />
          <OutcomesList
            items={[
              {
                key: 'validated',
                count: validated,
                title: t(
                  'validation.overview.outcomes.validated.title',
                  'Validated in the last 30 days'
                ),
                reason: t(
                  'validation.overview.outcomes.validated.reason',
                  'Closed after a re-check stopped reproducing them.'
                ),
                href: findingsHref(VALIDATED_RECENTLY),
              },
              {
                key: 'reproduces',
                count: stillReproduces,
                tone: 'danger',
                title: t('validation.overview.outcomes.reproduces.title', 'Still reproduces'),
                reason: t(
                  'validation.overview.outcomes.reproduces.reason',
                  'Open, and the latest re-check reproduced them.'
                ),
                href: findingsHref(STILL_REPRODUCES),
              },
              {
                key: 'reopened',
                count: reopened,
                tone: 'warning',
                title: t(
                  'validation.overview.outcomes.reopened.title',
                  'Reopened in the last 30 days'
                ),
                reason: t(
                  'validation.overview.outcomes.reopened.reason',
                  'Came back after they were closed.'
                ),
                href: findingsHref(REOPENED_RECENTLY),
              },
            ]}
          />
        </div>
        <ModulesOffHint modules={off} />
      </PageStack>
    </Main>
  )
}
