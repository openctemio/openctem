'use client'

import { Main } from '@/components/layout'
import { ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { MetricStrip, PageHeader, PageStack, type MetricStripItem } from '@/features/shared'
import { useDocsHref } from '@/context/brand-provider'
import { DOCS } from '@/lib/docs-links'
import { useFormatList } from '@/lib/format-list'
import { useValidationCoverage } from '@/features/validation/api/use-validation-coverage'
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
  CLOSED_P0_P1,
  REOPENED_RECENTLY,
  STILL_REPRODUCES,
  VALIDATED_RECENTLY,
  awaitingValidationQuery,
  findingsHref,
  switchedOffModules,
} from '@/features/validation/lib/overview-queries'
import {
  ModulesOffHint,
  WaitingForYou,
  type StartLink,
  type WaitingItem,
} from '@/features/validation/components/validation-overview'

/**
 * Validation › Overview (research/370): how much of the closed P0/P1 work is
 * proven and what the latest re-checks said (one strip), then what is
 * waiting for the viewer.
 *
 * Every figure is a findings list (or the coverage KPI, the definition the
 * CTEM cycle's close gate uses) read through the ordinary API, so the server
 * applies the viewer's tenant and data scope. A module the organization
 * switched off leaves the page without a request to its API; owners and
 * admins get one quiet line pointing at Settings › Modules.
 */
export default function ValidationOverviewPage() {
  const { t } = useTranslation()
  const docsHref = useDocsHref()
  const formatList = useFormatList()
  const canPentest = useHasPermission(Permission.PentestRead)
  const canVerify = useHasPermission(Permission.FindingsVerify)
  const canManageModules = useHasPermission(Permission.TeamUpdate)
  const pentestOn = useModuleEnabled('pentest') && canPentest
  const simOn = useModuleEnabled('attack_simulation') && canPentest
  const controlsOn = useModuleEnabled('control_testing') && canPentest
  const { moduleIds, notEntitledModuleIds, isLoading: modulesLoading } = useTenantModules()

  const awaitingQuery = awaitingValidationQuery(pentestOn)
  // The query depends on the pentest module, which is unknown until the module
  // list arrives: counting earlier would send a second request for the same figure.
  const awaiting = useFindingsCount({ extra: awaitingQuery }, !modulesLoading)
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
  const {
    data: coverage,
    error: coverageError,
    isLoading: coverageLoading,
  } = useValidationCoverage()

  const covTotal = coverage?.p0_p1_total ?? 0
  const covValidated = coverage?.p0_p1_validated ?? 0
  const share = (v: number, n: number) => (n > 0 ? Math.round((v / n) * 100) : 0)
  const classes = (coverage?.by_priority ?? [])
    .filter((r) => r.priority === 'P0' || r.priority === 'P1')
    .map((r) =>
      t('validation.overview.coverage.class', '{priority} {validated} of {total}', {
        priority: r.priority,
        validated: r.validated,
        total: r.total,
      })
    )
  const dash = (n: number | undefined) => (n === undefined ? '–' : n)
  const metrics: MetricStripItem[] = [
    {
      key: 'coverage',
      label: t('validation.overview.coverage.label', 'P0/P1 validation coverage'),
      value: coverageError || covTotal === 0 ? '–' : `${share(covValidated, covTotal)}%`,
      detail: coverageError
        ? undefined
        : covTotal === 0
          ? t('validation.overview.coverage.none', 'No P0 or P1 finding closed yet')
          : formatList(classes),
      description: t(
        'validation.overview.coverage.description',
        'Closed P0 and P1 findings with validation evidence (pentest, scripted or sensor).'
      ),
      href: findingsHref(CLOSED_P0_P1),
    },
    {
      key: 'validated',
      label: t('validation.overview.outcomes.validated', 'Validated, last 30 days'),
      value: dash(validated),
      description: t(
        'validation.overview.outcomes.validatedHint',
        'Closed after a re-check stopped reproducing them.'
      ),
      href: findingsHref(VALIDATED_RECENTLY),
    },
    {
      key: 'reproduces',
      label: t('validation.overview.outcomes.reproduces', 'Still reproduces'),
      value: dash(stillReproduces),
      tone: 'danger',
      description: t(
        'validation.overview.outcomes.reproducesHint',
        'Open, and the latest re-check reproduced them.'
      ),
      href: findingsHref(STILL_REPRODUCES),
    },
    {
      key: 'reopened',
      label: t('validation.overview.outcomes.reopened', 'Reopened, last 30 days'),
      value: dash(reopened),
      tone: 'warning',
      description: t(
        'validation.overview.outcomes.reopenedHint',
        'Came back after they were closed.'
      ),
      href: findingsHref(REOPENED_RECENTLY),
    },
  ]

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
        >
          <Button asChild variant="ghost" size="sm">
            <a href={docsHref(DOCS.validation.overview)} target="_blank" rel="noopener noreferrer">
              {t('validation.overview.coverage.howMeasured', 'How coverage is measured')}
              <ExternalLink aria-hidden="true" />
            </a>
          </Button>
        </PageHeader>
        <MetricStrip items={metrics} loading={coverageLoading} />
        <WaitingForYou items={waiting} starts={starts} />
        <ModulesOffHint modules={off} />
      </PageStack>
    </Main>
  )
}
