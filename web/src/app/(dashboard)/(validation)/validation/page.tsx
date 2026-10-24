'use client'

import { useMemo } from 'react'
import Link from '@/components/link'
import { ClipboardList, Grid3x3, RotateCcw, ShieldCheck, Swords } from 'lucide-react'
import { Main } from '@/components/layout'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  EmptyState,
  LinkCard,
  MetricStrip,
  PageHeader,
  PageStack,
  RelativeTime,
  SettingsSection,
  type MetricStripItem,
} from '@/features/shared'
import { useValidationCoverage } from '@/features/validation/api/use-validation-coverage'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import {
  useAdaptedAllPentestFindings,
  useAdaptedCampaigns,
  useAdaptedPentestFindingPage,
  RETEST_PENDING_STATUSES,
} from '@/features/pentest/api/use-pentest-api'
import { campaignHref } from '@/features/pentest/lib/campaign-links'
import { useControlTests, useSimulations } from '@/features/simulation/api/use-simulation-api'
import { useHasPermission, Permission } from '@/lib/permissions'

const pct = (validated: number, total: number) =>
  total > 0 ? `${Math.round((validated / total) * 100)}%` : '–'

interface Activity {
  key: string
  when: string
  what: string
  where: string
  href: string
}

/**
 * Validation › Overview: is the program proving its fixes and its controls?
 *
 * - Coverage: of the P0/P1 findings that were closed, the share with
 *   validation evidence, the same definition the CTEM cycle's close gate uses
 *   (api computeValidationCoverage, served tenant-wide by
 *   GET /api/v1/validation/coverage `by_priority`).
 * - Retests due, open campaigns, and the latest activity across pentest,
 *   attack simulation and control testing, each only when its module is on.
 */
export default function ValidationOverviewPage() {
  const canPentest = useHasPermission(Permission.PentestRead)
  const pentestOn = useModuleEnabled('pentest') && canPentest
  const simOn = useModuleEnabled('attack_simulation') && canPentest
  const controlsOn = useModuleEnabled('control_testing') && canPentest
  const attackCoverageOn = useModuleEnabled('mitre_coverage') && canPentest

  const { data: coverage, isLoading: coverageLoading } = useValidationCoverage()
  // null skips the request when the pentest module is off (no 403 noise).
  const { data: campaignsData, isLoading: campaignsLoading } = useAdaptedCampaigns(
    pentestOn ? undefined : null
  )
  const { data: findingsData, isLoading: findingsLoading } = useAdaptedAllPentestFindings(
    pentestOn ? { per_page: 200 } : null
  )
  const { data: simsData } = useSimulations({ enabled: simOn })
  const { data: testsData } = useControlTests({ enabled: controlsOn })

  const campaigns = useMemo(() => campaignsData?.data ?? [], [campaignsData])
  const findings = useMemo(() => findingsData?.data ?? [], [findingsData])
  // Counted on the server over every finding the viewer may see, not over
  // the one page of findings loaded above.
  const { data: retestsDueData } = useAdaptedPentestFindingPage(
    pentestOn ? { statuses: RETEST_PENDING_STATUSES, perPage: 1 } : null
  )
  const retestsDue = retestsDueData?.total ?? 0
  const openCampaigns = campaigns.filter(
    (c) => c.status === 'in_progress' || c.status === 'planning'
  ).length

  const byPriority = coverage?.by_priority ?? []

  const metrics: MetricStripItem[] = [
    ...(pentestOn
      ? [
          { key: 'retests', label: 'Retests due', value: retestsDue, href: '/validation/retests' },
          {
            key: 'campaigns',
            label: 'Open campaigns',
            value: openCampaigns,
            href: '/pentest/campaigns',
          },
        ]
      : []),
    ...(simOn
      ? [
          {
            key: 'sims',
            label: 'Simulations',
            value: simsData?.total ?? simsData?.data?.length ?? 0,
            href: '/attack-simulation',
          },
        ]
      : []),
    ...(controlsOn
      ? [
          {
            key: 'controls',
            label: 'Control tests',
            value: testsData?.total ?? testsData?.data?.length ?? 0,
            href: '/control-testing',
          },
        ]
      : []),
  ]

  const activity: Activity[] = useMemo(() => {
    const items: Activity[] = []
    const campaignName = (id: string) => campaigns.find((c) => c.id === id)?.name ?? 'Campaign'
    for (const f of findings) {
      items.push({
        key: `f-${f.id}`,
        when: f.updatedAt,
        what: f.title,
        where: `Pentest: ${campaignName(f.campaignId)}`,
        href: campaignHref(f.campaignId, 'findings'),
      })
    }
    for (const s of simsData?.data ?? []) {
      if (!s.last_run_at) continue
      items.push({
        key: `s-${s.id}`,
        when: s.last_run_at,
        what: s.name,
        where: 'Attack simulation',
        href: '/attack-simulation',
      })
    }
    for (const t of testsData?.data ?? []) {
      if (!t.last_tested_at) continue
      items.push({
        key: `c-${t.id}`,
        when: t.last_tested_at,
        what: t.name,
        where: `Control testing: ${t.framework}`,
        href: '/control-testing',
      })
    }
    return items
      .filter((i) => i.when && !isNaN(new Date(i.when).getTime()))
      .sort((a, b) => new Date(b.when).getTime() - new Date(a.when).getTime())
      .slice(0, 10)
  }, [findings, campaigns, simsData, testsData])

  const areas = [
    pentestOn && {
      href: '/pentest/campaigns',
      icon: ClipboardList,
      title: 'Pentest campaigns',
      description: 'Engagements with their findings, retests, reports, scope and team.',
    },
    simOn && {
      href: '/attack-simulation',
      icon: Swords,
      title: 'Attack simulation',
      description: 'Run attack techniques and measure detection and prevention.',
    },
    controlsOn && {
      href: '/control-testing',
      icon: ShieldCheck,
      title: 'Control testing',
      description: 'Test security controls against your frameworks.',
    },
    pentestOn && {
      href: '/validation/retests',
      icon: RotateCcw,
      title: 'Retest queue',
      description: 'Fixed findings waiting to be re-verified, across campaigns.',
    },
    attackCoverageOn && {
      href: '/validation/attack-coverage',
      icon: Grid3x3,
      title: 'ATT&CK coverage',
      description: 'Which ATT&CK techniques your testing has exercised.',
    },
  ].filter(Boolean) as {
    href: string
    icon: typeof ClipboardList
    title: string
    description: string
  }[]

  const loading = coverageLoading || (pentestOn && (campaignsLoading || findingsLoading))

  return (
    <Main>
      <PageStack>
        <PageHeader
          title="Validation"
          description="Whether fixes and controls are proven, and what is waiting to be re-tested."
        />
        {metrics.length > 0 && <MetricStrip loading={loading} items={metrics} />}

        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <SettingsSection
            title="Coverage by priority"
            description="Closed findings with validation evidence (pentest, scripted or sensor)."
          >
            <Card className="py-0">
              <CardContent className="p-4">
                {coverageLoading ? (
                  <Skeleton className="h-24 w-full" />
                ) : byPriority.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No coverage data yet.</p>
                ) : (
                  <ul className="space-y-3">
                    {byPriority.map((row) => {
                      const share = row.total > 0 ? (row.validated / row.total) * 100 : 0
                      return (
                        <li key={row.priority} className="space-y-1">
                          <div className="flex items-center justify-between text-sm">
                            <span className="font-medium">{row.priority}</span>
                            <span className="text-muted-foreground tabular-nums">
                              {row.validated} of {row.total}, {pct(row.validated, row.total)}
                            </span>
                          </div>
                          <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                            <div
                              className="h-full rounded-full bg-primary"
                              style={{ width: `${share}%` }}
                            />
                          </div>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
          </SettingsSection>

          <SettingsSection title="Recent activity" description="Latest across validation work.">
            <Card className="py-0">
              <CardContent className="p-0">
                {activity.length === 0 ? (
                  <EmptyState
                    icon={ClipboardList}
                    title="No validation activity yet"
                    description="Pentest findings, simulation runs and control tests show up here."
                  />
                ) : (
                  <ul className="divide-y">
                    {activity.map((a) => (
                      <li key={a.key}>
                        <Link
                          href={a.href}
                          className="flex items-start justify-between gap-3 px-4 py-2.5 hover:bg-muted/50"
                        >
                          <span className="min-w-0">
                            <span className="block truncate text-sm font-medium">{a.what}</span>
                            <span className="block truncate text-xs text-muted-foreground">
                              {a.where}
                            </span>
                          </span>
                          <RelativeTime
                            date={a.when}
                            className="shrink-0 text-xs text-muted-foreground"
                          />
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </SettingsSection>
        </div>

        {areas.length > 0 && (
          <SettingsSection title="Validation areas">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {areas.map((a) => (
                <LinkCard key={a.href} {...a} />
              ))}
            </div>
          </SettingsSection>
        )}
      </PageStack>
    </Main>
  )
}
