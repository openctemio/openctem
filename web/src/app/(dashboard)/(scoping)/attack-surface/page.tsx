'use client'

/**
 * Attack surface > Overview (research/353 D3, D4): what the organization
 * exposes and how healthy it is, in four blocks, each answering one question
 * and leading to the view that acts on it:
 *
 *   strip        how big the surface is, what is new, open and waiting
 *   fix first    the most severe open exposures, each opening its asset
 *   discovery    decisions waiting, watch freshness, monitoring settings
 *   composition  the surface by kind of asset, and what changed recently
 *
 * Every number comes from the server (GET /attack-surface/stats and
 * GET /easm/summary, both scoped to the reader by the API); tiles and rows
 * open exactly the population they count.
 */

import Link from '@/components/link'
import { Main } from '@/components/layout'
import { PageHeader, PageStack, MetricStrip, EmptyState, RelativeTime } from '@/features/shared'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Globe,
  Server,
  Cloud,
  GitBranch,
  Shield,
  AlertCircle,
  Layers,
  Network,
  Database,
  HardDrive,
  Key,
  Lock,
  History,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import {
  AttackSurfaceSectionTabs,
  EASMOverview,
  useAttackSurfaceStats,
} from '@/features/attack-surface'
import { useEASMSummary } from '@/features/attack-surface/hooks/use-easm-summary'
import { EASM_REVIEW_HREF } from '@/features/attack-surface/components/easm-overview'
import { STATS_ATTRIBUTION } from '@/features/attack-surface/lib/external-filters'
import { AssetPeekLink } from '@/features/assets/components/asset-peek'
import { SettleGroup, SettleSignal } from '@/features/shared/components/settle-group'
import { useTranslation } from '@/context/i18n-provider'

// Each tile and row opens exactly the population it counts, with the
// attribution the stats count, so a number and its list agree.
const TOTAL_ASSETS_HREF = `/assets?attribution=${STATS_ATTRIBUTION}`
const INTERNET_FACING_HREF = `/assets?internet_facing=true&attribution=${STATS_ATTRIBUTION}`
const CHANGES_HREF = '/attack-surface/changes'
const EXPOSURES_HREF = '/exposures'
const typeHref = (type: string) =>
  `/assets?types=${encodeURIComponent(type)}&attribution=${STATS_ATTRIBUTION}`

// Asset type to icon mapping. Icons stay muted: the type name carries the meaning.
const assetTypeIcons: Record<string, LucideIcon> = {
  domain: Globe,
  subdomain: Globe,
  website: Layers,
  service: Server,
  repository: GitBranch,
  cloud: Cloud,
  cloud_account: Cloud,
  host: Server,
  container: Layers,
  database: Database,
  network: Shield,
  storage: HardDrive,
  identity: Key,
  ip_address: Network,
  certificate: Lock,
  kubernetes: Layers,
  application: Layers,
}

// Asset type display names (en defaults; the keys are attackSurface.overview.type.*)
const assetTypeNames: Record<string, string> = {
  domain: 'Domains',
  subdomain: 'Subdomains',
  website: 'Websites',
  service: 'Services',
  repository: 'Repositories',
  cloud: 'Cloud assets',
  cloud_account: 'Cloud accounts',
  host: 'Hosts',
  container: 'Containers',
  database: 'Databases',
  network: 'Networks',
  storage: 'Storage',
  identity: 'Identities',
  ip_address: 'IP addresses',
  certificate: 'Certificates',
  kubernetes: 'Kubernetes',
  application: 'Applications',
  mobile: 'Mobile apps',
  serverless: 'Serverless',
}

function ListRowsSkeleton({ rows }: { rows: number }) {
  return (
    <div className="divide-y">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center justify-between py-3">
          <div className="space-y-1.5">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-3 w-24" />
          </div>
          <Skeleton className="h-5 w-20" />
        </div>
      ))}
    </div>
  )
}

/** The overview's shape while its blocks load: the strip, then two rows of cards. */
function OverviewSkeleton() {
  return (
    <div className="space-y-5" aria-busy data-testid="attack-surface-skeleton">
      <Skeleton className="h-[92px] w-full rounded-lg" />
      <div className="grid gap-5 lg:grid-cols-3">
        <Skeleton className="h-96 w-full rounded-lg lg:col-span-2" />
        <Skeleton className="h-96 w-full rounded-lg" />
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <Skeleton className="h-72 w-full rounded-lg" />
        <Skeleton className="h-72 w-full rounded-lg lg:col-span-2" />
      </div>
    </div>
  )
}

export default function AttackSurfacePage() {
  const { t } = useTranslation()
  const { stats, isLoading, error } = useAttackSurfaceStats()
  const { summary, isLoading: summaryLoading } = useEASMSummary()
  const typeName = (type: string, singular = false) => {
    const plural = assetTypeNames[type]
    if (!plural) return type
    // Rows name one asset's type ("Domain"), the breakdown a group ("Domains").
    return singular
      ? t(`attackSurface.overview.typeOne.${type}`, plural.replace(/s$/, ''))
      : t(`attackSurface.overview.type.${type}`, plural)
  }
  const changeName = (v: string) =>
    v === 'added'
      ? t('attackSurface.overview.change.added', 'Added')
      : v === 'removed'
        ? t('attackSurface.overview.change.removed', 'Removed')
        : v === 'changed'
          ? t('attackSurface.overview.change.changed', 'Changed')
          : v

  const breakdown = (stats?.assetBreakdown ?? []).filter((item) => item.total > 0)
  const changes = stats?.recentChanges ?? []
  const days = stats?.trendWindowDays ?? 7
  const a = summary?.attribution
  const waiting = (a?.needs_review ?? 0) + (a?.candidate ?? 0)

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('attackSurface.title', 'Attack surface')}
          description={t(
            'attackSurface.overview.lede',
            'What you expose on the internet, what to fix first and whether discovery keeps up.'
          )}
        />
        <AttackSurfaceSectionTabs />

        {/* The blocks below load on their own: show them together, so the
              numbers and the cards arriving one after the other do not push
              the page around. */}
        <SettleGroup fallback={<OverviewSkeleton />}>
          <SettleSignal pending={isLoading || summaryLoading} />

          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>
                {t('attackSurface.overview.errorTitle', 'Failed to load attack surface data')}
              </AlertTitle>
              <AlertDescription>
                {t('attackSurface.overview.errorDescription', 'Reload the page to try again.')}
              </AlertDescription>
            </Alert>
          )}

          {/* Slot for the posture grade card (research/353 D5). */}

          <MetricStrip
            loading={isLoading || summaryLoading}
            items={[
              {
                key: 'total',
                href: TOTAL_ASSETS_HREF,
                label: t('attackSurface.overview.surfaceAssets', 'Surface assets'),
                value: stats?.totalAssets ?? 0,
                description: t(
                  'attackSurface.overview.surfaceAssetsInfo',
                  'Assets attributed to your organization: confirmed, or found by a rule you trust.'
                ),
              },
              {
                key: 'internet',
                href: INTERNET_FACING_HREF,
                label: t('attackSurface.overview.internetFacing', 'Internet-facing assets'),
                value: stats?.internetFacingAssets ?? 0,
                detail: t(
                  'attackSurface.overview.newlyExposed',
                  '{count} newly exposed in the last {days} days',
                  { count: stats?.newlyExposed ?? 0, days }
                ),
                description: t(
                  'attackSurface.overview.internetFacingInfo',
                  'Assets whose exposure is public or that a source reported reachable from the internet. Newly exposed counts the same changes as Assets › Activity.'
                ),
              },
              {
                key: 'new',
                href: CHANGES_HREF,
                label: t('attackSurface.overview.new7', 'New in the last 7 days'),
                value: summary?.new?.last_7_days ?? 0,
                description: t(
                  'attackSurface.overview.new7Info',
                  'Domains, subdomains, addresses and certificates first seen in the last 7 days.'
                ),
              },
              {
                key: 'open',
                href: EXPOSURES_HREF,
                label: t('attackSurface.overview.openExposures', 'Open exposures'),
                value: summary?.exposures?.open ?? 0,
              },
              {
                key: 'waiting',
                href: EASM_REVIEW_HREF,
                label: t('attackSurface.overview.waitingDecision', 'Waiting for a decision'),
                value: waiting,
                tone: 'warning',
                description: t(
                  'attackSurface.overview.waitingDecisionInfo',
                  'Names discovery found that nobody has confirmed or rejected yet. Nothing joins your scope until someone decides.'
                ),
              },
            ]}
          />

          <EASMOverview />

          <div className="grid gap-5 lg:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('attackSurface.overview.breakdownTitle', 'Asset breakdown')}
                </CardTitle>
                <CardDescription>
                  {t(
                    'attackSurface.overview.breakdownDescription',
                    'Assets by type, with how many are exposed'
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <ListRowsSkeleton rows={6} />
                ) : breakdown.length === 0 ? (
                  <EmptyState
                    icon={Layers}
                    title={t('attackSurface.overview.noAssetsTitle', 'No assets yet')}
                    description={t(
                      'attackSurface.overview.noAssetsDescription',
                      'Assets appear here once discovery or an import adds them.'
                    )}
                    card={false}
                    className="py-8"
                  />
                ) : (
                  <ul className="divide-y">
                    {breakdown.map((item) => {
                      const TypeIcon = assetTypeIcons[item.type] || Server
                      return (
                        <li key={item.type}>
                          <Link
                            href={typeHref(item.type)}
                            className="flex items-center justify-between gap-3 py-2.5 hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                          >
                            <span className="flex min-w-0 items-center gap-3">
                              <TypeIcon
                                className="h-4 w-4 shrink-0 text-muted-foreground"
                                aria-hidden
                              />
                              <span className="min-w-0">
                                <span className="block truncate text-sm font-medium">
                                  {typeName(item.type)}
                                </span>
                                <span className="block text-xs text-muted-foreground tabular-nums">
                                  {t('attackSurface.overview.exposedCount', '{count} exposed', {
                                    count: item.exposed,
                                  })}
                                </span>
                              </span>
                            </span>
                            <span className="text-sm font-medium tabular-nums">{item.total}</span>
                          </Link>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>

            <Card className="lg:col-span-2">
              <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
                <div className="min-w-0 space-y-1.5">
                  <CardTitle className="text-base">
                    {t('attackSurface.overview.recentTitle', 'Recent changes')}
                  </CardTitle>
                  <CardDescription>
                    {t(
                      'attackSurface.overview.recentDescription',
                      'Assets added, removed or changed'
                    )}
                  </CardDescription>
                </div>
                <Button size="sm" variant="outline" asChild>
                  <Link href={CHANGES_HREF}>{t('attackSurface.overview.viewAll', 'View all')}</Link>
                </Button>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <ListRowsSkeleton rows={5} />
                ) : changes.length === 0 ? (
                  <EmptyState
                    icon={History}
                    title={t('attackSurface.overview.noChangesTitle', 'No recent changes')}
                    description={t(
                      'attackSurface.overview.noChangesDescription',
                      'The attack surface has not changed recently.'
                    )}
                    card={false}
                    className="py-8"
                  />
                ) : (
                  <ul className="divide-y">
                    {changes.map((change) => (
                      <li
                        key={`${change.assetId ?? change.assetName}-${change.type}-${change.timestamp}`}
                        className="flex items-center justify-between gap-3 py-2.5"
                      >
                        <span className="flex min-w-0 items-center gap-3">
                          <span className="w-20 shrink-0 text-xs text-muted-foreground">
                            {changeName(change.type)}
                          </span>
                          <span className="min-w-0">
                            <AssetPeekLink
                              assetId={change.assetId}
                              className="block truncate text-sm font-medium"
                            >
                              {change.assetName}
                            </AssetPeekLink>
                            <span className="block text-xs text-muted-foreground">
                              {typeName(change.assetType, true)}
                            </span>
                          </span>
                        </span>
                        <span className="shrink-0 text-xs text-muted-foreground">
                          <RelativeTime date={change.timestamp} />
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
        </SettleGroup>
      </PageStack>
    </Main>
  )
}
