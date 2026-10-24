'use client'

import Link from '@/components/link'
import { Main } from '@/components/layout'
import { PageHeader, PageStack, MetricStrip, EmptyState, RelativeTime } from '@/features/shared'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
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
import {
  AttackSurfaceSectionTabs,
  EASMDecidePanel,
  EASMOverview,
  useAttackSurfaceStats,
} from '@/features/attack-surface'
import { STATS_ATTRIBUTION } from '@/features/attack-surface/lib/external-filters'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { assetDetailHref, isLinkableAssetId } from '@/features/findings/lib/asset-link'
import { useTranslation } from '@/context/i18n-provider'

// Drill-downs: each card opens exactly the population it counts.
// They carry the attribution the stats count, so a tile and its list agree.
const TOTAL_ASSETS_HREF = `/assets?attribution=${STATS_ATTRIBUTION}`
const INTERNET_FACING_HREF = `/assets?internet_facing=true&attribution=${STATS_ATTRIBUTION}`
const CRITICAL_INTERNET_FACING_HREF = `/assets?internet_facing=true&criticalities=critical,high&attribution=${STATS_ATTRIBUTION}`
const NEWLY_EXPOSED_HREF = '/assets/changes?view=newly_exposed'

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
  ip_address: Globe,
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

const EXPOSURES = ['public', 'restricted', 'private', 'isolated', 'unknown'] as const

/** An asset name that opens the asset when its id is known; truncates, never overflows. */
function AssetName({ id, name }: { id?: string; name: string }) {
  if (!isLinkableAssetId(id)) {
    return <p className="min-w-0 truncate text-sm font-medium">{name}</p>
  }
  return (
    <Link
      href={assetDetailHref(id)}
      className="min-w-0 truncate text-sm font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {name}
    </Link>
  )
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

export default function AttackSurfacePage() {
  const { t } = useTranslation()
  const { stats, isLoading, error } = useAttackSurfaceStats()
  const typeName = (type: string, singular = false) => {
    const plural = assetTypeNames[type]
    if (!plural) return type
    // Rows name one asset's type ("Domain"), the breakdown a group ("Domains").
    return singular
      ? t(`attackSurface.overview.typeOne.${type}`, plural.replace(/s$/, ''))
      : t(`attackSurface.overview.type.${type}`, plural)
  }
  const exposureName = (v: string) =>
    (EXPOSURES as readonly string[]).includes(v)
      ? t(`attackSurface.overview.exposure.${v}`, v.charAt(0).toUpperCase() + v.slice(1))
      : v
  const changeName = (v: string) =>
    v === 'added'
      ? t('attackSurface.overview.change.added', 'Added')
      : v === 'removed'
        ? t('attackSurface.overview.change.removed', 'Removed')
        : v === 'changed'
          ? t('attackSurface.overview.change.changed', 'Changed')
          : v

  const breakdown = (stats?.assetBreakdown ?? []).filter((item) => item.total > 0)
  const exposed = stats?.exposedServicesList ?? []
  const changes = stats?.recentChanges ?? []
  const days = stats?.trendWindowDays ?? 7

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('attackSurface.title', 'Attack surface')}
          description={t(
            'attackSurface.overview.description',
            'What your organization exposes, and how it changed this week.'
          )}
        />
        <AttackSurfaceSectionTabs />

        <EASMDecidePanel compact />

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

        <MetricStrip
          loading={isLoading}
          items={[
            {
              key: 'total',
              href: TOTAL_ASSETS_HREF,
              label: t('attackSurface.overview.totalAssets', 'Total assets'),
              value: stats?.totalAssets || 0,
              detail: t(
                'attackSurface.overview.newInWindow',
                '{count} new in the last {days} days',
                { count: stats?.totalAssetsChange ?? 0, days }
              ),
            },
            {
              key: 'internet',
              href: INTERNET_FACING_HREF,
              label: t('attackSurface.overview.internetFacing', 'Internet-facing assets'),
              value: stats?.internetFacingAssets || 0,
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
              key: 'critical',
              href: CRITICAL_INTERNET_FACING_HREF,
              label: t(
                'attackSurface.overview.criticalInternetFacing',
                'Critical internet-facing assets'
              ),
              value: stats?.criticalInternetFacingAssets || 0,
              description: t(
                'attackSurface.overview.criticalInternetFacingInfo',
                'Internet-facing assets with critical or high criticality. A population to watch, not open risks: open exposures are listed below.'
              ),
            },
          ]}
        />

        {!isLoading && !error && (
          <p className="text-sm text-muted-foreground">
            <Link
              href={NEWLY_EXPOSED_HREF}
              className="underline underline-offset-2 hover:text-foreground"
            >
              {t(
                'attackSurface.overview.seeNewlyExposed',
                'See what became internet-facing this week'
              )}
            </Link>
          </p>
        )}

        <EASMOverview />

        <div className="grid gap-5 lg:grid-cols-3">
          <Card className="lg:col-span-1">
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
                <div className="divide-y">
                  {breakdown.map((item) => {
                    const TypeIcon = assetTypeIcons[item.type] || Server
                    return (
                      <div key={item.type} className="flex items-center justify-between py-2.5">
                        <div className="flex min-w-0 items-center gap-3">
                          <TypeIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
                          <div className="min-w-0">
                            <p className="truncate text-sm font-medium">{typeName(item.type)}</p>
                            <p className="text-xs text-muted-foreground tabular-nums">
                              {t('attackSurface.overview.exposedCount', '{count} exposed', {
                                count: item.exposed,
                              })}
                            </p>
                          </div>
                        </div>
                        <span className="text-sm font-medium tabular-nums">{item.total}</span>
                      </div>
                    )
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
              <div className="space-y-1.5">
                <CardTitle className="text-base">
                  {t('attackSurface.overview.exposedTitle', 'Exposed assets')}
                </CardTitle>
                <CardDescription>
                  {t(
                    'attackSurface.overview.exposedDescription',
                    'Internet-facing assets with the highest risk'
                  )}
                </CardDescription>
              </div>
              <Button size="sm" variant="outline" asChild>
                <Link href="/attack-surface/external">
                  {t('attackSurface.overview.viewAll', 'View all')}
                </Link>
              </Button>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <ListRowsSkeleton rows={5} />
              ) : exposed.length === 0 ? (
                <EmptyState
                  icon={Network}
                  title={t('attackSurface.overview.noExposedTitle', 'No exposed assets')}
                  description={t(
                    'attackSurface.overview.noExposedDescription',
                    'No asset is marked public yet.'
                  )}
                  card={false}
                  className="py-8"
                />
              ) : (
                <div className="divide-y">
                  {exposed.map((service) => (
                    <div
                      key={service.id}
                      className="flex items-center justify-between gap-3 py-2.5"
                    >
                      <div className="flex min-w-0 items-center gap-3">
                        <Server className="h-4 w-4 shrink-0 text-muted-foreground" />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <AssetName id={service.id} name={service.name} />
                          </div>
                          <p className="flex flex-wrap gap-x-2 text-xs text-muted-foreground">
                            <span>{typeName(service.type, true)}</span>
                            <RelativeTime date={service.lastSeen} />
                          </p>
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <span
                          className={cn(
                            'text-xs tabular-nums',
                            service.findingCount > 0
                              ? 'font-medium text-destructive'
                              : 'text-muted-foreground'
                          )}
                        >
                          {service.findingCount === 1
                            ? t('attackSurface.overview.findings.one', '1 finding', { count: 1 })
                            : t('attackSurface.overview.findings.other', '{count} findings', {
                                count: service.findingCount,
                              })}
                        </span>
                        <Badge
                          variant={service.exposure === 'public' ? 'destructive' : 'secondary'}
                        >
                          {exposureName(service.exposure)}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
            <div className="space-y-1.5">
              <CardTitle className="text-base">
                {t('attackSurface.overview.recentTitle', 'Recent changes')}
              </CardTitle>
              <CardDescription>
                {t('attackSurface.overview.recentDescription', 'Assets added, removed or changed')}
              </CardDescription>
            </div>
            <Button size="sm" variant="outline" asChild>
              <Link href="/assets/changes">{t('attackSurface.overview.viewAll', 'View all')}</Link>
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
              <div className="divide-y">
                {changes.map((change) => (
                  <div
                    key={`${change.assetId ?? change.assetName}-${change.type}-${change.timestamp}`}
                    className="flex items-center justify-between gap-3 py-2.5"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <Badge
                        variant={change.type === 'added' ? 'secondary' : 'outline'}
                        className="w-20 justify-center"
                      >
                        {changeName(change.type)}
                      </Badge>
                      <AssetName id={change.assetId} name={change.assetName} />
                    </div>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      <RelativeTime date={change.timestamp} />
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </PageStack>
    </Main>
  )
}
