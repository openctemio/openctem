/**
 * An asset's own page — `/assets/{id}`.
 *
 * Catches deep-links from blast-radius views (Vuln Detail Sheet → "Affected
 * Assets" tab → click row, Component Detail Sheet → "Used By Assets" tab →
 * click row) and the drawer's "Open full page".
 *
 *  - A repository opens its workspace here (branches, findings by branch,
 *    scan settings): one URL per asset, whatever its type.
 *  - Every other type follows the detail layout (docs/ui-style-contract.md,
 *    "Detail pages"): the header, the tab strip, the properties beside the
 *    panel from 1280 px and under the header below it. The panels are the
 *    drawer's own section components, and the header's actions open the
 *    drawer's and the inventory's own dialogs (`useAssetPageActions`).
 */

'use client'

import * as React from 'react'
import { useRouter, useParams } from 'next/navigation'
import {
  ArrowLeft,
  Bug,
  Cpu,
  FolderTree,
  Globe,
  Hash,
  History,
  LayoutGrid,
  Link2,
  List,
  Lock,
  Network,
  Plug,
  Route,
  Users,
  type LucideIcon,
} from 'lucide-react'
import { toast } from 'sonner'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { type ActionMenuEntry } from '@/components/ui/action-menu'
import {
  DetailPageHeader,
  DetailSectionList,
  PropertyFold,
  PropertyGroup,
  PropertyList,
  PropertyRow,
} from '@/features/shared/components/detail'
import { DetailSections } from '@/features/shared/components/detail-sheet'
import { useDetailTab } from '@/features/shared/components/detail-sheet-layout'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { PageHeader } from '@/features/shared/components/page-header'
import { PageStack } from '@/features/shared/components/page-stack'
import { RiskScoreBadge, riskScoreState } from '@/features/shared/components/risk-score-badge'
import { SettleGroup, useSettleSignal } from '@/features/shared/components/settle-group'
import { OpenFindingsLink } from '@/features/assets/components/service-cells'
import { AssetAttributeSourcesSection } from '@/features/assets/components/asset-attribute-sources-section'
import { AssetFreshnessSection } from '@/features/assets/components/asset-freshness-section'
import { AssetCoverageSection } from '@/features/assets/components/asset-coverage-section'
import { AssetAttributionSection } from '@/features/assets/components/asset-attribution-section'
import { AssetIdentitySections } from '@/features/assets/components/asset-identity-sections'
import { AssetLineageSection } from '@/features/assets/components/asset-lineage-section'
import { RELATED_PREVIEW_ROWS } from '@/features/assets/components/relationships/related-assets-list'
import { AssetTimeline } from '@/features/assets/components/asset-timeline'
import {
  useAssetPageActions,
  useAssetScanGate,
} from '@/features/assets/components/asset-page-actions'
import { KeyFactsSection } from '@/features/assets/components/key-facts'
import { RiskSummarySection } from '@/features/assets/components/asset-overview-sections'
import type { Asset } from '@/features/assets/types/asset.types'
import { useAssetPage } from '@/features/assets/hooks/use-assets'
import { useRelatedAssets } from '@/features/assets/hooks/use-related-assets'
import {
  ResolvedPortsSection,
  hasResolvedPorts,
} from '@/features/assets/components/resolved-ports-section'
import { NameAddressesSection } from '@/features/assets/components/name-addresses-section'
import { ClassificationBadges } from '@/features/assets/components/classification-badges'
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { AssetLivenessBadge } from '@/features/asset-lifecycle/components/asset-liveness-badge'
import { AssetStatusBadge } from '@/features/asset-lifecycle/components/asset-status-badge'
import { AssetScanWindowCard } from '@/features/scan-windows/components/asset-scan-window-card'
import { AssetWebEvidenceCard } from '@/features/attack-surface/components/asset-web-evidence-card'
import { useWebEvidence } from '@/features/attack-surface/hooks/use-web-evidence'
import {
  OriginWebSection,
  isWebOriginType,
} from '@/features/web-surface/components/origin-web-section'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { useTranslation } from '@/context/i18n-provider'
import { AssetNextSteps } from '@/features/exploration/components/asset-next-steps'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { copyToClipboard } from '@/lib/clipboard'
import { shareableLink } from '@/lib/org-link'
import { cn } from '@/lib/utils'
import dynamic from 'next/dynamic'

// Only a repository opens its workspace here (branches, scan settings, drag
// and drop ordering); every other asset type would download it for nothing.
// The asset is fetched on the client first, so the page already shows its
// loading state while the workspace code arrives.
const RepositoryWorkspace = dynamic(
  () =>
    import('@/features/repositories/components/repository-workspace').then(
      (m) => m.RepositoryWorkspace
    ),
  {
    ssr: false,
    loading: () => (
      <Main>
        <PageStack>
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-64 w-full" />
        </PageStack>
      </Main>
    ),
  }
)

// Owners and access and Relationships hold their own dialogs (add, edit,
// grant, revoke): they load when their tab opens, not with the page.
const TabSkeleton = () => <Skeleton className="h-40 w-full" />
const AssetOwnersTab = dynamic(
  () => import('@/features/assets/components/asset-owners-tab').then((m) => m.AssetOwnersTab),
  { ssr: false, loading: TabSkeleton }
)
const AssetRelationshipsTab = dynamic(
  () =>
    import('@/features/assets/components/asset-relationships-tab').then(
      (m) => m.AssetRelationshipsTab
    ),
  { ssr: false, loading: TabSkeleton }
)
// The open findings and the technologies read their own lists when their tab opens.
// The origin's path tree: its own chunk, loaded when the tab opens.
const OriginPathsTab = dynamic(
  () => import('@/features/web-surface/components/origin-paths-tab').then((m) => m.OriginPathsTab),
  { ssr: false, loading: TabSkeleton }
)
const AssetFindings = dynamic(
  () => import('@/features/assets/components/asset-findings').then((m) => m.AssetFindings),
  { ssr: false, loading: TabSkeleton }
)
const AssetTechnologiesTab = dynamic(
  () =>
    import('@/features/assets/components/technologies/asset-technologies-tab').then(
      (m) => m.AssetTechnologiesTab
    ),
  { ssr: false, loading: TabSkeleton }
)

type TabKey =
  | 'overview'
  | 'findings'
  | 'relationships'
  | 'found'
  | 'ports'
  | 'technologies'
  | 'web'
  | 'paths'
  | 'owners'
  | 'activity'

const TAB_LABEL: Record<TabKey, string> = {
  overview: 'Overview',
  findings: 'Findings',
  relationships: 'Relationships',
  found: 'How we found this',
  ports: 'Ports and services',
  technologies: 'Technologies',
  web: 'Web',
  paths: 'Paths',
  owners: 'Owners and access',
  activity: 'Activity',
}

const TAB_ICON: Record<TabKey, LucideIcon> = {
  overview: LayoutGrid,
  findings: Bug,
  relationships: Network,
  found: Route,
  ports: Plug,
  technologies: Cpu,
  web: Globe,
  paths: FolderTree,
  owners: Users,
  activity: History,
}

/** The page's grid: the tab strip across, then the panel beside the properties rail. */
const GRID = 'grid min-w-0 gap-page xl:grid-cols-[minmax(0,1fr)_19rem]'
const RAIL = 'min-w-0 max-xl:order-2 xl:sticky xl:top-4 xl:col-start-2 xl:row-start-2 xl:self-start'
const STRIP = 'min-w-0 max-xl:order-3 xl:col-span-2 xl:row-start-1'
const PANEL = 'min-w-0 max-xl:order-4 xl:col-start-1 xl:row-start-2'
/**
 * Tabs that hold a wide table or a tree beside a table. From 1280 px their
 * panel takes the page's full width and the properties rail steps aside (one
 * screen, one job); below 1280 px the properties already sit above the strip
 * on every tab, so nothing moves when the tab changes.
 */
const WIDE_TABS: ReadonlySet<TabKey> = new Set<TabKey>([
  'findings',
  'relationships',
  'ports',
  'technologies',
  'web',
  'paths',
])
const RAIL_ASIDE = 'xl:hidden'
const PANEL_FULL = 'xl:col-span-2'

/**
 * Same blocks and order as the page (header, tab strip, properties, panel),
 * so the swap to the real page moves nothing.
 */
function PageSkeleton(props: React.ComponentProps<'div'>) {
  return (
    <PageStack aria-busy {...props}>
      <div className="space-y-2">
        <Skeleton className="h-6 w-56" />
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Skeleton className="h-8 w-3/5" />
          <Skeleton className="h-8 w-8" />
        </div>
      </div>
      <div className={GRID}>
        <div className={cn(RAIL, 'space-y-2')}>
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="grid grid-cols-[6.75rem_1fr] items-center gap-3">
              <Skeleton className="h-4 w-16" />
              <Skeleton className="h-6 w-full" />
            </div>
          ))}
        </div>
        <PanelSkeleton />
      </div>
    </PageStack>
  )
}

/** The tab strip and the panel while their reads load (grid items of the page). */
function PanelSkeleton() {
  return (
    <>
      <div className={STRIP} aria-busy data-testid="asset-detail-panels-skeleton">
        <Skeleton className="h-10 w-full max-w-xl" />
      </div>
      <div className={cn(PANEL, 'space-y-4')}>
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-28 w-full" />
      </div>
    </>
  )
}

/** Reports the page-level reads that decide which tabs exist to the SettleGroup. */
/** The origin's Paths; "Crawl this site" follows the page's scan gate. */
function AssetPathsTab({ asset }: { asset: Asset }) {
  const { canScan } = useAssetScanGate(asset)
  return <OriginPathsTab assetId={asset.id} assetName={asset.name} canCrawl={canScan} />
}

function SettleOn({ pending }: { pending: boolean }) {
  useSettleSignal(pending)
  return null
}

/**
 * The page's header: the asset's name and chips, its one main action and the
 * More menu (the actions first, then the links).
 */
function AssetHeader({
  asset,
  typeLabel,
  listingHref,
  onChanged,
}: {
  asset: Asset
  typeLabel: string
  listingHref: string
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const actions = useAssetPageActions(asset, onChanged)
  const links: ActionMenuEntry[] = [
    {
      id: 'copy-link',
      section: 'links',
      label: t('assetDetail.copyLink', 'Copy link'),
      icon: Link2,
      onSelect: async () => {
        const ok = await copyToClipboard(shareableLink(`/assets/${asset.id}`))
        if (ok) toast.success(t('assetDetail.linkCopied', 'Link copied'))
        else toast.error(t('common.copyFailed', 'Could not copy'))
      },
    },
    {
      id: 'copy-id',
      section: 'links',
      label: t('assets.sheet.copyId', 'Copy ID'),
      icon: Hash,
      onSelect: async () => {
        const ok = await copyToClipboard(asset.id)
        if (ok) toast.success(t('assets.sheet.idCopied', 'Asset ID copied'))
        else toast.error(t('common.copyFailed', 'Could not copy'))
      },
    },
    {
      id: 'open-list',
      section: 'links',
      icon: List,
      label: t('assetDetail.openList', 'Open {type} list', { type: typeLabel }),
      href: listingHref,
    },
  ]

  return (
    <>
      <DetailPageHeader
        title={asset.name}
        parent={{ href: '/assets', label: t('nav.item.assets', 'Assets') }}
        chips={
          <>
            <Badge variant="outline">{typeLabel}</Badge>
            <ClassificationBadges
              scope={asset.scope}
              exposure={asset.exposure}
              criticality={asset.criticality}
              size="md"
              labelled
              // The chips join the header's wrapping row, so on a phone
              // they break onto lines instead of running off the screen.
              className="contents"
            />
          </>
        }
        primary={actions.primary}
        menu={[...actions.menu, ...links]}
      />
      {actions.dialogs}
    </>
  )
}

export default function AssetDetailPage() {
  const router = useRouter()
  const params = useParams<{ id: string }>()
  const assetId = params?.id ?? null

  const { t } = useTranslation()
  const { can } = usePermissions()
  const { isLoading: tenantLoading } = useTenant()
  const { asset, isLoading, error, mutate } = useAssetPage(assetId)
  useBreadcrumbTitle(asset?.name)

  // Reads that decide the tab strip. Each is the request its tab's component
  // makes itself (same SWR key), so the tab opens on the cached answer.
  const backed = !!asset && asset.type !== 'repository'
  const relationshipsOn = useModuleEnabled('relationships') && backed
  const related = useRelatedAssets(relationshipsOn ? (asset?.id ?? null) : null, {
    limit: RELATED_PREVIEW_ROWS,
  })
  const webEvidence = useWebEvidence(backed ? (asset?.id ?? '') : '')

  const technologyCount = asset?.technologies?.length ?? 0
  const tabs: TabKey[] = backed
    ? [
        'overview',
        'findings',
        ...(relationshipsOn ? (['relationships'] as const) : []),
        'found',
        ...(hasResolvedPorts(asset?.type ?? '') ? (['ports'] as const) : []),
        // What probes fingerprinted on the asset (RFC-112), when anything.
        ...(technologyCount > 0 ? (['technologies'] as const) : []),
        // The web tab holds the origin's own section, or what a sensor saw
        // when it fetched the asset; hidden when neither applies.
        ...(isWebOriginType(asset?.type, asset?.subType) || webEvidence.items.length > 0
          ? (['web'] as const)
          : []),
        // The origin's endpoints as a tree of paths.
        ...(isWebOriginType(asset?.type, asset?.subType) ? (['paths'] as const) : []),
        'owners',
        'activity',
      ]
    : ['overview']
  const [tab, setTab] = useDetailTab<TabKey>('tab', tabs)

  // useAssetPage sends nothing until the tenant is known, so wait for it instead
  // of reading the empty answer as "not found".
  if (tenantLoading || isLoading) {
    return (
      <Main>
        <PageSkeleton role="status" aria-label={t('assetDetail.loading', 'Loading asset')} />
      </Main>
    )
  }

  if (!can(Permission.AssetsRead)) {
    return (
      <Main>
        <EmptyState
          icon={Lock}
          title={t('assetDetail.noAccess', 'You do not have access to assets')}
          description={t(
            'assetDetail.noAccessHint',
            'Ask a team administrator for the assets:read permission.'
          )}
        />
      </Main>
    )
  }

  const notFound = (error as { statusCode?: number } | undefined)?.statusCode === 404
  if (error && !notFound) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={t('assetDetail.title', 'Asset')} />
          <ErrorState
            title={t('assetDetail.errorTitle', 'asset details')}
            error={error}
            onRetry={() => mutate()}
          />
        </PageStack>
      </Main>
    )
  }

  if (!asset) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={t('assetDetail.notFound', 'Asset not found')} />
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12 text-center">
              <p className="text-base font-medium">
                {t('assetDetail.notFoundTitle', 'No asset with this ID')}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {t(
                  'assetDetail.notFoundHint',
                  'The asset may have been deleted or you may not have access.'
                )}
              </p>
              <div className="mt-4">
                <Button variant="outline" onClick={() => router.push('/assets')}>
                  <ArrowLeft aria-hidden />
                  {t('assetDetail.backToAssets', 'Back to assets')}
                </Button>
              </div>
            </CardContent>
          </Card>
        </PageStack>
      </Main>
    )
  }

  if (asset.type === 'repository') {
    return <RepositoryWorkspace repositoryId={asset.id} />
  }

  // The inventory filtered to this asset's type (and alias sub-type).
  const listingQuery = new URLSearchParams({ types: asset.type })
  if (asset.subType) listingQuery.set('sub_type', asset.subType)
  const listingHref = `/assets?${listingQuery}`
  const typeLabel = t(`assets.typeLabel.${asset.type}`, getAssetTypeLabel(asset.type))

  const goToRelated = (id: string) => router.push(`/assets/${encodeURIComponent(id)}`)

  return (
    <Main>
      <PageStack>
        <AssetHeader
          asset={asset}
          typeLabel={typeLabel}
          listingHref={listingHref}
          onChanged={() => void mutate()}
        />

        <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)} className={GRID}>
          <aside
            aria-label={t('assetDetail.propertiesAria', 'Asset properties')}
            className={cn(RAIL, WIDE_TABS.has(tab) && RAIL_ASIDE)}
          >
            <div className="max-md:rounded-lg max-md:border max-md:bg-card max-md:px-3">
              <PropertyList label={t('assetDetail.properties', 'Properties')}>
                <PropertyGroup>
                  <PropertyRow label={t('assetDetail.riskScore', 'Risk score')}>
                    <RiskScoreBadge score={asset.riskScore} state={riskScoreState(asset)} />
                  </PropertyRow>
                  <PropertyRow label={t('assetDetail.openFindings', 'Open findings')}>
                    {asset.findingCount > 0 ? (
                      <OpenFindingsLink assetId={asset.id} count={asset.findingCount} />
                    ) : (
                      <span className="text-muted-foreground">
                        {t('assets.overview2.noOpenShort', 'No open findings')}
                      </span>
                    )}
                  </PropertyRow>
                  <PropertyRow label={t('assetDetail.status', 'Status')}>
                    <span className="inline-flex flex-wrap items-center gap-1.5">
                      <AssetStatusBadge status={asset.status} />
                      <AssetLivenessBadge liveness={asset.liveness} />
                    </span>
                  </PropertyRow>
                  <PropertyRow label={t('assetDetail.type', 'Type')}>{typeLabel}</PropertyRow>
                </PropertyGroup>
                <PropertyFold
                  label={t('assetDetail.moreProperties', 'ID, description and tags')}
                  openLabel={t('assetDetail.fewerProperties', 'Fewer details')}
                >
                  <PropertyGroup>
                    <PropertyRow label={t('assetDetail.id', 'ID')}>
                      <code className="font-mono text-xs break-all">{asset.id}</code>
                    </PropertyRow>
                    <PropertyRow label={t('assetDetail.description', 'Description')} top>
                      {asset.description}
                    </PropertyRow>
                    {asset.tags && asset.tags.length > 0 && (
                      <PropertyRow label={t('assetDetail.tags', 'Tags')} top>
                        <span className="flex flex-wrap gap-1 max-md:justify-end">
                          {asset.tags.map((tag) => (
                            <Badge key={tag} variant="secondary">
                              {tag}
                            </Badge>
                          ))}
                        </span>
                      </PropertyRow>
                    )}
                  </PropertyGroup>
                </PropertyFold>
              </PropertyList>
            </div>
          </aside>

          {/* The strip waits for the reads that decide its tabs, and the panel's
                sections read their own data (served from the page view a moment
                after the asset) and some hide when empty: both show once they
                answered, so nothing moves after it painted. The name and the
                properties paint at once. */}
          <SettleGroup fallback={<PanelSkeleton />}>
            <SettleOn pending={related.isLoading || webEvidence.isLoading} />

            <div className={STRIP}>
              {/* Eight tabs do not fit a phone: the shared strip is one row you swipe
                  sideways, with an edge fade and the active tab kept in view. */}
              <TabsList>
                {tabs.map((key) => {
                  const Icon = TAB_ICON[key]
                  return (
                    <TabsTrigger key={key} value={key}>
                      <Icon aria-hidden />
                      {t(`assetDetail.tab.${key}`, TAB_LABEL[key])}
                      {key === 'findings' && asset.findingCount > 0 && (
                        <TabsCount value={asset.findingCount} />
                      )}
                      {key === 'relationships' && related.total > 0 && (
                        <TabsCount value={related.total} />
                      )}
                      {key === 'technologies' && <TabsCount value={technologyCount} />}
                    </TabsTrigger>
                  )
                })}
              </TabsList>
            </div>

            <div data-slot="asset-panel" className={cn(PANEL, WIDE_TABS.has(tab) && PANEL_FULL)}>
              <TabsContent value="overview">
                <DetailSectionList>
                  {/* What it is and what runs on it; hidden when nothing was collected. */}
                  <KeyFactsSection asset={asset} />
                  <RiskSummarySection
                    asset={asset}
                    numbersShown
                    onViewFindings={() => setTab('findings')}
                  />
                  <AssetNextSteps assetId={asset.id} />
                  {/* When active scans of this asset may run (RFC-067); hidden when no window applies. */}
                  <AssetScanWindowCard assetId={asset.id} />
                </DetailSectionList>
              </TabsContent>
              <TabsContent value="findings">
                <AssetFindings
                  assetId={asset.id}
                  assetName={asset.name}
                  findingCount={asset.findingCount}
                  severityCounts={asset.findingSeverityCounts}
                />
              </TabsContent>
              {relationshipsOn && (
                <TabsContent value="relationships">
                  <AssetRelationshipsTab
                    assetId={asset.id}
                    sourceAsset={{
                      id: asset.id,
                      name: asset.name,
                      type: asset.type,
                      subType: asset.subType,
                    }}
                    onNavigateToAsset={goToRelated}
                  />
                </TabsContent>
              )}
              <TabsContent value="found">
                <DetailSections>
                  <AssetAttributionSection
                    assetId={asset.id}
                    assetName={asset.name}
                    assetType={asset.type}
                  />
                  <AssetLineageSection assetId={asset.id} />
                  <AssetAttributeSourcesSection assetId={asset.id} />
                  <AssetFreshnessSection assetId={asset.id} />
                  <AssetCoverageSection assetId={asset.id} />
                  <AssetIdentitySections
                    assetId={asset.id}
                    assetName={asset.name}
                    properties={asset.metadata}
                  />
                </DetailSections>
              </TabsContent>
              {/* Open ports of the addresses a domain or subdomain resolves to. */}
              <TabsContent value="ports">
                <div className="flex min-w-0 flex-col gap-page">
                  {/* The addresses it resolves to, by provider, with history (research/531). */}
                  <NameAddressesSection assetId={asset.id} />
                  <ResolvedPortsSection assetId={asset.id} />
                </div>
              </TabsContent>
              {technologyCount > 0 && (
                <TabsContent value="technologies">
                  <AssetTechnologiesTab assetId={asset.id} />
                </TabsContent>
              )}
              <TabsContent value="web">
                <div className="flex min-w-0 flex-col gap-page">
                  {/* What a sensor saw when it fetched the asset (RFC-081); hidden when none. */}
                  <AssetWebEvidenceCard assetId={asset.id} />
                  {/* Header posture, endpoints, parameters and changes of a web origin (research/292). */}
                  {isWebOriginType(asset.type, asset.subType) && (
                    <OriginWebSection
                      assetId={asset.id}
                      assetName={asset.name}
                      properties={asset.metadata}
                      onOpenPaths={() => setTab('paths')}
                    />
                  )}
                </div>
              </TabsContent>
              {isWebOriginType(asset.type, asset.subType) && (
                <TabsContent value="paths">
                  <AssetPathsTab asset={asset} />
                </TabsContent>
              )}
              <TabsContent value="owners">
                <AssetOwnersTab assetId={asset.id} />
              </TabsContent>
              <TabsContent value="activity">
                <AssetTimeline assetId={asset.id} onWhy={() => setTab('found')} />
              </TabsContent>
            </div>
          </SettleGroup>
        </Tabs>
      </PageStack>
    </Main>
  )
}
