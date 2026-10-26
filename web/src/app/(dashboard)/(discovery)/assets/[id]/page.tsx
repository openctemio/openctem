/**
 * Generic asset detail page — `/assets/{id}`.
 *
 * Catches deep-links from blast-radius views (Vuln Detail Sheet → "Affected
 * Assets" tab → click row, Component Detail Sheet → "Used By Assets" tab →
 * click row). Without this route those clicks 404'd.
 *
 * Behavior:
 *  - Fetch asset by id.
 *  - A repository opens its workspace here (branches, findings by branch,
 *    scan settings): one URL per asset, whatever its type.
 *  - Other asset types: render a minimal detail layout (header + key fields)
 *    plus a link to the inventory filtered to the asset's type.
 */

'use client'

import * as React from 'react'
import { useRouter, useParams } from 'next/navigation'
import { OpenFindingsLink } from '@/features/assets/components/service-cells'
import { ArrowLeft, Lock } from 'lucide-react'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSections, EmptyState, ErrorState, PageHeader, PageStack } from '@/features/shared'
import { RiskScoreBadge, riskScoreState } from '@/features/shared/components/risk-score-badge'
import {
  AssetAttributeSourcesSection,
  AssetFreshnessSection,
  AssetCoverageSection,
  AssetAttributionSection,
  AssetIdentitySections,
  AssetTimeline,
  useAsset,
} from '@/features/assets'
import { ClassificationBadges } from '@/features/assets/components/classification-badges'
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { AssetStatusBadge } from '@/features/asset-lifecycle'
import { AssetScanWindowCard } from '@/features/scan-windows'
import { AssetWebEvidenceCard } from '@/features/attack-surface'
import { OriginWebSection, isWebOriginType } from '@/features/web-surface'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { RepositoryWorkspace } from '@/features/repositories/components/repository-workspace'

export default function AssetDetailPage() {
  const router = useRouter()
  const params = useParams<{ id: string }>()
  const assetId = params?.id ?? null

  const { t } = useTranslation()
  const { can } = usePermissions()
  const { isLoading: tenantLoading } = useTenant()
  const { asset, isLoading, error, mutate } = useAsset(assetId)
  useBreadcrumbTitle(asset?.name)

  // useAsset sends nothing until the tenant is known, so wait for it instead
  // of reading the empty answer as "not found".
  if (tenantLoading || isLoading) {
    return (
      <Main>
        <div
          className="space-y-4"
          role="status"
          aria-label={t('assetDetail.loading', 'Loading asset')}
        >
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-40 w-full" />
        </div>
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
              <Button variant="outline" className="mt-4" onClick={() => router.push('/assets')}>
                <ArrowLeft className="me-2 h-4 w-4" />
                {t('assetDetail.backToAssets', 'Back to assets')}
              </Button>
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
  const typeLabel = getAssetTypeLabel(asset.type)

  return (
    <Main>
      <PageStack>
        <Button variant="ghost" size="sm" className="self-start" onClick={() => router.back()}>
          <ArrowLeft className="me-2 h-4 w-4" />
          {t('assetDetail.back', 'Back')}
        </Button>

        <PageHeader
          title={asset.name}
          description={t('assetDetail.subtitle', 'Asset type: {type}', { type: typeLabel })}
        />

        <div className="flex flex-wrap items-center gap-2">
          <ClassificationBadges
            scope={asset.scope}
            exposure={asset.exposure}
            criticality={asset.criticality}
            size="md"
            labelled
          />
          <RiskScoreBadge score={asset.riskScore} state={riskScoreState(asset)} labelled />
          {asset.findingCount > 0 ? (
            <OpenFindingsLink assetId={assetId} count={asset.findingCount} className="text-sm" />
          ) : (
            <span className="text-sm text-muted-foreground">
              {t('assets.overview2.noOpenShort', 'No open findings')}
            </span>
          )}
        </div>

        <Card>
          <CardHeader>
            <CardTitle>{t('assetDetail.properties', 'Properties')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <DetailRow
              label={t('assetDetail.id', 'ID')}
              value={<code className="font-mono text-xs break-all">{asset.id}</code>}
            />
            <DetailRow label={t('assetDetail.type', 'Type')} value={typeLabel} />
            <DetailRow
              label={t('assetDetail.status', 'Status')}
              value={<AssetStatusBadge status={asset.status} />}
            />
            {asset.description && (
              <DetailRow
                label={t('assetDetail.description', 'Description')}
                value={asset.description}
              />
            )}
            {asset.tags && asset.tags.length > 0 && (
              <DetailRow
                label={t('assetDetail.tags', 'Tags')}
                value={
                  <div className="flex flex-wrap justify-end gap-1">
                    {asset.tags.map((tag) => (
                      <Badge key={tag} variant="secondary" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                }
              />
            )}
          </CardContent>
        </Card>

        <Card id="asset-identity">
          <CardHeader>
            <CardTitle>{t('assetDetail.identity', 'Identity')}</CardTitle>
          </CardHeader>
          <CardContent>
            <DetailSections>
              <AssetAttributionSection
                assetId={asset.id}
                assetName={asset.name}
                assetType={asset.type}
              />
              <AssetAttributeSourcesSection assetId={asset.id} />
              <AssetFreshnessSection assetId={asset.id} />
              <AssetCoverageSection assetId={asset.id} />
              <AssetIdentitySections
                assetId={asset.id}
                assetName={asset.name}
                properties={asset.metadata}
              />
            </DetailSections>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t('assetTimeline.tab', 'Timeline')}</CardTitle>
          </CardHeader>
          <CardContent>
            <AssetTimeline
              assetId={asset.id}
              onWhy={() =>
                document
                  .getElementById('asset-identity')
                  ?.scrollIntoView({ behavior: 'smooth', block: 'start' })
              }
            />
          </CardContent>
        </Card>
        {/* What a sensor saw when it fetched the asset (RFC-081); hidden when none. */}
        <AssetWebEvidenceCard assetId={asset.id} />
        {/* Header posture, endpoints, parameters and changes of a web origin (research/292). */}
        {isWebOriginType(asset.type) && (
          <OriginWebSection assetId={asset.id} assetName={asset.name} properties={asset.metadata} />
        )}
        {/* When active scans of this asset may run (RFC-067); hidden when no window applies. */}
        <AssetScanWindowCard assetId={asset.id} />

        {/* The inventory filtered to this type */}
        <Card className="bg-muted/30">
          <CardContent className="flex flex-wrap items-center justify-between gap-3 py-4">
            <div className="min-w-0">
              <p className="text-sm font-medium">
                {t('assetDetail.richerTitle', 'Looking for richer details?')}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                {t(
                  'assetDetail.richerHint',
                  'The inventory lists every {type} with its filters, columns and actions.',
                  { type: typeLabel }
                )}
              </p>
            </div>
            <Button variant="outline" onClick={() => router.push(`/assets?${listingQuery}`)}>
              {t('assetDetail.openList', 'Open {type} list', { type: typeLabel })}
            </Button>
          </CardContent>
        </Card>
      </PageStack>
    </Main>
  )
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b py-2 last:border-0">
      <span className="shrink-0 text-sm text-muted-foreground">{label}</span>
      <div className="min-w-0 text-end text-sm break-words">{value}</div>
    </div>
  )
}
