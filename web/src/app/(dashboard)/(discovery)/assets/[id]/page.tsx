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
import Link from '@/components/link'
import { AlertCircle, ArrowLeft, Globe, Loader2, Server, Shield } from 'lucide-react'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { DetailSections, PageHeader } from '@/features/shared'
import {
  AssetAttributeSourcesSection,
  AssetAttributionSection,
  AssetIdentitySections,
  useAsset,
} from '@/features/assets'
import { AssetScanWindowCard } from '@/features/scan-windows'
import { cn } from '@/lib/utils'
import { RepositoryWorkspace } from '@/features/repositories/components/repository-workspace'
import { CRITICALITY_TEXT_COLORS } from '@/lib/criticality-colors'

const CRITICALITY_COLOR: Record<string, string> = CRITICALITY_TEXT_COLORS

export default function AssetDetailPage() {
  const router = useRouter()
  const params = useParams<{ id: string }>()
  const assetId = params?.id ?? null

  const { asset, isLoading, error } = useAsset(assetId)
  useBreadcrumbTitle(asset?.name)

  if (isLoading) {
    return (
      <Main>
        <div className="flex items-center justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </Main>
    )
  }

  if (error || !asset) {
    return (
      <Main>
        <PageHeader title="Asset not found" className="mb-6" />
        <Card className="border-destructive/40">
          <CardContent className="flex flex-col items-center justify-center py-12">
            <AlertCircle className="h-12 w-12 text-destructive mb-3" />
            <p className="text-base font-medium">
              {error ? 'Failed to load asset details' : 'No asset with this ID'}
            </p>
            <p className="text-sm text-muted-foreground mt-1">
              The asset may have been deleted or you may not have access.
            </p>
            <Button variant="outline" className="mt-4" onClick={() => router.push('/assets')}>
              <ArrowLeft className="me-2 h-4 w-4" />
              Back to assets
            </Button>
          </CardContent>
        </Card>
      </Main>
    )
  }

  if (asset.type === 'repository') {
    return <RepositoryWorkspace repositoryId={asset.id} />
  }

  // The inventory filtered to this asset's type (and alias sub-type).
  const listingQuery = new URLSearchParams({ types: asset.type })
  if (asset.subType) listingQuery.set('sub_type', asset.subType)
  const typeLabel = asset.type.replace(/_/g, ' ')

  return (
    <Main>
      <div className="mb-4">
        <Button variant="ghost" size="sm" onClick={() => router.back()}>
          <ArrowLeft className="me-2 h-4 w-4" />
          Back
        </Button>
      </div>

      <PageHeader title={asset.name} description={`Asset · ${typeLabel}`} className="mb-6" />

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Criticality
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p
              className={cn('text-2xl font-bold capitalize', CRITICALITY_COLOR[asset.criticality])}
            >
              {asset.criticality}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Server className="h-4 w-4" />
              Risk Score
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{asset.riskScore}/100</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Exposure
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Badge variant="outline" className="text-base capitalize">
              {asset.exposure}
            </Badge>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Findings</CardTitle>
          </CardHeader>
          <CardContent>
            <Link
              href={`/findings?asset_id=${assetId}`}
              className={cn(
                'inline-block text-2xl font-bold hover:underline',
                asset.findingCount > 0 ? 'text-destructive' : ''
              )}
              aria-label={`View ${asset.findingCount} findings for this asset`}
            >
              {asset.findingCount}
            </Link>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Properties</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <DetailRow label="ID" value={<code className="text-xs font-mono">{asset.id}</code>} />
          <DetailRow label="Type" value={<span className="capitalize">{typeLabel}</span>} />
          <DetailRow
            label="Status"
            value={
              <Badge variant="outline" className="capitalize">
                {asset.status}
              </Badge>
            }
          />
          <DetailRow
            label="Scope"
            value={
              <Badge variant="outline" className="capitalize">
                {asset.scope}
              </Badge>
            }
          />
          {asset.description && <DetailRow label="Description" value={asset.description} />}
          {asset.tags && asset.tags.length > 0 && (
            <DetailRow
              label="Tags"
              value={
                <div className="flex flex-wrap gap-1">
                  {asset.tags.map((t) => (
                    <Badge key={t} variant="secondary" className="text-xs">
                      {t}
                    </Badge>
                  ))}
                </div>
              }
            />
          )}
        </CardContent>
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Identity</CardTitle>
        </CardHeader>
        <CardContent>
          <DetailSections>
            <AssetAttributionSection
              assetId={asset.id}
              assetName={asset.name}
              assetType={asset.type}
            />
            <AssetAttributeSourcesSection assetId={asset.id} />
            <AssetIdentitySections
              assetId={asset.id}
              assetName={asset.name}
              properties={asset.metadata}
            />
          </DetailSections>
        </CardContent>
      </Card>

      {/* When active scans of this asset may run (RFC-067); hidden when no window applies. */}
      <AssetScanWindowCard assetId={asset.id} className="mt-4" />

      {/* The inventory filtered to this type */}
      <Card className="mt-4 bg-muted/30">
        <CardContent className="flex items-center justify-between py-4">
          <div>
            <p className="text-sm font-medium">Looking for richer details?</p>
            <p className="text-xs text-muted-foreground mt-1">
              The inventory lists every {typeLabel} with its filters, columns and actions.
            </p>
          </div>
          <Button variant="outline" onClick={() => router.push(`/assets?${listingQuery}`)}>
            Open {typeLabel} list
          </Button>
        </CardContent>
      </Card>
    </Main>
  )
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b last:border-0">
      <span className="text-sm text-muted-foreground shrink-0">{label}</span>
      <div className="text-sm text-end">{value}</div>
    </div>
  )
}
