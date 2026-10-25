'use client'

import Link from '@/components/link'
import { TruncatedText } from '@/features/shared'
import type { Finding } from '@/features/findings/types/finding.types'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { AssetMarkers } from './asset-markers'

/**
 * The Asset cell of a findings row: the asset name with its internet-facing
 * and crown-jewel markers, and the place on the asset below (a path or URL,
 * cut from the middle so the part that differs between two findings stays
 * visible; the full value is in the tooltip).
 */
export function FindingAssetCell({ finding }: { finding: Finding }) {
  const { t } = useTranslation()
  const asset = finding.assets[0]
  const loc = finding.location
  const markers = (
    <AssetMarkers internetFacing={asset?.isInternetAccessible} crownJewel={asset?.isCrownJewel} />
  )
  if (loc && (loc.asset || loc.detail)) {
    return (
      <div data-slot="finding-asset-cell" className="flex min-w-0 max-w-[240px] flex-col">
        {loc.asset && (
          <div className="flex min-w-0 items-center gap-1.5">
            <TruncatedText value={loc.asset} label={t('findings.list.asset')} className="text-sm" />
            {markers}
          </div>
        )}
        {loc.detail && (
          <TruncatedText
            value={loc.detail}
            label={t('findings.list.location')}
            middle={30}
            className={cn('font-mono text-muted-foreground', loc.asset ? 'text-xs' : 'text-sm')}
          />
        )}
      </div>
    )
  }
  // No asset name and no location: a plain "Unnamed asset" link to the asset
  // (an id fragment meant nothing to people).
  if (asset?.id) {
    return (
      <span data-slot="finding-asset-cell" className="inline-flex items-center gap-1.5">
        <Link
          href={`/assets/${encodeURIComponent(asset.id)}`}
          title={asset.id}
          className="text-muted-foreground hover:text-foreground text-sm hover:underline"
        >
          {t('findings.list.unnamedAsset', 'Unnamed asset')}
        </Link>
        {markers}
      </span>
    )
  }
  return <span className="text-muted-foreground text-sm">—</span>
}
