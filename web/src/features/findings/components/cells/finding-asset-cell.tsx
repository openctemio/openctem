'use client'

import Link from '@/components/link'
import { TruncatedText } from '@/features/shared'
import type { Finding } from '@/features/findings/types/finding.types'
import { useTranslation } from '@/context/i18n-provider'
import { AssetMarkers } from './asset-markers'

/**
 * The Asset cell of a findings row: the asset name with its internet-facing
 * and crown-jewel markers on one line. The place on the asset (a path or URL)
 * is in the name's tooltip and accessible name; with no asset name the place
 * is the line, cut from the middle so the part that differs stays visible.
 */
export function FindingAssetCell({ finding }: { finding: Finding }) {
  const { t } = useTranslation()
  const asset = finding.assets[0]
  const loc = finding.location
  const markers = (
    <AssetMarkers internetFacing={asset?.isInternetAccessible} crownJewel={asset?.isCrownJewel} />
  )
  if (loc && (loc.asset || loc.detail)) {
    // One line: the asset name, or the place when there is no name. The place
    // under a name (a path or URL) is in the tooltip and the accessible name,
    // so the row stays one line tall; the drawer shows both.
    return (
      <div data-slot="finding-asset-cell" className="flex min-w-0 items-center gap-1.5">
        {loc.asset ? (
          <TruncatedText
            value={loc.asset}
            label={t('findings.list.asset')}
            detail={loc.detail}
            detailLabel={t('findings.list.location')}
            className="text-sm"
          />
        ) : (
          <TruncatedText
            value={loc.detail}
            label={t('findings.list.location')}
            middle={30}
            className="font-mono text-xs text-muted-foreground"
          />
        )}
        {markers}
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
