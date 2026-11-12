'use client'

// The finding's asset liveness in the drawer: "Unreachable since <date>.
// Last checked 2 days ago by <sensor>." with what it means for the finding
// (stays open and cannot be verified, or closes as obsolete when gone).
// Reads the asset through the shared asset cache; nothing when the asset is
// alive, not checked, or the reader may not see assets.

import { AssetLivenessLine } from '@/features/asset-lifecycle'
import { useAsset } from '@/features/assets/hooks/use-assets'

export function FindingAssetLiveness({ assetId }: { assetId?: string }) {
  const { asset } = useAsset(assetId ?? null)
  return <AssetLivenessLine liveness={asset?.liveness} />
}
