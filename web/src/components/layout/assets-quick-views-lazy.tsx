'use client'

import dynamic from 'next/dynamic'
import { usePathname } from 'next/navigation'

/** Whether `pathname` is the asset inventory (not groups, activity or a detail page). */
export function isAssetInventoryPath(pathname: string): boolean {
  return pathname === '/assets'
}

// The views read the asset stats hooks and the asset-type registry, which every
// other page has no use for: the code downloads only when the inventory opens.
// The list renders nothing until its data is in, so no space needs reserving.
const AssetsQuickViews = dynamic(
  () => import('./assets-quick-views').then((m) => m.AssetsQuickViews),
  {
    ssr: false,
  }
)

/** The inventory's quick views under the Assets row, loaded on the inventory page. */
export function LazyAssetsQuickViews() {
  const pathname = usePathname()
  return isAssetInventoryPath(pathname) ? <AssetsQuickViews /> : null
}
