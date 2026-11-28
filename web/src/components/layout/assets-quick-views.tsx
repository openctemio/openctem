'use client'

import { useMemo } from 'react'
import { usePathname } from 'next/navigation'
import { useTranslation } from '@/context/i18n-provider'
import { useUrlParams } from '@/hooks/use-url-param'
import { usePermissions, Permission } from '@/lib/permissions'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'
import { useAssetStats } from '@/features/assets/hooks/use-assets'
import { DEFAULT_ATTRIBUTION } from '@/features/assets/lib/inventory-url'
import {
  activeQuickView,
  assetQuickViews,
  lensCounts,
} from '@/features/assets/lib/inventory-lenses'
import { NavQuickViewList } from './nav-quick-views'
import { isAssetInventoryPath } from './assets-quick-views-lazy'

/**
 * The inventory's quick views under the Assets row: All assets, then each lens
 * that holds an asset, then "Other", with counts. They show only while the
 * inventory is open. The counts come from the data-scoped `/assets/stats`
 * with the list's default attribution (the server applies the list's own
 * attribution field), so a count always matches the list it opens.
 */
export function AssetsQuickViews() {
  const pathname = usePathname()
  if (!isAssetInventoryPath(pathname)) return null
  return <AssetsQuickViewGate />
}

function AssetsQuickViewGate() {
  const { can } = usePermissions()
  return can(Permission.AssetsRead) ? <AssetsQuickViewList /> : null
}

function AssetsQuickViewList() {
  const { t } = useTranslation()
  const search = useUrlParams()
  const { registry } = useAssetTypeRegistry()
  // The inventory's own attribution default, so "All assets 615" here is
  // the total the list opens with (not every name awaiting review).
  const { stats, isLoading, error } = useAssetStats({ attribution: DEFAULT_ATTRIBUTION })
  const counts = useMemo(
    () => lensCounts(registry, stats.byTypeSubType),
    [registry, stats.byTypeSubType]
  )
  // Without the registry every type would land in "Other": wait for it.
  if (isLoading || error || !registry) return null
  const active = activeQuickView(search, counts)
  const views = assetQuickViews(registry, stats.total, counts)
  return (
    <NavQuickViewList
      label={t('assets.quickView.nav', 'Asset views')}
      fallbackHref="/assets"
      className="ms-[11px]"
      views={views.map((v) => ({
        key: v.key,
        label:
          v.key === 'all'
            ? t('assets.quickView.all', 'All assets')
            : t(`assets.lens.${v.key}`, v.label),
        href: v.href,
        count: v.count,
        active: v.key === active,
      }))}
    />
  )
}
