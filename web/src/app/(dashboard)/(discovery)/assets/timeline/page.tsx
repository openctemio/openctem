'use client'

import { ShieldX } from 'lucide-react'
import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { AssetsSectionTabs } from '@/features/assets/components/assets-section-tabs'
import { RecentAssetChanges } from '@/features/assets'
import { EmptyState, PageHeader } from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'

/** Discovery > Assets > Timeline: the organization's recent asset changes (RFC-069). */
export default function AssetTimelinePage() {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.AssetsRead)
  return (
    <Main>
      <PageHeader
        title={t('assetTimeline.feedTitle', 'Recent asset changes')}
        description={t(
          'assetTimeline.feedDescription',
          'Every change of an asset value or of the source that decides it, newest first. Only assets you can see are listed.'
        )}
      />
      <AssetsSectionTabs />
      <div className="mt-5">
        {canRead ? (
          <RecentAssetChanges />
        ) : (
          <EmptyState
            icon={ShieldX}
            title={t('assetTimeline.noAccessTitle', 'Access denied')}
            description={t(
              'assetTimeline.noAccess',
              'You do not have permission to view assets. Ask your administrator for access.'
            )}
          />
        )}
      </div>
    </Main>
  )
}
