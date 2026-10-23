'use client'

import { Lock } from 'lucide-react'
import { Main } from '@/components/layout'
import { EmptyState, PageHeader, PageStack } from '@/features/shared'
import { AssetsSectionTabs } from '@/features/assets/components/assets-section-tabs'
import { AttentionReasons } from '@/features/assets/components/attention/attention-reasons'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'

export default function AssetAttentionPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  return (
    <Main>
      <PageStack>
        <PageHeader title={t('assets.overview.title', 'Assets')} />
        <AssetsSectionTabs />
        {can(Permission.AssetsRead) ? (
          <AttentionReasons />
        ) : (
          <EmptyState
            className="border-dashed"
            icon={Lock}
            title={t('assets.inventoryPage.noAccess', "You don't have access to assets")}
            description={t(
              'assets.inventoryPage.noAccessHint',
              'Ask an administrator for the assets:read permission to view the inventory.'
            )}
          />
        )}
      </PageStack>
    </Main>
  )
}
