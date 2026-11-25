'use client'

/**
 * Attack surface > Discovery: the coverage work by stage, with Run per
 * stage, Run all and Abort all.
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { AttackSurfaceSectionTabs, EASMDiscovery } from '@/features/attack-surface'

export default function AttackSurfaceDiscoveryPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('attackSurface.title', 'Attack surface')}
          description={t(
            'attackSurface.discovery.pageDescription',
            'How discovery runs for your organization, stage by stage: what ran last, what runs now, and what holds a stage back.'
          )}
        />
        <AttackSurfaceSectionTabs />
        <EASMDiscovery />
      </PageStack>
    </Main>
  )
}
