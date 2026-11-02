'use client'

/**
 * Attack surface > Exposure items: the exposures of the external surface,
 * by severity and by type, open work on monitored assets first.
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { AttackSurfaceSectionTabs, EASMExposureItems } from '@/features/attack-surface'

export default function AttackSurfaceExposuresPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('attackSurface.title', 'Attack surface')}
          description={t(
            'attackSurface.exposures.pageDescription',
            'What your external assets expose: open ports, weak TLS, takeover risks, leaked data and more, with the asset each one is on.'
          )}
        />
        <AttackSurfaceSectionTabs />
        <EASMExposureItems />
      </PageStack>
    </Main>
  )
}
