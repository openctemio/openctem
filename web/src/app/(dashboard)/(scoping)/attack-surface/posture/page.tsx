'use client'

/**
 * Attack surface > Posture: the grade of the external surface, what takes
 * points away and what to fix to reach the next grade.
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { AttackSurfaceSectionTabs, EASMPosture } from '@/features/attack-surface'

export default function AttackSurfacePosturePage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('attackSurface.title', 'Attack surface')}
          description={t(
            'attackSurface.posture.pageDescription',
            'A grade from A to F for your external attack surface and each root domain, what takes points away and what to fix to reach the next grade.'
          )}
        />
        <AttackSurfaceSectionTabs />
        <EASMPosture />
      </PageStack>
    </Main>
  )
}
