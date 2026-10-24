'use client'

/**
 * Attack surface › Lookalikes: passive lookalike-domain monitoring (RFC-083).
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { AttackSurfaceSectionTabs, EASMLookalikes } from '@/features/attack-surface'

export default function AttackSurfaceLookalikesPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('lookalikes.pageTitle', 'Attack surface')}
          description={t(
            'lookalikes.pageDescription',
            'Domains registered by others that imitate yours, found without contacting them.'
          )}
        />
        <AttackSurfaceSectionTabs />
        <EASMLookalikes />
      </PageStack>
    </Main>
  )
}
