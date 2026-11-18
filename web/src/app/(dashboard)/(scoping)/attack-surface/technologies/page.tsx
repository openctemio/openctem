'use client'

/**
 * Attack surface > Technologies: what the external assets run, by version,
 * with the CVEs known for each version.
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { AttackSurfaceSectionTabs, EASMTechnologies } from '@/features/attack-surface'

export default function AttackSurfaceTechnologiesPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('attackSurface.title', 'Attack surface')}
          // A list page: on a phone the list comes first, so the sentence
          // under the title is left to wider screens (as on Scans).
          description={
            <span className="max-md:hidden">
              {t(
                'attackSurface.technologies.pageDescription',
                'The technologies your external assets run, by version, with the CVEs known for each version and the assets that run it.'
              )}
            </span>
          }
        />
        <AttackSurfaceSectionTabs />
        <EASMTechnologies />
      </PageStack>
    </Main>
  )
}
