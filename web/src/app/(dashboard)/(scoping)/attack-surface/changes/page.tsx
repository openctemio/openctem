'use client'

/**
 * Attack surface › Changes: typed changes of the external attack surface
 * (RFC-080). The weekly digest links here with its window.
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { AttackSurfaceSectionTabs, EASMChanges } from '@/features/attack-surface'

export default function AttackSurfaceChangesPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('attackSurface.title', 'Attack surface')}
          // A list page: on a phone the list comes first (as on Certificates).
          description={
            <span className="max-md:hidden">
              {t(
                'attackSurface.changes.pageDescription',
                'What changed on your external attack surface. A weekly digest of these changes goes to your administrators and notification channels.'
              )}
            </span>
          }
        />
        <AttackSurfaceSectionTabs />
        <EASMChanges />
      </PageStack>
    </Main>
  )
}
