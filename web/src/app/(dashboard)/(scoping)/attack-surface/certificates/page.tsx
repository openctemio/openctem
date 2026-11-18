'use client'

/**
 * Attack surface > Certificates: the certificate assets of the external
 * surface with their expiry status.
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { AttackSurfaceSectionTabs, EASMCertificates } from '@/features/attack-surface'

export default function AttackSurfaceCertificatesPage() {
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
                'attackSurface.certificates.pageDescription',
                'The TLS certificates found on your external assets: who they were issued to, who issued them, and when they expire.'
              )}
            </span>
          }
        />
        <AttackSurfaceSectionTabs />
        <EASMCertificates />
      </PageStack>
    </Main>
  )
}
