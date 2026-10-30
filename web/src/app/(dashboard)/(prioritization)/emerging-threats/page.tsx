'use client'

import { Main } from '@/components/layout'
import { PageHeader, PageStack } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { EmergingThreatsList } from '@/features/emerging-threats'

export default function EmergingThreatsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('emergingThreats.title')}
          description={t('emergingThreats.description')}
        />
        <EmergingThreatsList />
      </PageStack>
    </Main>
  )
}
