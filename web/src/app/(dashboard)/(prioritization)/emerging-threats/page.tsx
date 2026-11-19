'use client'

import { Main } from '@/components/layout'
import { PageHeader, PageStack } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { EmergingThreatsList } from '@/features/emerging-threats'
import { FeedDataAsOf } from '@/features/threat-intel/components/feed-freshness-banner'

export default function EmergingThreatsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('emergingThreats.title')}
          description={
            <span className="flex flex-wrap items-center gap-x-2">
              <span>{t('emergingThreats.description')}</span>
              <FeedDataAsOf className="text-muted-foreground" />
            </span>
          }
        />
        <EmergingThreatsList />
      </PageStack>
    </Main>
  )
}
