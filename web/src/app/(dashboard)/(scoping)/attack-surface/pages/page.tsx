'use client'

/**
 * Attack surface › Page changes: web page monitoring (RFC-138).
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { AttackSurfaceSectionTabs, PageMonitor } from '@/features/attack-surface'

export default function AttackSurfacePagesPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('pageMonitor.pageTitle', 'Attack surface')}
          description={t(
            'pageMonitor.pageDescription',
            'The scripts and content of your web pages, and what changed on them.'
          )}
        />
        <AttackSurfaceSectionTabs />
        <PageMonitor />
      </PageStack>
    </Main>
  )
}
