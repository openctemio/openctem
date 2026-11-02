'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { ContentRulesPanel } from '@/features/content-rules'
import { PageHeader, PageStack } from '@/features/shared'

/** Settings › Scanning › Detection rules: technologies and exposed secrets found in scan results. */
export default function DetectionRulesSettingsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('settings.item.detectionRules', 'Detection rules')}
          description={t(
            'contentRules.page.description',
            'Rules read the web responses your scans already fetch: technology rules name products and versions, sensitive-data rules find keys, tokens and internal names. A found secret is kept masked, never in full. Every scan records the rule versions it used.'
          )}
        />
        <ContentRulesPanel />
      </PageStack>
    </Main>
  )
}
