'use client'

import { useTranslation } from '@/context/i18n-provider'
import { HubPage } from '@/features/remediation-hub/components/hub-page'
import { SuggestionsInbox } from '@/features/remediation-hub/components/suggestions-inbox'

export default function RemediationSuggestionsPage() {
  const { t } = useTranslation()
  return (
    <HubPage
      title={t('remediationHub.suggestions.title')}
      description={t('remediationHub.suggestions.description')}
    >
      <SuggestionsInbox />
    </HubPage>
  )
}
