'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader } from '@/features/shared'
import { PentestRetestsSection } from '@/features/pentest/components/pentest-retests-section'

/**
 * Validation › Retest queue: every finding awaiting re-verification, across
 * campaigns (was /pentest/retests; 308 from there). A campaign's own queue is
 * the Retests tab of its page.
 *
 * anatomy-ok: inside a PageStack (PentestRetestsSection renders the header
 * into its own PageStack).
 */
export default function RetestQueuePage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PentestRetestsSection
        header={(actions) => (
          <PageHeader
            title={t('validation.retests.title', 'Retest queue')}
            description={t(
              'validation.retests.description',
              'Findings that were fixed and need re-verification, across campaigns.'
            )}
          >
            {actions}
          </PageHeader>
        )}
      />
    </Main>
  )
}
