'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { WordlistsPanel } from '@/features/wordlists'

/** Settings › Scanning › Wordlists: the words subdomain discovery tries under your domains. */
export default function WordlistsSettingsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('settings.item.wordlists', 'Wordlists')}
          description={t(
            'wordlists.page.description',
            'Subdomain discovery asks DNS for likely names under your domains. Each run combines a platform list built from public sources, the words learned from the names you already have (with variants such as -uat2), and your own lists. Every run records the versions it used.'
          )}
        />
        <WordlistsPanel />
      </PageStack>
    </Main>
  )
}
