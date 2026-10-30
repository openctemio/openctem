'use client'

/**
 * Scoping › Scope › Networks: AS numbers and organization names that are the
 * organization's, looked up to list the address ranges they announce. A route
 * tab of Scope, so the Scope page keeps one tab row (research/249 R21). The
 * panel and its API are unchanged; the route is gated like the panel was
 * (scope:read, attack surface module).
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { SCOPE_SECTION_TABS } from '@/config/section-tabs'
import { GatedSectionTabs, PageHeader, PageStack } from '@/features/shared'
import { EASMNetworkSeedsPanel } from '@/features/attack-surface/components/easm-network-seeds'

export default function ScopeNetworksPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('networkSeeds.tab', 'Networks')}
          description={t(
            'scope.networksPage.description',
            'Address ranges announced by the AS numbers and organizations that are yours. A network authorizes no scan by itself; add its ranges as scope entries.'
          )}
        />
        <GatedSectionTabs tabs={SCOPE_SECTION_TABS} label={t('scope.sections', 'Scope sections')} />
        <EASMNetworkSeedsPanel />
      </PageStack>
    </Main>
  )
}
