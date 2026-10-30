'use client'

/**
 * Scoping › Scope › Domain proof: domains the organization has proved it
 * controls (DNS TXT). A route tab of Scope, so the Scope page keeps one tab
 * row (research/249 R21). The panel and its API are unchanged; the route is
 * gated like the panel was (scope:read, attack surface module).
 */

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { SCOPE_SECTION_TABS } from '@/config/section-tabs'
import { GatedSectionTabs, PageHeader, PageStack } from '@/features/shared'
import { EASMDomainProofPanel } from '@/features/attack-surface/components/easm-domain-proof'

export default function ScopeDomainProofPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('scope.tabs.proof', 'Domain proof')}
          description={t(
            'scope.proofPage.description',
            'Domains your organization has proved it controls with a DNS record. Proof authorizes no scan by itself; it is what platform sensors and intrusive checks require.'
          )}
        />
        <GatedSectionTabs tabs={SCOPE_SECTION_TABS} label={t('scope.sections', 'Scope sections')} />
        <EASMDomainProofPanel />
      </PageStack>
    </Main>
  )
}
