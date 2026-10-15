'use client'

/**
 * CI/CD integration (api RFC-051): the pipelines that scan your repositories
 * from any supported CI system, their runs and repository coverage, and
 * the setup that decides which pipelines may send results (trust) and what
 * fails them (gate policy, break-glass). One page, two tabs; each tab reuses
 * the component the rest of the console shows.
 */

import { useDocsHref } from '@/context/brand-provider'
import { BookOpen } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SafeExternalLink } from '@/components/safe-external-link'
import { PageHeader } from '@/features/shared'
import { DOCS } from '@/lib/docs-links'
import { useUrlFilter } from '@/hooks/use-url-param'
import { CIPipelinesPanel } from './ci-pipelines-panel'
import { CITrustSettings } from './ci-trust-settings'
import { useTranslation } from '@/context/i18n-provider'

export type CICDTab = 'pipelines' | 'setup'

/** The tab a URL asks for (`?tab=setup`); anything else is Pipelines. */
export function cicdTab(raw: string): CICDTab {
  return raw === 'setup' ? 'setup' : 'pipelines'
}

export function CICDIntegration() {
  const docsHref = useDocsHref()
  const { t } = useTranslation()
  const [tabParam, setTabParam] = useUrlFilter('tab', 'pipelines')
  const tab = cicdTab(tabParam)

  return (
    <div className="space-y-4">
      <PageHeader
        title={t('scans.ci.title', 'CI/CD integration')}
        description={t(
          'scans.ci.description',
          'CI jobs send scan results with their CI provider’s identity, so no secret is stored in CI.'
        )}
      >
        <Button asChild variant="outline" size="sm">
          <SafeExternalLink href={docsHref(DOCS.ci.guide)}>
            <BookOpen className="h-4 w-4" />
            {t('scans.ci.guide', 'CI integration guide')}
          </SafeExternalLink>
        </Button>
      </PageHeader>
      <Tabs value={tab} onValueChange={(v) => setTabParam(v === 'setup' ? 'setup' : '')}>
        <TabsList>
          <TabsTrigger value="pipelines">{t('scans.ci.tab.pipelines', 'Pipelines')}</TabsTrigger>
          <TabsTrigger value="setup">{t('scans.ci.tab.setup', 'Trust and gate')}</TabsTrigger>
        </TabsList>
      </Tabs>
      {tab === 'setup' ? <CITrustSettings embedded /> : <CIPipelinesPanel />}
    </div>
  )
}
