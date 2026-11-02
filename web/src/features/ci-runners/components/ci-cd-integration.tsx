'use client'

/**
 * CI/CD integration (api RFC-051): the pipelines that scan your repositories
 * from any supported CI system, their runs and repository coverage, and
 * the setup that decides which pipelines may send results (trust) and what
 * fails them (gate policy, break-glass) under Settings. One tab row; each tab
 * reuses the component the rest of the console shows.
 */

import { useDocsHref } from '@/context/brand-provider'
import { BookOpen } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SafeExternalLink } from '@/components/safe-external-link'
import { PageHeader, PageStack } from '@/features/shared'
import { DOCS } from '@/lib/docs-links'
import { useUrlFilter } from '@/hooks/use-url-param'
import { CIPipelinesPanel } from './ci-pipelines-panel'
import { CITrustSettings } from './ci-trust-settings'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import { CISetupEntry } from './ci-setup-wizard'

export type CICDTab = 'pipelines' | 'runs' | 'coverage' | 'setup'

/**
 * The tab a URL asks for. `?tab=setup` is Settings; otherwise `?view=`
 * picks Pipelines, Runs or Coverage (the parameters existing links use).
 */
export function cicdTab(tabRaw: string, viewRaw = ''): CICDTab {
  if (tabRaw === 'setup') return 'setup'
  return viewRaw === 'runs' || viewRaw === 'coverage' ? viewRaw : 'pipelines'
}

export function CICDIntegration() {
  const docsHref = useDocsHref()
  const { t } = useTranslation()
  const [tabParam, setTabParam] = useUrlFilter('tab', '')
  const [viewParam, setViewParam] = useUrlFilter('view', '')
  const tab = cicdTab(tabParam, viewParam)
  const { can } = usePermissions()
  // The way in for a new pipeline sits in the header, on every tab.
  const canWrite = can(Permission.CIWrite)
  // One tab row (research/249 R21): pipelines, runs and coverage are lists of
  // different rows, so they are tabs beside Settings, not a second row.
  const changeTab = (next: string) => {
    if (next === 'setup') {
      setViewParam('')
      setTabParam('setup')
    } else {
      setTabParam('')
      setViewParam(next === 'runs' || next === 'coverage' ? next : '')
    }
  }

  return (
    <PageStack>
      <PageHeader
        title={t('scans.ci.title', 'CI/CD integration')}
        description={t(
          'scans.ci.description',
          'CI jobs send scan results with their CI provider’s identity, so no secret is stored in CI.'
        )}
      >
        {canWrite && <CISetupEntry canWrite />}
        <Button asChild variant="outline" size="sm">
          <SafeExternalLink href={docsHref(DOCS.ci.guide)}>
            <BookOpen className="h-4 w-4" />
            {t('scans.ci.guide', 'CI integration guide')}
          </SafeExternalLink>
        </Button>
      </PageHeader>
      <Tabs value={tab} onValueChange={changeTab}>
        <TabsList aria-label={t('scans.ci.tabsLabel', 'CI/CD sections')}>
          <TabsTrigger value="pipelines">{t('scans.ci.view.pipelines', 'Pipelines')}</TabsTrigger>
          <TabsTrigger value="runs">{t('scans.ci.view.runs', 'Runs')}</TabsTrigger>
          <TabsTrigger value="coverage">{t('scans.ci.view.coverage', 'Coverage')}</TabsTrigger>
          <TabsTrigger value="setup">{t('scans.ci.tab.settings', 'Settings')}</TabsTrigger>
        </TabsList>
        {/* The open tab's panel only: each trigger points at its panel. */}
        <TabsContent value={tab}>
          {tab === 'setup' ? <CITrustSettings embedded /> : <CIPipelinesPanel />}
        </TabsContent>
      </Tabs>
    </PageStack>
  )
}
