'use client'

/**
 * CI/CD integration (api RFC-051): the pipelines that scan your repositories
 * from any supported CI system, their runs and repository coverage, and
 * then the setup: Connections (which CI jobs may send results, and whether
 * they do), Gate (what fails a pipeline) and Pull request feedback.
 * Break-glass lives on Runs, next to the run it unblocks. One tab row; each
 * tab reuses the component the rest of the console shows.
 */

import { useDocsHref } from '@/context/brand-provider'
import { BookOpen } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SafeExternalLink } from '@/components/safe-external-link'
import { PageHeader, PageStack } from '@/features/shared'
import { DOCS } from '@/lib/docs-links'
import { useEffect } from 'react'
import { replaceUrlSearch, useUrlFilter } from '@/hooks/use-url-param'
import { CIPipelinesPanel } from './ci-pipelines-panel'
import { CIConnections } from './ci-connections'
import { CIGateSettings } from './ci-gate-settings'
import { CIPRFeedback } from './ci-pr-feedback'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import { CISetupEntry } from './ci-setup-wizard'

export type CICDTab = 'pipelines' | 'runs' | 'coverage' | 'connections' | 'gate' | 'feedback'

/** The tabs a `?tab=` value names (the lists use `?view=`). */
const SETTING_TABS = ['connections', 'gate', 'feedback'] as const

/**
 * Where a link that predates the Connections / Gate / Pull request feedback
 * tabs lands: `?tab=setup` (the old single Settings tab) and its
 * `?section=` anchors. Server alerts, e-mails, the GitHub App callback and
 * bookmarks still carry them.
 */
export const LEGACY_SETUP_SECTIONS: Record<string, { tab: CICDTab; extra?: [string, string] }> = {
  '': { tab: 'connections' },
  trust: { tab: 'connections' },
  refused: { tab: 'connections', extra: ['refused', '1'] },
  gate: { tab: 'gate' },
  feedback: { tab: 'feedback' },
  'break-glass': { tab: 'runs', extra: ['section', 'break-glass'] },
}

/**
 * The address an old `?tab=setup[&section=]` link becomes, or null when the
 * address is current. Other parameters (`org`, a run) are kept.
 */
export function canonicalCICDSearch(search: string): string | null {
  const params = new URLSearchParams(search)
  const tab = params.get('tab') ?? ''
  if (tab !== 'setup') return null
  const target = LEGACY_SETUP_SECTIONS[params.get('section') ?? ''] ?? { tab: 'connections' }
  params.delete('tab')
  params.delete('section')
  if (target.tab === 'runs') params.set('view', 'runs')
  else params.set('tab', target.tab)
  if (target.extra) params.set(target.extra[0], target.extra[1])
  return params.toString()
}

/**
 * The tab a URL asks for. `?tab=connections|gate|feedback` are the setup
 * tabs (`?tab=setup` is an old link: Connections, or its `?section=`);
 * otherwise `?view=` picks Pipelines, Runs or Coverage.
 */
export function cicdTab(tabRaw: string, viewRaw = '', sectionRaw = ''): CICDTab {
  if ((SETTING_TABS as readonly string[]).includes(tabRaw)) return tabRaw as CICDTab
  if (tabRaw === 'setup') return (LEGACY_SETUP_SECTIONS[sectionRaw] ?? { tab: 'connections' }).tab
  return viewRaw === 'runs' || viewRaw === 'coverage' ? viewRaw : 'pipelines'
}

export function CICDIntegration() {
  const docsHref = useDocsHref()
  const { t } = useTranslation()
  const [tabParam, setTabParam] = useUrlFilter('tab', '')
  const [viewParam, setViewParam] = useUrlFilter('view', '')
  const [sectionParam] = useUrlFilter('section', '')
  const tab = cicdTab(tabParam, viewParam, sectionParam)
  // An old link is rewritten in place to the current address, so a reload
  // or a copied link carries the new one.
  useEffect(() => {
    const next = canonicalCICDSearch(window.location.search)
    if (next !== null) replaceUrlSearch(new URLSearchParams(next))
  }, [tabParam, sectionParam])
  const { can } = usePermissions()
  // The way in for a new pipeline sits in the header, on every tab.
  const canWrite = can(Permission.CIWrite)
  // One tab row (research/249 R21): pipelines, runs and coverage are lists of
  // different rows, so they are tabs beside the setup tabs, not a second row.
  const changeTab = (next: string) => {
    if ((SETTING_TABS as readonly string[]).includes(next)) {
      setViewParam('')
      setTabParam(next)
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
          <TabsTrigger value="connections">
            {t('scans.ci.tab.connections', 'Connections')}
          </TabsTrigger>
          <TabsTrigger value="gate">{t('scans.ci.tab.gate', 'Gate')}</TabsTrigger>
          <TabsTrigger value="feedback">
            {t('scans.ci.feedback.tab', 'Pull request feedback')}
          </TabsTrigger>
        </TabsList>
        {/* The open tab's panel only: each trigger points at its panel. */}
        <TabsContent value={tab}>
          {tab === 'connections' ? (
            <CIConnections />
          ) : tab === 'gate' ? (
            <CIGateSettings />
          ) : tab === 'feedback' ? (
            <CIPRFeedback canWrite={canWrite} />
          ) : (
            <CIPipelinesPanel />
          )}
        </TabsContent>
      </Tabs>
    </PageStack>
  )
}
