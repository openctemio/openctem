'use client'

/**
 * CI/CD integration (api RFC-051): the pipelines that scan your repositories
 * from GitHub Actions and GitLab CI, their runs and repository coverage, and
 * the setup that decides which pipelines may send results (trust) and what
 * fails them (gate policy, break-glass). One page, two tabs; each tab reuses
 * the component the rest of the console shows.
 */

import { BookOpen } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SafeExternalLink } from '@/components/safe-external-link'
import { PageHeader } from '@/features/shared'
import { CI_GITHUB_GUIDE_URL, CI_GITLAB_GUIDE_URL } from '@/config/help-links'
import { useUrlFilter } from '@/hooks/use-url-param'
import { CIPipelinesPanel } from './ci-pipelines-panel'
import { CITrustSettings } from './ci-trust-settings'

export type CICDTab = 'pipelines' | 'setup'

/** The tab a URL asks for (`?tab=setup`); anything else is Pipelines. */
export function cicdTab(raw: string): CICDTab {
  return raw === 'setup' ? 'setup' : 'pipelines'
}

export function CICDIntegration() {
  const [tabParam, setTabParam] = useUrlFilter('tab', 'pipelines')
  const tab = cicdTab(tabParam)

  return (
    <div className="space-y-4">
      <PageHeader
        title="CI/CD integration"
        description="Scan every repository in its own pipeline: GitHub Actions and GitLab CI jobs send their results with the identity their CI provider gives them, no stored secret, and the platform decides which builds fail."
      >
        <Button asChild variant="outline" size="sm">
          <SafeExternalLink href={CI_GITHUB_GUIDE_URL}>
            <BookOpen className="h-4 w-4" />
            GitHub Actions guide
          </SafeExternalLink>
        </Button>
        <Button asChild variant="outline" size="sm">
          <SafeExternalLink href={CI_GITLAB_GUIDE_URL}>
            <BookOpen className="h-4 w-4" />
            GitLab CI guide
          </SafeExternalLink>
        </Button>
      </PageHeader>
      <Tabs value={tab} onValueChange={(v) => setTabParam(v === 'setup' ? 'setup' : '')}>
        <TabsList>
          <TabsTrigger value="pipelines">Pipelines</TabsTrigger>
          <TabsTrigger value="setup">Trust and gate</TabsTrigger>
        </TabsList>
      </Tabs>
      {tab === 'setup' ? <CITrustSettings embedded /> : <CIPipelinesPanel />}
    </div>
  )
}
