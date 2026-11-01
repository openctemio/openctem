'use client'

import { useEffect, useMemo, useRef } from 'react'
import { AlertTriangle } from 'lucide-react'

import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { AIActivityCard } from '@/features/ai-triage/components/ai-activity-card'
import { AIAgentsSection } from '@/features/ai-triage/components/ai-agents-section'
import { AIAutoTriageCard } from '@/features/ai-triage/components/ai-auto-triage-card'
import { AIConsentCard } from '@/features/ai-triage/components/ai-consent-card'
import { AIKnowledgeSection } from '@/features/ai-triage/components/ai-knowledge-section'
import { AIMaskingSection } from '@/features/ai-triage/components/ai-masking-section'
import { AISourceCard } from '@/features/ai-triage/components/ai-source-card'
import { AIStatusStrip, type AISettingsTab } from '@/features/ai-triage/components/ai-status-strip'
import { AIUsageCard } from '@/features/ai-triage/components/ai-usage-card'
import { useAIConfig } from '@/features/ai-triage/api/use-ai-triage-api'
import { useAIMasking } from '@/features/ai-triage/api/use-ai-masking'
import { useAISettings } from '@/features/ai-triage/api/use-ai-settings'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'
import { PageHeader, ReadOnlyNotice, PageStack } from '@/features/shared'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Permission, useCanMutate, useHasPermission } from '@/lib/permissions'

/**
 * Settings anchors (settings-nav.ts) link to `#<id>`: open the tab that holds
 * the element so search results still land on it.
 */
const ANCHOR_TAB: Record<string, AISettingsTab> = {
  'ai-triage': 'provider',
  'ai-source': 'provider',
  'ai-auto-triage': 'features',
  'ai-agents': 'features',
  'ai-knowledge': 'knowledge',
  'ai-usage': 'limits',
  'ai-masking': 'limits',
  'ai-activity': 'activity',
}

/**
 * Settings > AI: a status strip, then five tabs (the tab is in the URL).
 * Provider: the organization's consent and where the AI comes from
 * (api docs: architecture/ai-triage.md). Features: automatic triage and the
 * AI agents (architecture/ai-analysis.md). Knowledge: the sources AI agents
 * cite. Limits and data: use against the limit and the masking of what is
 * sent (architecture/ai-context-masking.md). Activity: the latest AI events
 * from the audit log. Each part is its own section component; tabs that read
 * data mount only when open. Until an owner or administrator turns it on, no
 * finding content is sent to an AI provider.
 */
export default function AISettingsPage() {
  const { t } = useTranslation()
  const canEdit = useCanMutate('PUT /api/v1/organization/settings/ai')
  const canReadKnowledge = useHasPermission(Permission.AIKnowledgeRead)
  const { moduleIds } = useTenantModules()
  // The audit log is a module: without it there is no activity to show.
  const canReadAudit = useHasPermission(Permission.AuditRead) && moduleIds.includes('audit')
  const settings = useAISettings(true)
  // Usage is live data: read it on mount, not from the bootstrap's copy.
  const config = useAIConfig({ revalidateIfStale: true, dedupingInterval: 2000 })
  const masking = useAIMasking(true)
  const [urlTab, setUrlTab] = useUrlFilter('tab', 'provider')

  const available = useMemo<AISettingsTab[]>(
    () => [
      'provider',
      'features',
      ...(canReadKnowledge ? (['knowledge'] as const) : []),
      'limits',
      ...(canReadAudit ? (['activity'] as const) : []),
    ],
    [canReadKnowledge, canReadAudit]
  )
  const tab: AISettingsTab = available.includes(urlTab as AISettingsTab)
    ? (urlTab as AISettingsTab)
    : 'provider'

  // The hash names where a settings search result points. Follow it once on
  // arrival: the ref stops the effect from pulling the user back to the anchor
  // tab after they switch tabs. A tab that is not available yet (permissions
  // still loading) leaves the ref unset, so the effect retries when it is.
  const hashHandled = useRef(false)
  useEffect(() => {
    if (hashHandled.current) return
    const target = ANCHOR_TAB[window.location.hash.slice(1)]
    if (!target) {
      hashHandled.current = true
      return
    }
    if (!available.includes(target)) return
    hashHandled.current = true
    if (target !== tab) setUrlTab(target)
  }, [available, tab, setUrlTab])

  const platformMissing = config.data?.reason === 'platform_not_configured'
  const enabled = settings.data?.enabled === true

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('settings.ai.title', 'AI')}
          description={t(
            'settings.ai.description',
            'Decide whether this organization’s findings may be sent to an AI provider for triage.'
          )}
        />

        {!canEdit && (
          <ReadOnlyNotice
            reason={t(
              'settings.ai.readOnly',
              'Only owners and administrators can change this setting.'
            )}
          />
        )}

        <AIStatusStrip
          settings={settings.data}
          config={config.data}
          masking={masking.data}
          loading={settings.isLoading}
          tab={tab}
          onTab={setUrlTab}
        />

        <Tabs value={tab} onValueChange={setUrlTab}>
          <TabsList>
            <TabsTrigger value="provider">{t('settings.ai.tabs.provider', 'Provider')}</TabsTrigger>
            <TabsTrigger value="features">{t('settings.ai.tabs.features', 'Features')}</TabsTrigger>
            {available.includes('knowledge') && (
              <TabsTrigger value="knowledge">
                {t('settings.ai.tabs.knowledge', 'Knowledge')}
              </TabsTrigger>
            )}
            <TabsTrigger value="limits">
              {t('settings.ai.tabs.limits', 'Limits and data')}
            </TabsTrigger>
            {available.includes('activity') && (
              <TabsTrigger value="activity">
                {t('settings.ai.tabs.activity', 'Activity')}
              </TabsTrigger>
            )}
          </TabsList>

          <TabsContent value="provider">
            <PageStack>
              {platformMissing && (
                <Alert role="status">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>
                    {t('settings.ai.platformMissingTitle', 'No AI provider is set up yet')}
                  </AlertTitle>
                  <AlertDescription>
                    {t(
                      'settings.ai.platformMissing',
                      'A platform administrator sets up the AI provider in the console (System > AI provider). You can turn AI triage on now; it works once a provider is set up.'
                    )}
                  </AlertDescription>
                </Alert>
              )}
              <AIConsentCard
                settings={settings.data}
                isLoading={settings.isLoading}
                error={settings.error}
                canEdit={canEdit}
                onSaved={async (next) => {
                  await settings.mutate(next, { revalidate: false })
                  await config.mutate()
                }}
              />
              {settings.data && (
                <AISourceCard
                  settings={settings.data}
                  canEdit={canEdit}
                  onSaved={async (next) => {
                    await settings.mutate(next, { revalidate: false })
                    await config.mutate()
                  }}
                />
              )}
            </PageStack>
          </TabsContent>

          <TabsContent value="features">
            <PageStack>
              <AIAutoTriageCard canEdit={canEdit} aiEnabled={enabled} />
              <AIAgentsSection />
            </PageStack>
          </TabsContent>

          {available.includes('knowledge') && (
            <TabsContent value="knowledge">
              <AIKnowledgeSection />
            </TabsContent>
          )}

          <TabsContent value="limits">
            <PageStack>
              <AIUsageCard config={config.data} />
              <AIMaskingSection canEdit={canEdit} />
            </PageStack>
          </TabsContent>

          {available.includes('activity') && (
            <TabsContent value="activity">
              <AIActivityCard />
            </TabsContent>
          )}
        </Tabs>
      </PageStack>
    </Main>
  )
}
