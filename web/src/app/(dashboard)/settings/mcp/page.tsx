'use client'

import { useState } from 'react'
import { KeyRound } from 'lucide-react'

import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useAccessRequests } from '@/features/mcp-oauth/api/access-requests'
import {
  revokeOrgConnection,
  scopeOrgConnection,
  useMcpPolicy,
  useOrgConnections,
} from '@/features/mcp-oauth/api/connections'
import { AccessRequestsCard } from '@/features/mcp-oauth/components/access-requests-card'
import { ApprovedPublishersCard } from '@/features/mcp-oauth/components/approved-publishers-card'
import { ConnectPanel } from '@/features/mcp-oauth/components/connect-panel'
import { ConnectionsList } from '@/features/mcp-oauth/components/connections-list'
import { McpPolicyCard } from '@/features/mcp-oauth/components/mcp-policy-card'
import { McpStatusStrip } from '@/features/mcp-oauth/components/mcp-status-strip'
import { OrgClientsCard } from '@/features/mcp-oauth/components/org-clients-card'
import { UnverifiedAppsCard } from '@/features/mcp-oauth/components/unverified-apps-card'
import { PageHeader, PageStack } from '@/features/shared'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Can, Permission, useCanMutate, useHasPermission } from '@/lib/permissions'

type TabId = 'connect' | 'applications' | 'connections' | 'policy'

/**
 * AI assistants (MCP): how to connect (everyone), which applications the
 * organization approves and the members' requests (settings readers), every
 * connection (owners and administrators) and the policy (settings readers;
 * editing needs settings:write and a recent sign-in). The tab is in the URL.
 */
export default function MCPSettingsPage() {
  const { t } = useTranslation()
  const [urlTab, setUrlTab] = useUrlFilter('tab', 'connect')
  const [keyDialogOpen, setKeyDialogOpen] = useState(false)
  const canWriteKeys = useHasPermission(Permission.ApiKeysWrite)
  const { currentTenant } = useTenant()
  const isOrgAdmin = currentTenant?.role === 'owner' || currentTenant?.role === 'admin'
  const canReadPolicy = useHasPermission(Permission.SettingsRead)
  const canWritePolicy = useCanMutate('PUT /api/v1/mcp-access/settings')
  const policy = useMcpPolicy(canReadPolicy)
  const requests = useAccessRequests(canReadPolicy)
  const orgConnections = useOrgConnections(isOrgAdmin)

  const available: TabId[] = [
    'connect',
    ...(canReadPolicy ? (['applications'] as const) : []),
    ...(isOrgAdmin ? (['connections'] as const) : []),
    ...(canReadPolicy ? (['policy'] as const) : []),
  ]
  const tab: TabId = available.includes(urlTab as TabId) ? (urlTab as TabId) : 'connect'

  const setTab = setUrlTab

  const pendingCount = requests.data?.data.length ?? 0
  const connect = (
    <ConnectPanel
      keyDialogOpen={keyDialogOpen}
      onKeyDialogOpenChange={setKeyDialogOpen}
      canWriteKeys={canWriteKeys}
    />
  )
  const policyLoading = (
    <Card>
      <CardHeader>
        <Skeleton className="h-5 w-1/3" />
      </CardHeader>
      <CardContent className="space-y-3">
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-2/3" />
      </CardContent>
    </Card>
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('mcp.page.title', 'AI assistants (MCP)')}
          description={t(
            'mcp.page.description',
            'Let AI assistants work with this organization’s data, as the person who connects them and never beyond what that person can see.'
          )}
        >
          <Can route="POST /api/v1/api-keys">
            <Button size="sm" variant="outline" onClick={() => setKeyDialogOpen(true)}>
              <KeyRound className="me-2 h-4 w-4" aria-hidden />
              {t('mcp.key.generate', 'Generate key')}
            </Button>
          </Can>
        </PageHeader>

        {policy.data && <McpStatusStrip policy={policy.data} />}

        {available.length === 1 ? (
          connect
        ) : (
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="connect">{t('mcp.tabs.connect', 'Connect')}</TabsTrigger>
              {available.includes('applications') && (
                <TabsTrigger value="applications">
                  {t('mcp.tabs.applications', 'Applications')}
                  {pendingCount > 0 && <TabsCount value={pendingCount} />}
                </TabsTrigger>
              )}
              {available.includes('connections') && (
                <TabsTrigger value="connections">
                  {t('mcp.tabs.connections', 'Connections')}
                </TabsTrigger>
              )}
              {available.includes('policy') && (
                <TabsTrigger value="policy">{t('mcp.tabs.policy', 'Policy')}</TabsTrigger>
              )}
            </TabsList>

            <TabsContent value="connect">{connect}</TabsContent>

            {available.includes('applications') && (
              <TabsContent value="applications">
                <PageStack>
                  <AccessRequestsCard canEdit={canWritePolicy} />
                  {policy.data ? (
                    <ApprovedPublishersCard policy={policy.data} canEdit={canWritePolicy} />
                  ) : (
                    policyLoading
                  )}
                  <OrgClientsCard canEdit={canWritePolicy} />
                  {policy.data && (
                    <UnverifiedAppsCard policy={policy.data} canEdit={canWritePolicy} />
                  )}
                </PageStack>
              </TabsContent>
            )}

            {available.includes('connections') && (
              <TabsContent value="connections">
                <Card>
                  <CardHeader>
                    <CardTitle>{t('mcp.connections.orgTitle', 'Connected applications')}</CardTitle>
                    <CardDescription>
                      {t(
                        'mcp.connections.orgDescription',
                        'Every AI application a member connected. Disconnecting one ends its access at once.'
                      )}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ConnectionsList
                      connections={orgConnections.data?.data}
                      isLoading={orgConnections.isLoading}
                      showUser
                      onRevoke={revokeOrgConnection}
                      onScope={scopeOrgConnection}
                      emptyTitle={t('mcp.connections.emptyTitle', 'No connected applications')}
                      emptyDescription={t(
                        'mcp.connections.orgEmpty',
                        'When a member connects an AI assistant, it appears here.'
                      )}
                    />
                  </CardContent>
                </Card>
              </TabsContent>
            )}

            {available.includes('policy') && (
              <TabsContent value="policy">
                {policy.data ? (
                  <McpPolicyCard policy={policy.data} canEdit={canWritePolicy} />
                ) : (
                  policyLoading
                )}
              </TabsContent>
            )}
          </Tabs>
        )}
      </PageStack>
    </Main>
  )
}
