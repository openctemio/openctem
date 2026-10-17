'use client'

import { useTranslation } from '@/context/i18n-provider'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { revokeMyConnection, useMyConnections } from '@/features/mcp-oauth/api/connections'
import { ConnectionsList } from '@/features/mcp-oauth/components/connections-list'

/**
 * The AI applications (MCP clients) the signed-in person connected in this
 * organization (RFC-062 §12). Each one acts as the person and sees only what
 * they can see; disconnecting ends it at once.
 */
export default function ConnectedAppsPage() {
  const { t } = useTranslation()
  const { data, isLoading } = useMyConnections()
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('mcp.myConnections.title', 'Your AI applications')}</CardTitle>
        <CardDescription>
          {t(
            'mcp.myConnections.description',
            'Applications you allowed to work with this organization’s data as you. They lose access when you disconnect them or when your own access changes.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ConnectionsList
          connections={data?.data}
          isLoading={isLoading}
          onRevoke={revokeMyConnection}
          emptyTitle={t('mcp.connections.emptyTitle', 'No connected applications')}
          emptyDescription={t(
            'mcp.myConnections.empty',
            'When you connect an AI assistant to {product}, it appears here.'
          )}
        />
      </CardContent>
    </Card>
  )
}
