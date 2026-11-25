'use client'

import { useTranslation } from '@/context/i18n-provider'
import {
  revokeMyConnection,
  scopeMyConnection,
  useMyConnections,
} from '@/features/mcp-oauth/api/connections'
import { ConnectionsList } from '@/features/mcp-oauth/components/connections-list'

/**
 * The AI applications (MCP clients) the signed-in person connected in this
 * organization (RFC-062 §12). Each one acts as the person and sees only what
 * they can see; disconnecting ends it at once. The page header (the
 * /settings/me layout) says what the list is, so the list stands alone in the
 * settings column, with no card around it.
 */
export default function ConnectedAppsPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useMyConnections()
  return (
    <ConnectionsList
      connections={data?.data}
      isLoading={isLoading}
      error={error}
      onRetry={() => void mutate()}
      onRevoke={revokeMyConnection}
      onScope={scopeMyConnection}
      emptyTitle={t('mcp.connections.emptyTitle', 'No connected applications')}
      emptyDescription={t(
        'mcp.myConnections.empty',
        'When you connect an AI assistant to {product}, it appears here.'
      )}
    />
  )
}
