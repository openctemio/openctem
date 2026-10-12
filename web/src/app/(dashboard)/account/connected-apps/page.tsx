'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { revokeMyConnection, useMyConnections } from '@/features/mcp-oauth/api/connections'
import { ConnectionsList } from '@/features/mcp-oauth/components/connections-list'

/**
 * The AI applications (MCP clients) the signed-in person connected in this
 * organization (RFC-062 §12). Each one acts as the person and sees only what
 * they can see; disconnecting ends it at once.
 */
export default function ConnectedAppsPage() {
  const { data, isLoading } = useMyConnections()
  return (
    <Card>
      <CardHeader>
        <CardTitle>Your AI applications</CardTitle>
        <CardDescription>
          Applications you allowed to read data in this organization as you. They lose access when
          you disconnect them or when your own access changes.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ConnectionsList
          connections={data?.data}
          isLoading={isLoading}
          onRevoke={revokeMyConnection}
          emptyTitle="No connected applications"
          emptyDescription="When you connect an AI assistant to OpenCTEM, it appears here."
        />
      </CardContent>
    </Card>
  )
}
