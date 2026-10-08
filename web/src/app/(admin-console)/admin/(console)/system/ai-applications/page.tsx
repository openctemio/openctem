'use client'

import { useState } from 'react'
import { Ban, Bot, CircleCheck, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import {
  setMcpClientBlocked,
  useMcpClients,
  type AdminMcpClient,
} from '@/features/admin-console/api/use-mcp-clients'
import { adminCan } from '@/features/admin-console/types'
import { formatDateSafe, formatRelative } from '@/lib/format-date'

const KIND_LABEL: Record<AdminMcpClient['kind'], string> = {
  metadata_document: 'Published metadata',
  organization: 'Registered by an organization',
  dynamic: 'Self-registered (unverified)',
}

/**
 * System -> AI applications: every MCP client known to the platform with how
 * many active connections it has and in how many organizations (counts only,
 * RFC-062 §12). Operators block an application everywhere: it can no longer
 * be authorized and its tokens stop working.
 */
export default function AiApplicationsPage() {
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useMcpClients()
  const [busy, setBusy] = useState<string | null>(null)
  const canBlock = adminCan(me.role, 'ops_admin')

  const toggle = async (c: AdminMcpClient) => {
    setBusy(c.id)
    try {
      await setMcpClientBlocked(c.id, !c.blocked)
      toast.success(c.blocked ? `${c.name} unblocked` : `${c.name} blocked everywhere`)
      await mutate()
    } catch {
      toast.error('Could not update the application')
    } finally {
      setBusy(null)
    }
  }

  return (
    <Main>
      <PageHeader
        title="AI applications"
        description="MCP clients that connect to this deployment, with their usage. Block one to stop it everywhere."
      />
      <div className="mt-5">
        {error ? (
          <ErrorState title="AI applications" error={error} onRetry={() => void mutate()} />
        ) : isLoading || !data ? (
          <Skeleton className="h-48 w-full" />
        ) : data.data.length === 0 ? (
          <EmptyState
            icon={Bot}
            title="No AI applications yet"
            description="Applications appear after their first authorization request."
          />
        ) : (
          <Card>
            <CardContent className="p-0">
              <ul className="divide-y">
                {data.data.map((c) => (
                  <li
                    key={c.id}
                    className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium break-words">{c.name}</span>
                        <Badge variant={c.kind === 'dynamic' ? 'outline' : 'secondary'}>
                          {KIND_LABEL[c.kind]}
                        </Badge>
                        {c.blocked && <Badge variant="destructive">Blocked</Badge>}
                      </div>
                      <p className="text-muted-foreground font-mono text-xs break-all">
                        {c.host || c.client_id}
                      </p>
                      <p className="text-muted-foreground text-xs">
                        {c.active_connections} active connection
                        {c.active_connections === 1 ? '' : 's'} in {c.organizations} organization
                        {c.organizations === 1 ? '' : 's'} · first seen{' '}
                        {formatDateSafe(c.created_at)} · last used{' '}
                        {c.last_used_at ? formatRelative(c.last_used_at) : 'never'}
                      </p>
                    </div>
                    {canBlock && (
                      <Button
                        variant={c.blocked ? 'outline' : 'destructive'}
                        size="sm"
                        className="shrink-0"
                        disabled={busy === c.id}
                        onClick={() => void toggle(c)}
                      >
                        {busy === c.id ? (
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
                        ) : c.blocked ? (
                          <CircleCheck className="mr-2 h-4 w-4" aria-hidden />
                        ) : (
                          <Ban className="mr-2 h-4 w-4" aria-hidden />
                        )}
                        {c.blocked ? 'Unblock' : 'Block'}
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </div>
    </Main>
  )
}
