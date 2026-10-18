'use client'

import { useState } from 'react'
import { Ban, Bot, CircleCheck, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import {
  setMcpClientBlocked,
  useMcpClients,
  type AdminMcpClient,
} from '@console/features/admin-console/api/use-mcp-clients'
import { adminCan } from '@console/features/admin-console/types'
import { formatDateSafe, formatRelative } from '@/lib/format-date'

const KIND_KEY: Record<AdminMcpClient['kind'], string> = {
  metadata_document: 'admin.aiApplications.kind.metadataDocument',
  organization: 'admin.aiApplications.kind.organization',
  dynamic: 'admin.aiApplications.kind.dynamic',
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
  const [pendingBlock, setPendingBlock] = useState<AdminMcpClient | null>(null)
  const { t } = useTranslation()
  const canBlock = adminCan(me.role, 'ops_admin')

  const toggle = async (c: AdminMcpClient) => {
    setBusy(c.id)
    try {
      await setMcpClientBlocked(c.id, !c.blocked)
      setPendingBlock(null)
      toast.success(
        c.blocked
          ? t('admin.systemAiApplicationsPage.unblocked', '{name} unblocked', { name: c.name })
          : t('admin.systemAiApplicationsPage.blockedEverywhere', '{name} blocked everywhere', {
              name: c.name,
            })
      )
      await mutate()
    } catch {
      toast.error(
        t(
          'admin.systemAiApplicationsPage.couldNotUpdateTheApplication',
          'Could not update the application'
        )
      )
    } finally {
      setBusy(null)
    }
  }

  return (
    <Main>
      <PageHeader
        title={t('admin.systemAiApplicationsPage.aiApplications', 'AI applications')}
        description={t(
          'admin.systemAiApplicationsPage.mcpClientsThatConnectTo',
          'MCP clients that connect to this deployment, with their usage. Block one to stop it everywhere.'
        )}
      />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('admin.systemAiApplicationsPage.aiApplications', 'AI applications')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-48 w-full" />
        ) : data.data.length === 0 ? (
          <EmptyState
            icon={Bot}
            title={t(
              'admin.systemAiApplicationsPage.noAiApplicationsYet',
              'No AI applications yet'
            )}
            description={t(
              'admin.systemAiApplicationsPage.applicationsAppearAfterTheirFirst',
              'Applications appear after their first authorization request.'
            )}
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
                          {t(KIND_KEY[c.kind])}
                        </Badge>
                        {c.blocked && (
                          <Badge variant="destructive">
                            {t('admin.systemAiApplicationsPage.blocked', 'Blocked')}
                          </Badge>
                        )}
                      </div>
                      <p className="text-muted-foreground font-mono text-xs break-all">
                        {c.host || c.client_id}
                      </p>
                      <p className="text-muted-foreground text-xs">
                        {c.active_connections}{' '}
                        {t('admin.systemAiApplicationsPage.activeConnection', 'active connection')}
                        {c.active_connections === 1 ? '' : 's'}{' '}
                        {t('admin.systemAiApplicationsPage.in', 'in')} {c.organizations}{' '}
                        {t('admin.systemAiApplicationsPage.organization', 'organization')}
                        {c.organizations === 1 ? '' : 's'}{' '}
                        {t('admin.systemAiApplicationsPage.firstSeen', '· first seen')}{' '}
                        {formatDateSafe(c.created_at)}{' '}
                        {t('admin.systemAiApplicationsPage.lastUsed', '· last used')}{' '}
                        {c.last_used_at
                          ? formatRelative(c.last_used_at)
                          : t('admin.systemAiApplicationsPage.never', 'never')}
                      </p>
                    </div>
                    {canBlock && (
                      <Button
                        variant={c.blocked ? 'outline' : 'destructive'}
                        size="sm"
                        className="shrink-0"
                        disabled={busy === c.id}
                        // Unblocking is safe at once; blocking cuts every organization off.
                        onClick={() => (c.blocked ? void toggle(c) : setPendingBlock(c))}
                      >
                        {busy === c.id ? (
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
                        ) : c.blocked ? (
                          <CircleCheck className="mr-2 h-4 w-4" aria-hidden />
                        ) : (
                          <Ban className="mr-2 h-4 w-4" aria-hidden />
                        )}
                        {c.blocked
                          ? t('admin.systemAiApplicationsPage.unblock', 'Unblock')
                          : t('admin.systemAiApplicationsPage.block', 'Block')}
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </div>
      <ConfirmDialog
        open={pendingBlock !== null}
        onOpenChange={(o) => !o && setPendingBlock(null)}
        destructive
        title={t('confirm.mcpClient.blockTitle', 'Block {name} everywhere?', {
          name: pendingBlock?.name ?? '',
        })}
        desc={t(
          'confirm.mcpClient.blockDesc',
          'Every organization on this deployment loses the use of this application at once: its tokens stop working and it cannot be authorized again until you unblock it.'
        )}
        confirmText={t('confirm.mcpClient.block', 'Block')}
        isLoading={busy !== null}
        handleConfirm={() => (pendingBlock ? toggle(pendingBlock) : undefined)}
      />
    </Main>
  )
}
