'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Ban, CircleCheck, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useListParams } from '@/hooks/use-list-params'
import { DataTable, ErrorState, ListToolbar, PageHeader, PageStack } from '@/features/shared'
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
  const list = useListParams({ defaultPageSize: 25, filters: { state: 'all' } })
  const state = list.filters.state === 'blocked' ? 'blocked' : 'all'
  const { data, error, isLoading, mutate } = useMcpClients(
    list.searchTerm,
    state === 'blocked' ? true : null,
    list.page,
    list.perPage
  )
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

  const columns = useMemo<ColumnDef<AdminMcpClient>[]>(
    () => [
      {
        id: 'application',
        header: t('admin.systemAiApplicationsPage.application', 'Application'),
        cell: ({ row }) => {
          const c = row.original
          return (
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                {/* Applications that name themselves (a metadata document or a
                            dynamic registration) are identified by where they live: the
                            name is whatever the application chose to say. */}
                <span className="font-medium break-all">
                  {c.kind === 'organization' ? c.name : c.host || c.name}
                </span>
                <Badge variant={c.kind === 'dynamic' ? 'outline' : 'secondary'}>
                  {t(KIND_KEY[c.kind])}
                </Badge>
                {c.blocked && (
                  <Badge variant="destructive">
                    {t('admin.systemAiApplicationsPage.blocked', 'Blocked')}
                  </Badge>
                )}
              </div>
              {c.kind !== 'organization' && (
                <p className="text-muted-foreground text-xs break-words">
                  {c.host
                    ? t(
                        'admin.systemAiApplicationsPage.declaresItselfAs',
                        'Declares itself as {name}',
                        { name: c.name }
                      )
                    : t(
                        'admin.systemAiApplicationsPage.nameChosenByApplication',
                        'Name chosen by the application'
                      )}
                </p>
              )}
              <p className="text-muted-foreground font-mono text-xs break-all">{c.client_id}</p>
              <p className="text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 text-xs">
                <span>
                  {t(
                    'admin.systemAiApplicationsPage.connections',
                    '{count, plural, one {# active connection} other {# active connections}}',
                    { count: c.active_connections }
                  )}
                </span>
                <span>
                  {t(
                    'admin.systemAiApplicationsPage.organizations',
                    '{count, plural, one {# organization} other {# organizations}}',
                    { count: c.organizations }
                  )}
                </span>
                <span>
                  {t('admin.systemAiApplicationsPage.firstSeen', 'First seen {date}', {
                    date: formatDateSafe(c.created_at),
                  })}
                </span>
                <span>
                  {c.last_used_at
                    ? t('admin.systemAiApplicationsPage.lastUsed', 'Last used {when}', {
                        when: formatRelative(c.last_used_at),
                      })
                    : t('admin.systemAiApplicationsPage.neverUsed', 'Never used')}
                </span>
              </p>
            </div>
          )
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => {
          const c = row.original
          return (
            <>
              {canBlock && (
                <Button
                  variant={c.blocked ? 'outline' : 'destructive'}
                  size="sm"
                  className="shrink-0"
                  disabled={busy === c.id}
                  // Blocking cuts every organization off and unblocking lets the
                  // application connect again everywhere, so both ask first.
                  onClick={() => setPendingBlock(c)}
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
            </>
          )
        },
      },
    ],
    [t, busy, canBlock]
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.systemAiApplicationsPage.aiApplications', 'AI applications')}
          description={t(
            'admin.systemAiApplicationsPage.mcpClientsThatConnectTo',
            'MCP clients that connect to this deployment, with their usage. Block one to stop it everywhere.'
          )}
        />
        <ListToolbar
          search={{
            value: list.q,
            onChange: list.setSearch,
            placeholder: t('admin.systemAiApplicationsPage.search', 'Search host or name…'),
            label: t('admin.systemAiApplicationsPage.searchLabel', 'Search AI applications'),
          }}
          start={
            <Tabs value={state} onValueChange={(v) => list.setFilter('state', v)}>
              <TabsList>
                <TabsTrigger value="all">
                  {t('admin.systemAiApplicationsPage.filterAll', 'All')}
                </TabsTrigger>
                <TabsTrigger value="blocked">
                  {t('admin.systemAiApplicationsPage.blocked', 'Blocked')}
                </TabsTrigger>
              </TabsList>
            </Tabs>
          }
        />
        {error ? (
          <ErrorState
            title={t('admin.systemAiApplicationsPage.aiApplications', 'AI applications')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            getRowId={(c) => c.id}
            isLoading={isLoading}
            showSearch={false}
            showColumnToggle={false}
            showSelectionCount={false}
            emptyMessage={
              list.searchTerm || state === 'blocked'
                ? t(
                    'admin.systemAiApplicationsPage.noMatch',
                    'No AI application matches this search'
                  )
                : t(
                    'admin.systemAiApplicationsPage.applicationsAppearAfterTheirFirst',
                    'Applications appear after someone approves them for the first time.'
                  )
            }
            manualPagination
            pageCount={data?.total_pages ?? 1}
            rowCount={data?.total ?? 0}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
          />
        )}
        <ConfirmDialog
          open={pendingBlock !== null}
          onOpenChange={(o) => !o && setPendingBlock(null)}
          destructive={!pendingBlock?.blocked}
          title={
            pendingBlock?.blocked
              ? t('confirm.mcpClient.unblockTitle', 'Unblock {name} everywhere?', {
                  name: pendingBlock.name,
                })
              : t('confirm.mcpClient.blockTitle', 'Block {name} everywhere?', {
                  name: pendingBlock?.name ?? '',
                })
          }
          desc={
            pendingBlock?.blocked
              ? t(
                  'confirm.mcpClient.unblockDesc',
                  'Every organization on this deployment can authorize this application again. Connections that were cut off are not restored; each member connects again.'
                )
              : t(
                  'confirm.mcpClient.blockDesc',
                  'Every organization on this deployment loses the use of this application at once: its tokens stop working and it cannot be authorized again until you unblock it.'
                )
          }
          confirmText={
            pendingBlock?.blocked
              ? t('confirm.mcpClient.unblockButton', 'Unblock application')
              : t('confirm.mcpClient.blockButton', 'Block application')
          }
          isLoading={busy !== null}
          handleConfirm={() => (pendingBlock ? toggle(pendingBlock) : undefined)}
        />
      </PageStack>
    </Main>
  )
}
