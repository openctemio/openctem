'use client'

import { useState, useMemo, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { csrfFetch, del } from '@/lib/api/client'
import { useRouter } from 'next/navigation'
import { Main } from '@/components/layout'
import {
  PageHeader,
  EmptyState,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  StackedCell,
  RelativeTime,
  ErrorState,
  MetricStrip,
  type MetricStripItem,
  type RowAction,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { toast } from 'sonner'
import { Can } from '@/lib/permissions'
import {
  Plus,
  Link2,
  RefreshCw,
  Eye,
  Pencil,
  Trash2,
  CheckCircle,
  XCircle,
  AlertCircle,
  Loader2,
  GitBranch,
  ExternalLink,
  Clock,
} from 'lucide-react'
import {
  AddConnectionDialog,
  EditConnectionDialog,
  SyncRepositoriesDialog,
  ProviderIcon,
} from '@/features/scm-connections'
import {
  useSCMConnections,
  invalidateSCMConnectionsCache,
} from '@/features/repositories/hooks/use-repositories'
import type { SCMConnection } from '@/features/repositories/types/repository.types'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'

// Only a problem (error) is coloured; the other states stay neutral.
const STATUS_CONFIG: Record<
  string,
  {
    label: string
    variant: 'default' | 'secondary' | 'destructive' | 'outline'
    icon: React.ReactNode
  }
> = {
  connected: {
    label: 'Connected',
    variant: 'default',
    icon: <CheckCircle className="h-3.5 w-3.5" />,
  },
  disconnected: {
    label: 'Disconnected',
    variant: 'secondary',
    icon: <XCircle className="h-3.5 w-3.5" />,
  },
  error: {
    label: 'Error',
    variant: 'destructive',
    icon: <AlertCircle className="h-3.5 w-3.5" />,
  },
  pending: {
    label: 'Pending',
    variant: 'outline',
    icon: <Clock className="h-3.5 w-3.5" />,
  },
}

const PROVIDER_LABELS: Record<string, string> = {
  github: 'GitHub',
  gitlab: 'GitLab',
  bitbucket: 'Bitbucket',
  azure_devops: 'Azure DevOps',
}

export default function SCMConnectionsPage() {
  const { t } = useTranslation()
  const router = useRouter()
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [syncDialogOpen, setSyncDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [selectedConnection, setSelectedConnection] = useState<SCMConnection | null>(null)
  const [actionInProgress, setActionInProgress] = useState<string | null>(null)

  // Fetch SCM connections
  const { data: connectionsData, error, isLoading, mutate } = useSCMConnections()

  // Handle the API response format - useSCMConnections returns SCMConnection[] directly
  const connections = useMemo(() => {
    if (!connectionsData) return []
    // Handle both array format and { data: [...] } format
    return Array.isArray(connectionsData) ? connectionsData : []
  }, [connectionsData])

  // Calculate stats - SCMConnection uses repositoryCount (camelCase)
  const stats = useMemo(() => {
    const total = connections.length
    const connected = connections.filter((c) => c.status === 'connected').length
    const errorCount = connections.filter((c) => c.status === 'error').length
    const totalRepos = connections.reduce((sum, c) => sum + (c.repositoryCount || 0), 0)
    return { total, connected, error: errorCount, totalRepos }
  }, [connections])

  const handleRefresh = useCallback(async () => {
    setActionInProgress('refresh')
    try {
      await invalidateSCMConnectionsCache()
      await mutate()
      toast.success(t('scmIntegration.toast.refreshed', 'Connections refreshed'))
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('scmIntegration.toast.refreshFailed', 'Failed to refresh connections')
        )
      )
    } finally {
      setActionInProgress(null)
    }
  }, [mutate, t])

  const handleTestConnection = useCallback(
    async (connection: SCMConnection) => {
      setActionInProgress(connection.id)
      try {
        const response = await csrfFetch(`/api/v1/integrations/${connection.id}/test`, {
          method: 'POST',
        })
        if (!response.ok) throw new Error('Test failed')
        const result = await response.json()
        if (result.status === 'connected') {
          toast.success(
            t('scmIntegration.toast.testOk', 'Connection "{name}" is working', {
              name: connection.name,
            })
          )
        } else {
          toast.error(
            result.status_message || t('scmIntegration.toast.testFailed', 'Connection test failed')
          )
        }
        await mutate()
      } catch (err) {
        toast.error(
          getErrorMessage(err, t('scmIntegration.toast.testError', 'Failed to test connection'))
        )
      } finally {
        setActionInProgress(null)
      }
    },
    [mutate, t]
  )

  const handleDelete = useCallback(async () => {
    if (!selectedConnection) return
    setActionInProgress(selectedConnection.id)
    try {
      // apiClient path: a STEP_UP_REQUIRED answer opens the re-authentication dialog and retries.
      await del(`/api/v1/integrations/${selectedConnection.id}`)
      toast.success(
        t('scmIntegration.toast.deleted', 'Connection "{name}" deleted', {
          name: selectedConnection.name,
        })
      )
      await invalidateSCMConnectionsCache()
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('scmIntegration.toast.deleteFailed', 'Failed to delete connection'))
      )
    } finally {
      setDeleteDialogOpen(false)
      setSelectedConnection(null)
      setActionInProgress(null)
    }
  }, [selectedConnection, mutate, t])

  const handleEditClick = (connection: SCMConnection) => {
    setSelectedConnection(connection)
    setEditDialogOpen(true)
  }

  const handleSyncClick = (connection: SCMConnection) => {
    setSelectedConnection(connection)
    setSyncDialogOpen(true)
  }

  const handleDeleteClick = (connection: SCMConnection) => {
    setSelectedConnection(connection)
    setDeleteDialogOpen(true)
  }

  const columns = useMemo<ColumnDef<SCMConnection>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scmIntegration.col.connection', 'Connection')}
          />
        ),
        cell: ({ row }) => {
          const connection = row.original
          return (
            <div className="flex items-center gap-3">
              <ProviderIcon provider={connection.provider} className="h-5 w-5 shrink-0" />
              <StackedCell
                primary={connection.name}
                secondary={
                  <span className="truncate max-w-[200px] inline-block align-bottom">
                    {connection.baseUrl}
                  </span>
                }
              />
            </div>
          )
        },
      },
      {
        accessorKey: 'provider',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scmIntegration.col.provider', 'Provider')}
          />
        ),
        cell: ({ row }) => (
          <Badge variant="outline" className="text-xs">
            {PROVIDER_LABELS[row.original.provider] || row.original.provider}
          </Badge>
        ),
      },
      {
        accessorKey: 'scmOrganization',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scmIntegration.col.organization', 'Organization')}
          />
        ),
        cell: ({ row }) => <span className="text-sm">{row.original.scmOrganization || '-'}</span>,
      },
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scmIntegration.col.status', 'Status')} />
        ),
        cell: ({ row }) => {
          const connection = row.original
          const statusKey = STATUS_CONFIG[connection.status] ? connection.status : 'pending'
          const statusConfig = STATUS_CONFIG[statusKey]
          return (
            <>
              <Badge variant={statusConfig.variant} className="gap-1">
                {statusConfig.icon}
                {t(`scmIntegration.status.${statusKey}`, statusConfig.label)}
              </Badge>
              {connection.errorMessage && connection.status === 'error' && (
                <p className="mt-1 max-w-[200px] truncate text-xs text-destructive">
                  {connection.errorMessage}
                </p>
              )}
            </>
          )
        },
      },
      {
        id: 'repositories',
        header: t('scmIntegration.col.repositories', 'Repositories'),
        enableSorting: false,
        cell: ({ row }) => {
          const connection = row.original
          return (
            <Button
              variant="link"
              size="sm"
              className="h-auto p-0"
              onClick={() => handleSyncClick(connection)}
            >
              {t('scmIntegration.repoCount', '{count} repos', {
                count: connection.repositoryCount || 0,
              })}
              <ExternalLink className="ms-1 h-3 w-3" />
            </Button>
          )
        },
      },
      {
        accessorKey: 'lastValidatedAt',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scmIntegration.col.lastVerified', 'Last verified')}
          />
        ),
        cell: ({ row }) => <RelativeTime date={row.original.lastValidatedAt} />,
      },
      {
        id: 'actions',
        header: '',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const connection = row.original
          const actions: RowAction[] = [
            {
              label: t('scmIntegration.actions.sync', 'Sync repositories'),
              icon: GitBranch,
              onClick: () => handleSyncClick(connection),
              route: 'POST /api/v1/integrations/{id}/sync',
            },
            {
              label: t('scmIntegration.actions.test', 'Test connection'),
              icon: Eye,
              onClick: () => handleTestConnection(connection),
              route: 'POST /api/v1/integrations/{id}/test',
            },
            {
              label: t('scmIntegration.actions.edit', 'Edit'),
              icon: Pencil,
              onClick: () => handleEditClick(connection),
              route: 'PUT /api/v1/integrations/{id}',
            },
            {
              label: t('scmIntegration.actions.delete', 'Delete'),
              icon: Trash2,
              onClick: () => handleDeleteClick(connection),
              destructive: true,
              separatorBefore: true,
              route: 'DELETE /api/v1/integrations/{id}',
            },
          ]
          return <DataTableRowActions actions={actions} />
        },
      },
    ],
    [handleTestConnection, t]
  )

  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('scmIntegration.metrics.connections', 'Connections'),
      value: stats.total,
    },
    {
      key: 'connected',
      label: t('scmIntegration.metrics.connected', 'Connected'),
      value: stats.connected,
    },
    {
      key: 'error',
      label: t('scmIntegration.metrics.errors', 'Errors'),
      value: stats.error,
      tone: 'danger',
    },
    {
      key: 'repos',
      label: t('scmIntegration.metrics.repositories', 'Repositories'),
      value: stats.totalRepos,
    },
  ]

  return (
    <>
      <Main>
        <PageHeader
          title={t('scmIntegration.page.title', 'SCM connections')}
          description={t(
            'scmIntegration.page.description',
            'Connect GitHub, GitLab, Bitbucket or Azure DevOps, then import repositories for scanning.'
          )}
        >
          <Button
            variant="outline"
            size="sm"
            onClick={() => router.push('/assets?types=repository')}
          >
            <GitBranch className="me-2 h-4 w-4" />
            {t('scmIntegration.page.repositories', 'Repositories')}
          </Button>
          <Can route="POST /api/v1/integrations">
            <Button size="sm" onClick={() => setAddDialogOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('scmIntegration.page.addConnection', 'Add connection')}
            </Button>
          </Can>
        </PageHeader>

        {error ? (
          <div className="mt-5">
            <ErrorState
              title={t('scmIntegration.page.errorTitle', 'SCM connections')}
              error={error}
              onRetry={() => void mutate()}
            />
          </div>
        ) : (
          <>
            <MetricStrip className="mt-5" loading={isLoading} items={metrics} />

            <div className="mt-5">
              {isLoading ? (
                <div className="space-y-3">
                  <Skeleton className="h-9 w-full max-w-sm" />
                  <Skeleton className="h-48 w-full" />
                </div>
              ) : connections.length === 0 ? (
                <EmptyState
                  icon={Link2}
                  title={t('scmIntegration.page.emptyTitle', 'No SCM connections')}
                  description={t(
                    'scmIntegration.page.emptyDescription',
                    'Connect your GitHub, GitLab, Bitbucket, or Azure DevOps account to import and scan repositories.'
                  )}
                  action={
                    <Can route="POST /api/v1/integrations">
                      <Button size="sm" onClick={() => setAddDialogOpen(true)}>
                        <Plus className="me-2 h-4 w-4" />
                        {t('scmIntegration.page.addConnection', 'Add connection')}
                      </Button>
                    </Can>
                  }
                />
              ) : (
                <DataTable
                  columns={columns}
                  data={connections}
                  getRowId={(c) => c.id}
                  searchPlaceholder={t(
                    'scmIntegration.page.searchPlaceholder',
                    'Search connections...'
                  )}
                  showSelectionCount={false}
                  toolbarEnd={
                    <Button
                      variant="outline"
                      size="icon"
                      className="h-9 w-9"
                      aria-label={t('scmIntegration.page.refresh', 'Refresh')}
                      title={t('scmIntegration.page.refresh', 'Refresh')}
                      onClick={handleRefresh}
                      disabled={actionInProgress === 'refresh'}
                    >
                      {actionInProgress === 'refresh' ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <RefreshCw className="h-4 w-4" />
                      )}
                    </Button>
                  }
                  emptyMessage={t(
                    'scmIntegration.page.noMatch',
                    'No connections match your search'
                  )}
                />
              )}
            </div>
          </>
        )}
      </Main>

      {/* Dialogs */}
      <AddConnectionDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        onSuccess={async () => {
          await invalidateSCMConnectionsCache()
          await mutate()
        }}
      />

      {selectedConnection && (
        <>
          <EditConnectionDialog
            open={editDialogOpen}
            onOpenChange={setEditDialogOpen}
            connection={selectedConnection}
            onSuccess={async () => {
              await invalidateSCMConnectionsCache()
              await mutate()
              setSelectedConnection(null)
            }}
          />

          <SyncRepositoriesDialog
            open={syncDialogOpen}
            onOpenChange={setSyncDialogOpen}
            connection={selectedConnection}
            onSuccess={async () => {
              await mutate()
            }}
          />
        </>
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t('confirm.scm.deleteTitle', 'Delete the SCM connection "{name}"?', {
          name: selectedConnection?.name ?? '',
        })}
        desc={t(
          'confirm.scm.deleteDesc',
          'Imported repositories stay, but they can no longer be synced through this connection. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        handleConfirm={() => void handleDelete()}
      />
    </>
  )
}
