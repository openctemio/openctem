'use client'

import { IntegrationHealth } from '@/features/integrations/components/integration-health'
import { ConnectionNote } from '@/features/integrations/components/connection-note'
import { useState, useMemo, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { csrfFetch, del } from '@/lib/api/client'
import { useRouter } from 'next/navigation'
import { Main } from '@/components/layout'
import { RefreshButton } from '@/components/list-page-parts'
import {
  PageHeader,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  StackedCell,
  RelativeTime,
  type RowAction,
  PageStack,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { confirmName } from '@/lib/confirm-name'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { toast } from 'sonner'
import { connectionProblem } from '@/features/integrations/lib/connection-status'
import { Can } from '@/lib/permissions'
import { Plus, Link2, Eye, Pencil, Trash2, GitBranch, ExternalLink } from 'lucide-react'
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
import {
  IntegrationList,
  integrationStatusGroup,
} from '@/features/integrations/components/integration-list'

// Only a problem (error) is coloured; the other states stay neutral.
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
            connectionProblem(
              result,
              t,
              t('scmIntegration.toast.testFailed', 'Connection test failed')
            ).message
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
        // The row's state: a phone card shows it on its title line. The cell
        // also says why a connection failed, so it keeps room for that reason.
        meta: { kind: 'status', width: 280 },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scmIntegration.col.status', 'Status')} />
        ),
        cell: ({ row }) => {
          const connection = row.original
          return (
            <>
              <IntegrationHealth status={connection.status} />
              <ConnectionNote
                integration={{
                  status: connection.status,
                  status_code: connection.errorCode,
                  status_message: connection.errorMessage,
                }}
                className="mt-1"
              />
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
          return (
            <DataTableRowActions
              title={connection.name}
              label={t('common.rowActions.actionsFor', 'Actions for {name}', {
                name: connection.name,
              })}
              actions={actions}
            />
          )
        },
      },
    ],
    [handleTestConnection, t]
  )

  return (
    <>
      <Main>
        <PageStack>
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
            {/* The create button stays in the header; the empty state only explains. */}
            <Can route="POST /api/v1/integrations">
              <Button size="sm" onClick={() => setAddDialogOpen(true)}>
                <Plus className="me-2 h-4 w-4" />
                {t('scmIntegration.page.addConnection', 'Add connection')}
              </Button>
            </Can>
          </PageHeader>

          <IntegrationList
            rows={connections}
            isLoading={isLoading}
            error={error}
            onRetry={() => void mutate()}
            errorTitle={t('scmIntegration.page.errorTitle', 'SCM connections')}
            groupOf={(c) => integrationStatusGroup(c.status)}
            empty={{
              icon: Link2,
              title: t('scmIntegration.page.emptyTitle', 'No SCM connections'),
              description: t(
                'scmIntegration.page.emptyDescription',
                'Connect your GitHub, GitLab, Bitbucket, or Azure DevOps account to import and scan repositories.'
              ),
            }}
          >
            {(visible) => (
              <DataTable
                columns={columns}
                data={visible}
                getRowId={(c) => c.id}
                searchPlaceholder={t(
                  'scmIntegration.page.searchPlaceholder',
                  'Search connections…'
                )}
                showSelectionCount={false}
                toolbarEnd={
                  <RefreshButton
                    onClick={() => void handleRefresh()}
                    loading={actionInProgress === 'refresh'}
                    label={t('scmIntegration.page.refresh', 'Refresh')}
                  />
                }
                emptyMessage={t('scmIntegration.page.noMatch', 'No connections match your search')}
              />
            )}
          </IntegrationList>
        </PageStack>
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
        confirmText={t('confirm.scm.deleteBtn')}
        destructive
        typeToConfirm={
          selectedConnection
            ? confirmName(selectedConnection.name, selectedConnection.id)
            : undefined
        }
        handleConfirm={() => void handleDelete()}
      />
    </>
  )
}
