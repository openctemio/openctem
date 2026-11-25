'use client'

import * as React from 'react'
import { useState, useMemo, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  Plus,
  KeyRound,
  AlertCircle,
  Pencil,
  Trash2,
  GitBranch,
  Cloud,
  Key,
  Lock,
  Terminal,
  AlertTriangle,
} from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'

import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { RefreshButton, TableSkeleton } from '@/components/list-page-parts'

import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  ErrorState,
  PageHeader,
  PageStack,
} from '@/features/shared'
import { AddCredentialDialog } from './add-credential-dialog'
import { EditCredentialDialog } from './edit-credential-dialog'
import { Can, Permission } from '@/lib/permissions'

// Note: Using CredentialsWrite/CredentialsRead permissions for secret store.
// The backend uses scans:credentials:* but the frontend maps to findings:credentials:*.
import {
  useSecretStoreCredentials,
  useDeleteSecretStoreCredential,
  invalidateSecretStoreCache,
} from '@/lib/api/secret-store-hooks'
import type { SecretStoreCredential, CredentialType } from '@/lib/api/secret-store-types'
import {
  CREDENTIAL_TYPE_DISPLAY_NAMES,
  isCredentialExpired,
  isCredentialExpiringSoon,
} from '@/lib/api/secret-store-types'
import { useTranslation } from '@/context/i18n-provider'
import { formatRelative } from '@/lib/format-date'

const CREDENTIAL_TYPE_ICONS: Record<CredentialType, React.ElementType> = {
  api_key: Key,
  basic_auth: Lock,
  bearer_token: GitBranch,
  ssh_key: Terminal,
  aws_role: Cloud,
  gcp_service_account: Cloud,
  azure_service_principal: Cloud,
  github_app: GitBranch,
  gitlab_token: GitBranch,
}

function CredentialStatusBadge({ credential }: { credential: SecretStoreCredential }) {
  const { t } = useTranslation()
  if (isCredentialExpired(credential)) {
    return (
      <Badge variant="destructive" className="gap-1">
        <AlertCircle className="h-3 w-3" />
        {t('scans.credentials.status.expired', 'Expired')}
      </Badge>
    )
  }
  if (isCredentialExpiringSoon(credential)) {
    return (
      <Badge variant="secondary" className="gap-1">
        <AlertTriangle className="h-3 w-3" />
        {t('scans.credentials.status.expiringSoon', 'Expiring soon')}
      </Badge>
    )
  }
  return <Badge variant="outline">{t('scans.credentials.status.active', 'Active')}</Badge>
}

export function SecretStoreSection() {
  const { t, locale } = useTranslation()
  // Dialog states
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)

  // Selected credential for dialogs
  const [selectedCredential, setSelectedCredential] = useState<SecretStoreCredential | null>(null)

  // API data
  const { data: credentialsData, error, isLoading, mutate } = useSecretStoreCredentials()
  const credentials: SecretStoreCredential[] = React.useMemo(
    () => credentialsData?.items ?? [],
    [credentialsData?.items]
  )

  // Delete mutation
  const { trigger: deleteCredential, isMutating: isDeleting } = useDeleteSecretStoreCredential(
    selectedCredential?.id || ''
  )

  // Handlers
  const handleRefresh = useCallback(async () => {
    await invalidateSecretStoreCache()
    await mutate()
    toast.success(t('scans.credentials.refreshed', 'Credentials refreshed'))
  }, [mutate, t])

  const handleEditCredential = useCallback((credential: SecretStoreCredential) => {
    setSelectedCredential(credential)
    setEditDialogOpen(true)
  }, [])

  const handleDeleteClick = useCallback((credential: SecretStoreCredential) => {
    setSelectedCredential(credential)
    setDeleteDialogOpen(true)
  }, [])

  const handleDeleteConfirm = useCallback(async () => {
    if (!selectedCredential) return
    try {
      await deleteCredential()
      toast.success(
        t('scans.credentials.deleted', 'Credential "{name}" deleted', {
          name: selectedCredential.name,
        })
      )
      await invalidateSecretStoreCache()
      setDeleteDialogOpen(false)
      setSelectedCredential(null)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('scans.credentials.deleteFailed', 'Failed to delete credential'))
      )
    }
  }, [selectedCredential, deleteCredential, t])

  const columns = useMemo<ColumnDef<SecretStoreCredential>[]>(
    () => [
      {
        id: 'name',
        accessorFn: (c) => `${c.name} ${c.description ?? ''}`,
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scans.credentials.col.credential', 'Credential')}
          />
        ),
        cell: ({ row }) => {
          const credential = row.original
          const Icon = CREDENTIAL_TYPE_ICONS[credential.credential_type] || Key
          return (
            <div className="flex min-w-0 items-center gap-3">
              <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
              <div className="min-w-0">
                <div className="truncate font-medium">{credential.name}</div>
                {credential.description && (
                  <p
                    className="max-w-xs truncate text-sm text-muted-foreground"
                    title={credential.description}
                  >
                    {credential.description}
                  </p>
                )}
              </div>
            </div>
          )
        },
      },
      {
        id: 'type',
        accessorFn: (c) => CREDENTIAL_TYPE_DISPLAY_NAMES[c.credential_type],
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.credentials.col.type', 'Type')} />
        ),
        cell: ({ getValue }) => <Badge variant="outline">{getValue<string>()}</Badge>,
      },
      {
        id: 'status',
        enableSorting: false,
        header: t('scans.credentials.col.status', 'Status'),
        cell: ({ row }) => <CredentialStatusBadge credential={row.original} />,
      },
      {
        id: 'last_used',
        accessorFn: (c) => c.last_used_at ?? '',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scans.credentials.col.lastUsed', 'Last used')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatRelative(
              row.original.last_used_at,
              t('scans.credentials.neverUsed', 'Never used'),
              locale
            )}
          </span>
        ),
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => (
          <Can permission={[Permission.SecretStoreWrite, Permission.SecretStoreDelete]}>
            <DataTableRowActions
              title={row.original.name}
              label={t('common.rowActions.actionsFor', 'Actions for {name}', {
                name: row.original.name,
              })}
              actions={[
                {
                  label: t('scans.credentials.row.edit', 'Edit'),
                  icon: Pencil,
                  onClick: () => handleEditCredential(row.original),
                  permission: Permission.SecretStoreWrite,
                },
                {
                  label: t('scans.credentials.row.delete', 'Delete'),
                  icon: Trash2,
                  onClick: () => handleDeleteClick(row.original),
                  destructive: true,
                  separatorBefore: true,
                  permission: Permission.SecretStoreDelete,
                },
              ]}
            />
          </Can>
        ),
      },
    ],
    [handleEditCredential, handleDeleteClick, t, locale]
  )

  let body: React.ReactNode
  if (error) {
    body = (
      <ErrorState
        title={t('scans.credentials.errorTitle', 'credentials')}
        error={error}
        onRetry={handleRefresh}
      />
    )
  } else if (isLoading) {
    body = <TableSkeleton rows={3} />
  } else if (credentials.length === 0) {
    body = (
      <EmptyState
        icon={KeyRound}
        title={t('scans.credentials.empty.title', 'No credentials')}
        description={t(
          'scans.credentials.empty.description',
          'Add credentials to authenticate with template sources.'
        )}
      />
    )
  } else {
    body = (
      <DataTable
        columns={columns}
        data={credentials}
        getRowId={(c) => c.id}
        searchPlaceholder={t('scans.credentials.search', 'Search credentials…')}
        toolbarEnd={<RefreshButton onClick={handleRefresh} loading={isLoading} />}
        emptyMessage={t('scans.credentials.noMatch', 'No credentials match your search')}
      />
    )
  }

  return (
    <PageStack>
      <PageHeader
        title={t('settings.item.source-credentials', 'Source credentials')}
        description={t(
          'settings.page.sourceCredentials.description',
          'Encrypted credentials that template sources use to authenticate (Git tokens, cloud keys and more).'
        )}
      >
        <Can permission={Permission.SecretStoreWrite}>
          <Button size="sm" onClick={() => setAddDialogOpen(true)}>
            <Plus className="h-4 w-4" />
            {t('scans.credentials.add', 'Add credential')}
          </Button>
        </Can>
      </PageHeader>

      {body}

      {/* Dialogs */}
      <AddCredentialDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        onSuccess={handleRefresh}
      />

      {selectedCredential && (
        <EditCredentialDialog
          open={editDialogOpen}
          onOpenChange={setEditDialogOpen}
          credential={selectedCredential}
          onSuccess={handleRefresh}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t('confirm.credential.deleteTitle', 'Delete the credential {name}?', {
          name: selectedCredential?.name ?? '',
        })}
        desc={t(
          'confirm.credential.deleteDesc',
          'Template sources that use it can no longer authenticate. The secret cannot be recovered. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        isLoading={isDeleting}
        typeToConfirm={selectedCredential?.name}
        handleConfirm={handleDeleteConfirm}
      />
    </PageStack>
  )
}
