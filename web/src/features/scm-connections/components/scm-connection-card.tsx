'use client'

import { IntegrationHealth } from '@/features/integrations/components/integration-health'
import { useState } from 'react'
import {
  MoreHorizontal,
  Trash2,
  RefreshCw,
  ExternalLink,
  Clock,
  Download,
  Settings,
} from 'lucide-react'
import { toast } from 'sonner'
import { connectionProblem } from '@/features/integrations/lib/connection-status'

import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ActionMenu } from '@/components/ui/action-menu'
import { confirmName } from '@/lib/confirm-name'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn, sanitizeExternalUrl } from '@/lib/utils'
import { getErrorMessage } from '@/lib/api/error-handler'

import { ProviderIcon, SCM_PROVIDER_COLORS } from './provider-icon'
import { SyncRepositoriesDialog } from './sync-repositories-dialog'
import { EditConnectionDialog } from './edit-connection-dialog'
import type { Integration } from '@/features/integrations'
import { SCM_PROVIDER_LABELS } from '@/features/assets/types/asset.types'
import {
  useDeleteIntegrationApi,
  useTestIntegrationApi,
  invalidateSCMIntegrationsCache,
} from '@/features/integrations'
import { useTranslation } from '@/context/i18n-provider'
import { formatDate, formatDateTime } from '@/lib/app-locale'

interface SCMConnectionCardProps {
  connection: Integration
  repositoryCount?: number
  onSelect?: () => void
  selected?: boolean
}

export function SCMConnectionCard({
  connection,
  repositoryCount = 0,
  onSelect,
  selected = false,
}: SCMConnectionCardProps) {
  const { t } = useTranslation()
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [syncDialogOpen, setSyncDialogOpen] = useState(false)
  const [editDialogOpen, setEditDialogOpen] = useState(false)

  const { trigger: deleteConnection, isMutating: isDeleting } = useDeleteIntegrationApi(
    connection.id
  )
  const { trigger: validateConnection, isMutating: isValidating } = useTestIntegrationApi(
    connection.id
  )

  const handleDelete = async () => {
    try {
      await deleteConnection()
      toast.success(
        t('scmIntegration.toast.deleted', 'Connection "{name}" deleted', { name: connection.name })
      )
      await invalidateSCMIntegrationsCache()
      setDeleteDialogOpen(false)
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('scmIntegration.toast.deleteFailed', 'Failed to delete connection')
        )
      )
    }
  }

  const handleValidate = async () => {
    try {
      const result = await validateConnection()
      await invalidateSCMIntegrationsCache()

      // Check if the test actually succeeded by looking at the returned status
      if (result && result.status === 'connected') {
        toast.success(
          t('scmConnections.card.validated', 'Connection "{name}" validated.', {
            name: connection.name,
          })
        )
      } else if (result && result.status === 'error') {
        toast.error(
          connectionProblem(
            result,
            t,
            t('scmIntegration.toast.testFailedNamed', 'Could not connect to {name}.', {
              name: connection.name,
            })
          ).message
        )
      } else {
        toast.warning(
          t('scmConnections.card.status', 'Connection "{name}" status: {status}', {
            name: connection.name,
            status: result?.status || t('scmConnections.card.statusUnknown', 'unknown'),
          })
        )
      }
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('scmConnections.card.validationFailed', 'Validation failed'))
      )
    }
  }

  return (
    <>
      <Card
        className={cn(
          'transition-all cursor-pointer hover:border-primary/50',
          selected && 'border-primary ring-1 ring-primary',
          connection.status === 'error' && 'border-destructive/40'
        )}
        onClick={onSelect}
      >
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div
                className={cn(
                  'flex h-10 w-10 items-center justify-center rounded-lg',
                  SCM_PROVIDER_COLORS[connection.provider]
                )}
              >
                <ProviderIcon provider={connection.provider} className="h-5 w-5" />
              </div>
              <div>
                <CardTitle className="text-base">{connection.name}</CardTitle>
                <CardDescription className="text-xs">
                  {SCM_PROVIDER_LABELS[connection.provider as keyof typeof SCM_PROVIDER_LABELS] ||
                    connection.provider}
                  {connection.scm_extension?.scm_organization &&
                    ` / ${connection.scm_extension.scm_organization}`}
                </CardDescription>
              </div>
            </div>
            <ActionMenu
              title={connection.name}
              label={t('common.rowActions.actionsFor', 'Actions for {name}', {
                name: connection.name,
              })}
              items={[
                {
                  id: 'test',
                  label: t('scmIntegration.actions.test', 'Test connection'),
                  icon: RefreshCw,
                  disabledReason: isValidating
                    ? t('scmIntegration.actions.testing', 'Testing...')
                    : undefined,
                  onSelect: () => void handleValidate(),
                },
                {
                  id: 'sync',
                  label: t('scmIntegration.actions.sync', 'Sync repositories'),
                  icon: Download,
                  onSelect: () => setSyncDialogOpen(true),
                },
                {
                  id: 'edit',
                  label: t('scmIntegration.actions.editConnection', 'Edit connection'),
                  icon: Settings,
                  onSelect: () => setEditDialogOpen(true),
                },
                ...(connection.base_url
                  ? [
                      {
                        id: 'open',
                        label: t('scmIntegration.actions.openInBrowser', 'Open in browser'),
                        icon: ExternalLink,
                        onSelect: () => {
                          // Build the URL to open - include organization if available
                          let url = connection.base_url
                          const org = connection.scm_extension?.scm_organization
                          if (org) {
                            // Every provider's URL structure is base/organization.
                            if (
                              connection.provider === 'github' ||
                              connection.provider === 'gitlab' ||
                              connection.provider === 'bitbucket' ||
                              connection.provider === 'azure_devops'
                            ) {
                              url = `${connection.base_url}/${org}`
                            }
                          }
                          if (url)
                            window.open(sanitizeExternalUrl(url), '_blank', 'noopener,noreferrer')
                        },
                      },
                    ]
                  : []),
                {
                  id: 'delete',
                  label: t('confirm.delete', 'Delete'),
                  icon: Trash2,
                  destructive: true,
                  onSelect: () => setDeleteDialogOpen(true),
                },
              ]}
              trigger={
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={t('common.rowActions.actionsFor', 'Actions for {name}', {
                    name: connection.name,
                  })}
                >
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              }
            />
          </div>
        </CardHeader>
        <CardContent className="pt-2">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-4">
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <IntegrationHealth status={connection.status} />
                  </TooltipTrigger>
                  {connection.status === 'error' && (
                    <TooltipContent className="max-w-xs">
                      <p>
                        {
                          connectionProblem(
                            connection,
                            t,
                            t(
                              'scmIntegration.toast.testFailedNamed',
                              'Could not connect to {name}.',
                              {
                                name: connection.name,
                              }
                            )
                          ).message
                        }
                      </p>
                    </TooltipContent>
                  )}
                </Tooltip>
              </TooltipProvider>
              <Badge variant="secondary" className="text-xs">
                {t('scmIntegration.repoCount', '{count, plural, one {# repo} other {# repos}}', {
                  count: repositoryCount,
                })}
              </Badge>
            </div>
            {connection.last_sync_at && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      {formatDate(new Date(connection.last_sync_at))}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>
                    {t('scmConnections.card.lastValidated', 'Last validated: {date}', {
                      date: formatDateTime(new Date(connection.last_sync_at)),
                    })}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
          </div>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t('confirm.scm.deleteTitle', 'Delete the SCM connection "{name}"?', {
          name: connection.name,
        })}
        desc={
          <>
            {t(
              'confirm.scm.deleteDesc',
              'Imported repositories stay, but they can no longer be synced through this connection. This cannot be undone.'
            )}
            {repositoryCount > 0 && (
              <>
                {' '}
                {t('confirm.scm.deleteRepoCount', '{count} repositories use this connection.', {
                  count: repositoryCount,
                })}
              </>
            )}
          </>
        }
        confirmText={t('confirm.scm.deleteBtn')}
        destructive
        typeToConfirm={confirmName(connection.name, connection.id)}
        isLoading={isDeleting}
        handleConfirm={handleDelete}
      />

      <SyncRepositoriesDialog
        open={syncDialogOpen}
        onOpenChange={setSyncDialogOpen}
        connection={connection}
      />

      <EditConnectionDialog
        open={editDialogOpen}
        onOpenChange={setEditDialogOpen}
        connection={connection}
      />
    </>
  )
}
