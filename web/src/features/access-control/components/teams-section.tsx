'use client'

import type { ReactNode } from 'react'

import { useState, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { toast } from 'sonner'
import { Plus, Trash2, Eye, Pencil, Loader2, AlertCircle, FolderKey, RefreshCw } from 'lucide-react'
import { useSWRConfig } from 'swr'
import {
  useGroups,
  useCreateGroup,
  useDeleteGroup,
  type Group,
  generateSlug,
} from '@/features/access-control'
import { GroupDetailSheet } from '@/features/access-control/components/group-detail-sheet'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, useCanMutate, usePermissions } from '@/lib/permissions'
import { setTeamAccess, useTeamPresetTemplates } from '../api/use-team-access'
import { EMPTY_TEAM_ACCESS, TeamAccessFields, type TeamAccessValue } from './team-access-fields'
import { confirmName } from '@/lib/confirm-name'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

interface SectionProps {
  /**
   * Renders the page header with this section's actions (its Create button),
   * so the page keeps one header and one set of tabs while each section keeps
   * its own dialogs and state.
   */
  header: (actions: ReactNode) => ReactNode
}

/** The Teams tab of /settings/teams (moved from its own page; content unchanged). */
export function TeamsSection({ header }: SectionProps) {
  const { t } = useTranslation()
  const { mutate } = useSWRConfig()

  // API Hooks
  const { groups, isLoading, isError, mutate: mutateGroups } = useGroups()
  const { createGroup, isCreating } = useCreateGroup()

  // UI State
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [groupToDelete, setGroupToDelete] = useState<Group | null>(null)
  const [createForm, setCreateForm] = useState({
    name: '',
    description: '',
  })
  const [createAccess, setCreateAccess] = useState<TeamAccessValue>(EMPTY_TEAM_ACCESS)
  // The Access section follows the route that sets it, so a person who cannot
  // set access is not offered it.
  const canSetAccess = useCanMutate('PUT /api/v1/groups/{groupId}/access')
  const { isOwner } = usePermissions()
  const { templates: presetTemplates, isLoading: presetsLoading } = useTeamPresetTemplates({
    skip: !createDialogOpen || !canSetAccess,
  })

  // Delete hook - need to pass groupId
  const { deleteGroup, isDeleting } = useDeleteGroup(groupToDelete?.id || null)

  // Refresh data
  const refreshData = useCallback(() => {
    mutateGroups()
  }, [mutateGroups])

  // Table columns
  const columns: ColumnDef<Group>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.teams.col.team', 'Team')} />
      ),
      cell: ({ row }) => (
        <div className="min-w-0">
          <p className="font-medium">{row.original.name}</p>
          {row.original.description && (
            <p className="text-muted-foreground text-xs line-clamp-1">{row.original.description}</p>
          )}
        </div>
      ),
    },
    {
      accessorKey: 'member_count',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.teams.col.members', 'Members')} />
      ),
      cell: ({ row }) => (
        <span className="text-sm tabular-nums">{row.original.member_count ?? 0}</span>
      ),
    },
    {
      accessorKey: 'asset_count',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.teams.col.assets', 'Assets')} />
      ),
      cell: ({ row }) => (
        <span className="text-sm tabular-nums">{row.original.asset_count ?? 0}</span>
      ),
    },
    {
      accessorKey: 'created_at',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.teams.col.created', 'Created')} />
      ),
      cell: ({ row }) => (
        <span className="text-muted-foreground text-sm">{formatDate(row.original.created_at)}</span>
      ),
    },
    {
      id: 'actions',
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => {
        const group = row.original

        return (
          <DataTableRowActions
            actions={[
              {
                label: t('org.teams.viewDetails', 'View details'),
                icon: Eye,
                onClick: () => setSelectedGroupId(group.id),
              },
              {
                label: t('org.teams.editTeam', 'Edit team'),
                icon: Pencil,
                route: 'PUT /api/v1/groups/{groupId}',
                onClick: () => setSelectedGroupId(group.id),
              },
              {
                label: t('org.teams.deleteTeam', 'Delete team'),
                icon: Trash2,
                destructive: true,
                separatorBefore: true,
                // Owner only on the API (RequireOwner), so admins do not see it.
                route: 'DELETE /api/v1/groups/{groupId}',
                onClick: () => {
                  setGroupToDelete(group)
                  setDeleteDialogOpen(true)
                },
              },
            ]}
          />
        )
      },
    },
  ]

  // Actions
  const handleCreateGroup = async () => {
    if (!createForm.name) {
      toast.error(t('org.teams.nameRequired', 'Enter a team name'))
      return
    }

    try {
      const created = await createGroup({
        slug: generateSlug(createForm.name),
        name: createForm.name,
        description: createForm.description || undefined,
        group_type: 'team', // Default type for data scoping groups
      })
      toast.success(t('org.teams.created', 'Team "{name}" created', { name: createForm.name }))
      setCreateDialogOpen(false)
      setCreateForm({ name: '', description: '' })
      refreshData()
      // The team exists even if its access cannot be set: say so and leave the
      // rest to the team's Access tab.
      const createdId = (created as unknown as { id?: string } | undefined)?.id
      if (createdId && (createAccess.presets.length > 0 || createAccess.scopeMode !== 'specific')) {
        try {
          await setTeamAccess(createdId, {
            presets: createAccess.presets,
            scope_mode: createAccess.scopeMode,
          })
        } catch (accessError) {
          toast.error(
            getErrorMessage(
              accessError,
              t(
                'org.teams.accessFailed',
                'The team was created but its access was not saved. Set it on the team.'
              )
            )
          )
        }
      }
      setCreateAccess(EMPTY_TEAM_ACCESS)
    } catch (error) {
      toast.error(getErrorMessage(error, t('org.teams.createFailed', 'Failed to create team')))
    }
  }

  const handleDeleteGroup = async () => {
    if (!groupToDelete) return

    try {
      await deleteGroup()
      toast.success(t('org.teams.deleted', 'Team "{name}" deleted', { name: groupToDelete.name }))
      setDeleteDialogOpen(false)
      setGroupToDelete(null)
      // Invalidate all group-related caches
      mutate(
        (key: string) => typeof key === 'string' && key.startsWith('/api/v1/groups'),
        undefined,
        { revalidate: true }
      )
      refreshData()
    } catch (error) {
      toast.error(getErrorMessage(error, t('org.teams.deleteFailed', 'Failed to delete team')))
    }
  }

  return (
    <>
      {header(
        <>
          <Can route="POST /api/v1/groups" mode="disable">
            <Button size="sm" onClick={() => setCreateDialogOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('org.teams.createTeam', 'Create team')}
            </Button>
          </Can>
        </>
      )}

      {isError && !isLoading ? (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>{t('org.teams.loadFailedTitle', 'Failed to load teams')}</AlertTitle>
          <AlertDescription>
            <p>{t('org.teams.loadFailedBody', 'The team list could not be loaded.')}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={refreshData}>
              <RefreshCw className="me-2 h-4 w-4" />
              {t('common.retry', 'Retry')}
            </Button>
          </AlertDescription>
        </Alert>
      ) : (
        <>
          <div>
            {isLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-9 w-full max-w-sm" />
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : groups.length === 0 ? (
              <EmptyState
                icon={FolderKey}
                title={t('org.teams.emptyTitle', 'No teams yet')}
                description={t(
                  'org.teams.emptyBody',
                  'Create a team to group users and scope their access to assets.'
                )}
                action={
                  <Can route="POST /api/v1/groups">
                    <Button size="sm" onClick={() => setCreateDialogOpen(true)}>
                      <Plus className="me-2 h-4 w-4" />
                      {t('org.teams.createTeam', 'Create team')}
                    </Button>
                  </Can>
                }
              />
            ) : (
              <DataTable
                columns={columns}
                data={groups}
                getRowId={(g) => g.id}
                searchPlaceholder={t('org.teams.searchPlaceholder', 'Search teams…')}
                onRowClick={(g) => setSelectedGroupId(g.id)}
                showColumnToggle={false}
                emptyMessage={t('org.teams.noMatch', 'No teams match your search')}
              />
            )}
          </div>

          {/* Members in no team see nothing (owner decision D2); there is
              no per-organization "see everything" switch. */}
          <p className="text-sm text-muted-foreground" data-testid="no-team-access-note">
            {t(
              'org.teams.noTeamNote',
              'Members who are in no team see no assets or findings until you add them to a team or grant them an asset. Owners, admins and roles with full data access see everything.'
            )}
          </p>
        </>
      )}

      {/* Group Detail Sheet */}
      <GroupDetailSheet
        groupId={selectedGroupId}
        open={!!selectedGroupId}
        onOpenChange={(open) => !open && setSelectedGroupId(null)}
        onUpdate={refreshData}
      />

      {/* Create Group Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{t('org.teams.createTeam', 'Create team')}</DialogTitle>
            <DialogDescription>
              {t(
                'org.teams.createDesc',
                'Create a new team to organize users and control access to assets.'
              )}
            </DialogDescription>
          </DialogHeader>

          <DialogBody>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="group-name">{t('org.teams.teamName', 'Team name')}</Label>
                <Input
                  id="group-name"
                  placeholder={t('org.teams.teamNamePlaceholder', 'e.g., Security team, DevOps')}
                  value={createForm.name}
                  onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="group-description">
                  {t('org.teams.descLabel', 'Description (optional)')}
                </Label>
                <Textarea
                  id="group-description"
                  placeholder={t(
                    'org.teams.descPlaceholder',
                    'Describe the purpose of this team...'
                  )}
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  rows={3}
                />
              </div>

              {canSetAccess && (
                <div className="space-y-2 border-t pt-4">
                  <h3 className="text-sm font-semibold">{t('org.teamAccess.title', 'Access')}</h3>
                  <TeamAccessFields
                    idPrefix="create-team"
                    templates={presetTemplates}
                    loading={presetsLoading}
                    value={createAccess}
                    onChange={setCreateAccess}
                    canSetAllAssets={isOwner()}
                    disabled={isCreating}
                  />
                </div>
              )}
            </div>
          </DialogBody>

          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreateGroup} disabled={isCreating || !createForm.name}>
              {isCreating ? (
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
              ) : (
                <Plus className="me-2 h-4 w-4" />
              )}
              {t('org.teams.createTeam', 'Create team')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={(open) => {
          setDeleteDialogOpen(open)
          if (!open) setGroupToDelete(null)
        }}
        destructive
        title={t('confirm.team.deleteTitle', 'Delete the team "{name}"?', {
          name: groupToDelete?.name ?? '',
        })}
        desc={t(
          'confirm.team.deleteDesc',
          'Members lose the access this team gives them, including to assets the team owns. This cannot be undone.'
        )}
        confirmText={
          <>
            {isDeleting ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <Trash2 className="me-2 h-4 w-4" />
            )}
            {t('confirm.team.delete', 'Delete team')}
          </>
        }
        isLoading={isDeleting}
        typeToConfirm={
          groupToDelete ? confirmName(groupToDelete.name, groupToDelete.id) : undefined
        }
        handleConfirm={handleDeleteGroup}
      />
    </>
  )
}
