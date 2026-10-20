'use client'

import * as React from 'react'
import { useState, useMemo, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Plus, Settings2, Star, Copy, Pencil, Trash2, Sparkles, ChevronDown } from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'

import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { RefreshButton, TableSkeleton } from '@/components/list-page-parts'

import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  ErrorState,
  PageHeader,
  type RowAction,
} from '@/features/shared'
import { AddScanProfileDialog } from './add-scan-profile-dialog'
import { EditScanProfileDialog } from './edit-scan-profile-dialog'
import { CloneScanProfileDialog } from './clone-scan-profile-dialog'
import { AddPresetDialog } from './add-preset-dialog'
import { Can, Permission, useCanMutate } from '@/lib/permissions'
import {
  useScanProfiles,
  useDeleteScanProfile,
  useSetDefaultScanProfile,
  invalidateScanProfilesCache,
} from '@/lib/api/scan-profile-hooks'
import type { ScanProfile } from '@/lib/api/scan-profile-types'
import { gateSummary } from '../gate-summary'
import { useTranslation } from '@/context/i18n-provider'

export function ScanProfilesSection() {
  const { t } = useTranslation()
  // Dialog states
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [presetDialogOpen, setPresetDialogOpen] = useState(false)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)

  // Selected profile for dialogs
  const [selectedProfile, setSelectedProfile] = useState<ScanProfile | null>(null)

  // API data
  const { data: profilesData, error, isLoading, mutate } = useScanProfiles()
  const profiles: ScanProfile[] = React.useMemo(
    () => profilesData?.items ?? [],
    [profilesData?.items]
  )

  // Delete mutation
  const { trigger: deleteProfile, isMutating: isDeleting } = useDeleteScanProfile(
    selectedProfile?.id || ''
  )

  // Set default mutation
  const { trigger: setDefaultProfile, isMutating: isSettingDefault } = useSetDefaultScanProfile()
  // The default profile is organization-wide: owner/admin only (the API gate).
  const canSetDefault = useCanMutate('POST /api/v1/scan-profiles/{id}/set-default')

  // Handlers
  const handleRefresh = useCallback(async () => {
    await invalidateScanProfilesCache()
    await mutate()
    toast.success(t('scans.profiles.refreshed'))
  }, [mutate])

  const handleEditProfile = useCallback((profile: ScanProfile) => {
    setSelectedProfile(profile)
    setEditDialogOpen(true)
  }, [])

  const handleCloneProfile = useCallback((profile: ScanProfile) => {
    setSelectedProfile(profile)
    setCloneDialogOpen(true)
  }, [])

  const handleDeleteClick = useCallback((profile: ScanProfile) => {
    setSelectedProfile(profile)
    setDeleteDialogOpen(true)
  }, [])

  const handleDeleteConfirm = useCallback(async () => {
    if (!selectedProfile) return
    try {
      await deleteProfile()
      toast.success(t('scans.profiles.deleted', undefined, { name: selectedProfile.name }))
      await invalidateScanProfilesCache()
      setDeleteDialogOpen(false)
      setSelectedProfile(null)
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.profiles.deleteFailed')))
    }
  }, [selectedProfile, deleteProfile])

  const handleSetDefault = useCallback(
    async (profile: ScanProfile) => {
      try {
        await setDefaultProfile(profile.id)
        toast.success(t('scans.profiles.defaultSet', undefined, { name: profile.name }))
        await invalidateScanProfilesCache()
      } catch (err) {
        toast.error(getErrorMessage(err, t('scans.profiles.defaultFailed')))
      }
    },
    [setDefaultProfile]
  )

  const columns = useMemo<ColumnDef<ScanProfile>[]>(
    () => [
      {
        id: 'name',
        accessorFn: (p) => `${p.name} ${p.description ?? ''}`,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.profiles.name')} />
        ),
        cell: ({ row }) => {
          const profile = row.original
          return (
            <div className="min-w-0">
              <div className="flex items-center gap-2 font-medium">
                <span className="truncate">{profile.name}</span>
                {profile.is_default && (
                  <Badge variant="secondary" className="gap-1">
                    <Star className="h-3 w-3 fill-current" />
                    {t('scans.profiles.badge.default')}
                  </Badge>
                )}
                {profile.is_system && (
                  <Badge variant="outline">{t('scans.profiles.badge.system')}</Badge>
                )}
                {profile.rule_sources && profile.rule_sources !== 'both' && (
                  <Badge variant="outline">
                    {t(`scans.profiles.rules.${profile.rule_sources}`)}
                  </Badge>
                )}
              </div>
              {profile.description && (
                <p
                  className="max-w-sm truncate text-sm text-muted-foreground"
                  title={profile.description}
                >
                  {profile.description}
                </p>
              )}
            </div>
          )
        },
      },
      {
        id: 'rule',
        accessorFn: (p) => gateSummary(p.quality_gate, t),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.profiles.col.rule')} />
        ),
        cell: ({ getValue }) => (
          <span className="text-sm text-muted-foreground">{getValue<string>()}</span>
        ),
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const profile = row.original
          return (
            <Can permission={[Permission.ScanProfilesWrite, Permission.ScanProfilesDelete]}>
              <DataTableRowActions
                actions={[
                  ...(!profile.is_default && canSetDefault
                    ? ([
                        {
                          label: t('scans.profiles.setAsDefault'),
                          icon: Star,
                          onClick: () => handleSetDefault(profile),
                          disabled: isSettingDefault,
                          permission: Permission.ScanProfilesWrite,
                        },
                      ] satisfies RowAction[])
                    : []),
                  {
                    label: t('scans.profiles.edit'),
                    icon: Pencil,
                    onClick: () => handleEditProfile(profile),
                    permission: Permission.ScanProfilesWrite,
                  },
                  {
                    label: t('scans.profiles.clone'),
                    icon: Copy,
                    onClick: () => handleCloneProfile(profile),
                    permission: Permission.ScanProfilesWrite,
                  },
                  ...(!profile.is_system
                    ? ([
                        {
                          label: t('scans.profiles.delete'),
                          icon: Trash2,
                          onClick: () => handleDeleteClick(profile),
                          destructive: true,
                          separatorBefore: true,
                          permission: Permission.ScanProfilesDelete,
                        },
                      ] satisfies RowAction[])
                    : []),
                ]}
              />
            </Can>
          )
        },
      },
    ],
    [
      handleSetDefault,
      handleEditProfile,
      handleCloneProfile,
      handleDeleteClick,
      isSettingDefault,
      canSetDefault,
      t,
    ]
  )

  const addMenu = (
    <Can permission={Permission.ScanProfilesWrite}>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="sm">
            <Plus className="h-4 w-4" />
            {t('scans.profiles.add')}
            <ChevronDown className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={() => setAddDialogOpen(true)}>
            <Plus className="me-2 h-4 w-4" />
            {t('scans.profiles.addCustom')}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setPresetDialogOpen(true)}>
            <Sparkles className="me-2 h-4 w-4" />
            {t('scans.profiles.addPreset')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </Can>
  )

  let body: React.ReactNode
  if (error) {
    body = (
      <ErrorState title={t('scans.profiles.errorTitle')} error={error} onRetry={handleRefresh} />
    )
  } else if (isLoading) {
    body = <TableSkeleton rows={4} />
  } else if (profiles.length === 0) {
    body = (
      <EmptyState
        icon={Settings2}
        title={t('scans.profiles.empty')}
        description={t('scans.profiles.emptyDesc')}
        action={
          <Can permission={Permission.ScanProfilesWrite}>
            <Button size="sm" onClick={() => setAddDialogOpen(true)}>
              <Plus className="h-4 w-4" />
              {t('scans.profiles.create')}
            </Button>
          </Can>
        }
      />
    )
  } else {
    body = (
      <DataTable
        columns={columns}
        data={profiles}
        getRowId={(p) => p.id}
        searchPlaceholder={t('scans.profiles.search')}
        toolbarEnd={<RefreshButton onClick={handleRefresh} loading={isLoading} />}
        emptyMessage={t('scans.profiles.noMatch')}
      />
    )
  }

  return (
    <>
      <PageHeader title={t('scans.profiles.title')} description={t('scans.profiles.pageDesc')}>
        {addMenu}
      </PageHeader>

      <div className="mt-5">{body}</div>

      {/* Dialogs */}
      <AddScanProfileDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        onSuccess={handleRefresh}
      />

      <AddPresetDialog open={presetDialogOpen} onOpenChange={setPresetDialogOpen} />

      {selectedProfile && (
        <>
          <EditScanProfileDialog
            open={editDialogOpen}
            onOpenChange={setEditDialogOpen}
            profile={selectedProfile}
            onSuccess={handleRefresh}
          />

          <CloneScanProfileDialog
            open={cloneDialogOpen}
            onOpenChange={setCloneDialogOpen}
            profile={selectedProfile}
            onSuccess={handleRefresh}
          />
        </>
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t('confirm.scanProfile.deleteTitle', 'Delete the scan profile {name}?', {
          name: selectedProfile?.name ?? '',
        })}
        desc={t(
          'confirm.scanProfile.deleteDesc',
          'It can no longer be chosen for scans. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDeleteConfirm}
      />
    </>
  )
}
