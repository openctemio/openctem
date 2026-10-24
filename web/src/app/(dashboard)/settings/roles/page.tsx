'use client'

import { useState, useMemo, useCallback, useEffect } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  MetricStrip,
  type RowAction,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { toast } from 'sonner'
import { Can } from '@/lib/permissions'
import {
  Plus,
  Shield,
  Trash2,
  Search as SearchIcon,
  Eye,
  Pencil,
  Loader2,
  AlertCircle,
  RefreshCw,
} from 'lucide-react'
import { useSWRConfig } from 'swr'
import {
  useRoles,
  useDeleteRole,
  type Role,
  CreateRoleSheet,
  RoleDetailSheet,
  EditRoleSheet,
} from '@/features/access-control'
import { useUrlFilter } from '@/hooks/use-url-param'
import { confirmName } from '@/lib/confirm-name'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { RoleRiskBadge, RoleSummaryLine } from '@/features/access-control/components/role-risk'

type TypeFilter = 'all' | 'system' | 'custom'

const typeFilters: { value: TypeFilter; key: string; en: string }[] = [
  { value: 'all', key: 'org.rolesPage.type.all', en: 'All types' },
  { value: 'system', key: 'org.rolesPage.type.system', en: 'System' },
  { value: 'custom', key: 'org.rolesPage.type.custom', en: 'Custom' },
]

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

export default function RolesPage() {
  const { t } = useTranslation()
  const { mutate } = useSWRConfig()

  // API Hooks
  const { roles, isLoading, isError, mutate: mutateRoles } = useRoles()
  // A role grants every permission it holds, whatever the modules: count all.
  const getFilteredPermissionCount = useCallback((role: Role) => role.permission_count, [])

  // UI State
  const [selectedRole, setSelectedRole] = useState<Role | null>(null)
  const [createSheetOpen, setCreateSheetOpen] = useState(false)
  const [editRole, setEditRole] = useState<Role | null>(null)
  const [pendingEditRole, setPendingEditRole] = useState<Role | null>(null) // For transition from detail to edit
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [roleToDelete, setRoleToDelete] = useState<Role | null>(null)
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const [typeParam, setTypeFilter] = useUrlFilter('type', 'all')
  const typeFilter: TypeFilter =
    typeParam === 'system' || typeParam === 'custom' ? typeParam : 'all'

  // Handle transition from detail sheet to edit sheet
  // When detail sheet closes and there's a pending edit, open the edit sheet
  useEffect(() => {
    if (!selectedRole && pendingEditRole) {
      // Small delay to ensure detail sheet animation is complete
      const timer = setTimeout(() => {
        setEditRole(pendingEditRole)
        setPendingEditRole(null)
      }, 50)
      return () => clearTimeout(timer)
    }
  }, [selectedRole, pendingEditRole])

  // Ensure mutual exclusivity: when edit sheet opens, close detail sheet
  useEffect(() => {
    if (editRole && selectedRole) {
      setSelectedRole(null)
    }
  }, [editRole, selectedRole])

  // Delete hook
  const { deleteRole, isDeleting } = useDeleteRole(roleToDelete?.id || null)

  // Refresh data
  const refreshData = useCallback(() => {
    mutateRoles()
  }, [mutateRoles])

  // Filter data
  const filteredData = useMemo(() => {
    let data = [...roles]

    if (typeFilter === 'system') {
      data = data.filter((role) => role.is_system)
    } else if (typeFilter === 'custom') {
      data = data.filter((role) => !role.is_system)
    }

    const q = searchQuery.trim().toLowerCase()
    if (q) {
      data = data.filter(
        (role) =>
          role.name.toLowerCase().includes(q) ||
          role.slug.toLowerCase().includes(q) ||
          role.description?.toLowerCase().includes(q)
      )
    }

    return data
  }, [roles, typeFilter, searchQuery])

  // Type counts
  const typeCounts = useMemo(
    () => ({
      all: roles.length,
      system: roles.filter((r) => r.is_system).length,
      custom: roles.filter((r) => !r.is_system).length,
    }),
    [roles]
  )

  // Table columns
  const columns: ColumnDef<Role>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.rolesPage.col.role', 'Role')} />
      ),
      cell: ({ row }) => (
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="font-medium">{row.original.name}</p>
            {row.original.is_system && (
              <Badge variant="outline" className="text-xs">
                {t('org.rolesPage.system', 'System')}
              </Badge>
            )}
          </div>
          {row.original.description && (
            <p className="text-muted-foreground text-xs line-clamp-1">{row.original.description}</p>
          )}
        </div>
      ),
    },
    {
      id: 'risk',
      header: t('org.roleRisk.column'),
      enableSorting: false,
      cell: ({ row }) =>
        row.original.summary ? (
          <div className="min-w-0 space-y-1">
            <RoleRiskBadge risk={row.original.summary.risk} />
            <RoleSummaryLine summary={row.original.summary} max={3} className="line-clamp-1" />
          </div>
        ) : (
          <span className="text-sm tabular-nums">{getFilteredPermissionCount(row.original)}</span>
        ),
    },
    {
      accessorKey: 'has_full_data_access',
      header: t('org.rolesPage.col.dataAccess', 'Data access'),
      enableSorting: false,
      cell: ({ row }) => (
        <Badge
          variant={row.original.has_full_data_access ? 'default' : 'secondary'}
          className="text-xs"
        >
          {row.original.has_full_data_access
            ? t('org.rolesPage.fullAccess', 'Full access')
            : t('org.rolesPage.teamBased', 'Team-based')}
        </Badge>
      ),
    },
    {
      accessorKey: 'hierarchy_level',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.rolesPage.col.level', 'Level')} />
      ),
      cell: ({ row }) => (
        <span className="text-muted-foreground text-sm tabular-nums">
          {row.original.hierarchy_level}
        </span>
      ),
    },
    {
      accessorKey: 'created_at',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.rolesPage.col.created', 'Created')} />
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
        const role = row.original

        const actions: RowAction[] = [
          {
            label: t('org.rolesPage.viewDetails', 'View details'),
            icon: Eye,
            onClick: () => setSelectedRole(role),
          },
          ...(!role.is_system
            ? [
                {
                  label: t('org.rolesPage.editRole', 'Edit role'),
                  icon: Pencil,
                  route: 'PUT /api/v1/roles/{roleId}' as const,
                  onClick: () => setEditRole(role),
                },
                {
                  label: t('org.rolesPage.deleteRole', 'Delete role'),
                  icon: Trash2,
                  destructive: true,
                  separatorBefore: true,
                  route: 'DELETE /api/v1/roles/{roleId}' as const,
                  onClick: () => {
                    setRoleToDelete(role)
                    setDeleteDialogOpen(true)
                  },
                },
              ]
            : []),
        ]

        return <DataTableRowActions actions={actions} />
      },
    },
  ]

  // Actions
  const handleDeleteRole = async () => {
    if (!roleToDelete) return

    try {
      await deleteRole()
      toast.success(
        t('org.rolesPage.deleted', 'Role "{name}" deleted', { name: roleToDelete.name })
      )
      setDeleteDialogOpen(false)
      setRoleToDelete(null)
      mutate(
        (key: string) => typeof key === 'string' && key.startsWith('/api/v1/roles'),
        undefined,
        { revalidate: true }
      )
      refreshData()
    } catch (error) {
      toast.error(
        t('org.rolesPage.deleteFailed', 'Failed to delete role: {error}', {
          error:
            error instanceof Error
              ? error.message
              : t('org.rolesPage.unknownError', 'Unknown error'),
        })
      )
    }
  }

  const toggleType = (next: TypeFilter) => setTypeFilter(typeFilter === next ? 'all' : next)

  return (
    <>
      <Main>
        <PageHeader
          title={t('org.rolesPage.title', 'Roles')}
          description={t(
            'org.rolesPage.description',
            'Roles bundle permissions; a user can hold several roles.'
          )}
        >
          <Can route="POST /api/v1/roles">
            <Button size="sm" onClick={() => setCreateSheetOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('org.rolesPage.createRole', 'Create role')}
            </Button>
          </Can>
        </PageHeader>

        {isError && !isLoading ? (
          <Alert variant="destructive" className="mt-5">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>{t('org.rolesPage.loadFailedTitle', 'Failed to load roles')}</AlertTitle>
            <AlertDescription>
              <p>{t('org.rolesPage.loadFailedBody', 'The role list could not be loaded.')}</p>
              <Button variant="outline" size="sm" className="mt-2" onClick={refreshData}>
                <RefreshCw className="me-2 h-4 w-4" />
                {t('common.retry', 'Retry')}
              </Button>
            </AlertDescription>
          </Alert>
        ) : (
          <>
            <MetricStrip
              className="mt-5"
              loading={isLoading}
              items={[
                {
                  key: 'all',
                  label: t('org.rolesPage.metric.roles', 'Roles'),
                  value: typeCounts.all,
                  onClick: () => setTypeFilter('all'),
                  active: typeFilter === 'all',
                },
                {
                  key: 'system',
                  label: t('org.rolesPage.metric.system', 'System roles'),
                  value: typeCounts.system,
                  onClick: () => toggleType('system'),
                  active: typeFilter === 'system',
                },
                {
                  key: 'custom',
                  label: t('org.rolesPage.metric.custom', 'Custom roles'),
                  value: typeCounts.custom,
                  onClick: () => toggleType('custom'),
                  active: typeFilter === 'custom',
                },
              ]}
            />

            <div className="mt-5">
              {isLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-9 w-full max-w-sm" />
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-12 w-full" />
                  ))}
                </div>
              ) : roles.length === 0 ? (
                <EmptyState
                  icon={Shield}
                  title={t('org.rolesPage.emptyTitle', 'No roles yet')}
                  description={t(
                    'org.rolesPage.emptyBody',
                    'Create a role to grant a set of permissions to users.'
                  )}
                  action={
                    <Can route="POST /api/v1/roles">
                      <Button size="sm" onClick={() => setCreateSheetOpen(true)}>
                        <Plus className="me-2 h-4 w-4" />
                        {t('org.rolesPage.createRole', 'Create role')}
                      </Button>
                    </Can>
                  }
                />
              ) : (
                <DataTable
                  columns={columns}
                  data={filteredData}
                  getRowId={(r) => r.id}
                  showSearch={false}
                  showColumnToggle={false}
                  onRowClick={(r) => setSelectedRole(r)}
                  toolbarStart={
                    <>
                      <div className="relative min-w-0 flex-1 sm:max-w-sm">
                        <SearchIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                        <Input
                          placeholder={t('org.rolesPage.searchPlaceholder', 'Search roles...')}
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="ps-9"
                          aria-label={t('org.rolesPage.searchLabel', 'Search roles')}
                        />
                      </div>
                      <Select
                        value={typeFilter}
                        onValueChange={(v) => setTypeFilter(v as TypeFilter)}
                      >
                        <SelectTrigger
                          className="h-9 w-[130px]"
                          aria-label={t('org.rolesPage.typeLabel', 'Role type')}
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {typeFilters.map((f) => (
                            <SelectItem key={f.value} value={f.value}>
                              {t(f.key, f.en)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </>
                  }
                  emptyMessage={t('org.rolesPage.noMatch', 'No roles match these filters')}
                />
              )}
            </div>
          </>
        )}
      </Main>

      {/* Create Role Sheet */}
      <CreateRoleSheet
        open={createSheetOpen}
        onOpenChange={setCreateSheetOpen}
        onSuccess={refreshData}
      />

      {/* Role Detail Sheet */}
      <RoleDetailSheet
        role={selectedRole}
        open={!!selectedRole}
        onOpenChange={(open) => !open && setSelectedRole(null)}
        onEdit={(role) => {
          // Use pending edit pattern to wait for detail sheet to close
          setPendingEditRole(role)
          setSelectedRole(null) // This triggers the close animation
        }}
        onDelete={(role) => {
          setRoleToDelete(role)
          setDeleteDialogOpen(true)
          setSelectedRole(null)
        }}
      />

      {/* Edit Role Sheet */}
      <EditRoleSheet
        role={editRole}
        open={!!editRole}
        onOpenChange={(open) => !open && setEditRole(null)}
        onSuccess={() => {
          setEditRole(null)
          refreshData()
        }}
      />

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={(open) => {
          setDeleteDialogOpen(open)
          if (!open) setRoleToDelete(null)
        }}
        destructive
        title={t('confirm.role.deleteTitle', 'Delete the role "{name}"?', {
          name: roleToDelete?.name ?? '',
        })}
        desc={t(
          'confirm.role.deleteDesc',
          'Members who have it lose its permissions at once, unless another role grants them. This cannot be undone.'
        )}
        confirmText={
          <>
            {isDeleting ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <Trash2 className="me-2 h-4 w-4" />
            )}
            {t('confirm.role.delete', 'Delete role')}
          </>
        }
        isLoading={isDeleting}
        typeToConfirm={roleToDelete ? confirmName(roleToDelete.name, roleToDelete.id) : undefined}
        handleConfirm={handleDeleteRole}
      />
    </>
  )
}
