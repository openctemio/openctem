'use client'

import { useState, useMemo, useCallback, useEffect } from 'react'
import type { Column, ColumnDef, Row } from '@tanstack/react-table'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  FacetOption,
  FacetPanel,
  FacetSection,
  FilterSheet,
  SettingsPage,
  type RowAction,
} from '@/features/shared'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { toast } from 'sonner'
import { Can, useCanMutate } from '@/lib/permissions'
import { Plus, Shield, Trash2, Eye, Pencil, Loader2 } from 'lucide-react'
import { useSWRConfig } from 'swr'
import {
  useRoles,
  useDeleteRole,
  type Role,
  CreateRoleSheet,
  RoleDetailSheet,
  EditRoleSheet,
} from '@/features/access-control'
import type { RoleRisk } from '@/features/access-control/types/role.types'
import { replaceUrlSearch, useUrlFilter } from '@/hooks/use-url-param'
import { confirmName } from '@/lib/confirm-name'
import { toDisplayText } from '@/lib/untrusted-text'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import {
  RoleRiskBadge,
  RoleSummaryLine,
  useRoleWords,
} from '@/features/access-control/components/role-risk'

/**
 * Roles of the organization (boards P4-Settings-Roles, -RoleEditor,
 * -DialogsAccess): one list with search, Add filter (role type, risk) and
 * Display; the role opens in the detail sheet (`?role=<id>`), custom roles are
 * edited and deleted from there or the row menu. The list is small and
 * unpaged (the four system roles plus the organization's own), so filters
 * apply on the client.
 */

type TypeFilter = 'all' | 'system' | 'custom'
const RISKS: RoleRisk[] = ['critical', 'high', 'medium', 'low']
const FILTER_PARAMS = ['type', 'risk', 'q']

const typeFilters: { value: Exclude<TypeFilter, 'all'>; key: string; en: string }[] = [
  { value: 'system', key: 'org.rolesPage.type.systemRoles', en: 'System roles' },
  { value: 'custom', key: 'org.rolesPage.type.customRoles', en: 'Custom roles' },
]

const roleHref = (id: string) => `/settings/roles?role=${encodeURIComponent(id)}`

export default function RolesPage() {
  const { t } = useTranslation()
  const words = useRoleWords()
  const { mutate } = useSWRConfig()
  const canCreate = useCanMutate('POST /api/v1/roles')

  const { roles, isLoading, isError, error, mutate: mutateRoles } = useRoles()

  const [roleParam, setRoleParam] = useUrlFilter('role', '')
  const selectedRole = useMemo(
    () => (roleParam ? (roles.find((r) => r.id === roleParam) ?? null) : null),
    [roles, roleParam]
  )
  const openRole = useCallback((role: Role | null) => setRoleParam(role?.id ?? ''), [setRoleParam])

  const [createSheetOpen, setCreateSheetOpen] = useState(false)
  const [editRole, setEditRole] = useState<Role | null>(null)
  const [pendingEditRole, setPendingEditRole] = useState<Role | null>(null)
  const [roleToDelete, setRoleToDelete] = useState<Role | null>(null)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const [typeParam, setTypeFilter] = useUrlFilter('type', '')
  const [riskParam, setRiskFilter] = useUrlFilter('risk', '')
  const typeFilter: TypeFilter =
    typeParam === 'system' || typeParam === 'custom' ? typeParam : 'all'
  const riskFilter = (RISKS as string[]).includes(riskParam) ? (riskParam as RoleRisk) : null

  // From the detail sheet to the edit sheet: wait until the detail sheet has
  // closed, so the two never show at once.
  useEffect(() => {
    if (!selectedRole && pendingEditRole) {
      const timer = setTimeout(() => {
        setEditRole(pendingEditRole)
        setPendingEditRole(null)
      }, 50)
      return () => clearTimeout(timer)
    }
  }, [selectedRole, pendingEditRole])

  const { deleteRole, isDeleting } = useDeleteRole(roleToDelete?.id || null)

  const refreshData = useCallback(() => {
    void mutateRoles()
  }, [mutateRoles])

  const filteredData = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return roles.filter((role) => {
      if (typeFilter === 'system' && !role.is_system) return false
      if (typeFilter === 'custom' && role.is_system) return false
      if (riskFilter && role.summary?.risk !== riskFilter) return false
      if (!q) return true
      return (
        role.name.toLowerCase().includes(q) ||
        role.slug.toLowerCase().includes(q) ||
        !!role.description?.toLowerCase().includes(q)
      )
    })
  }, [roles, typeFilter, riskFilter, searchQuery])

  const customCount = useMemo(() => roles.filter((r) => !r.is_system).length, [roles])
  const hasMemberCounts = roles.some((r) => r.members_count !== undefined)

  const askDelete = useCallback((role: Role) => setRoleToDelete(role), [])

  // A row menu only where it offers a change: a system role, or a reader who
  // can neither edit nor delete, opens the role by its name or the row (an
  // overflow menu never holds one item).
  const canEditRole = useCanMutate('PUT /api/v1/roles/{roleId}')
  const canDeleteRole = useCanMutate('DELETE /api/v1/roles/{roleId}')
  const roleMenu = useCallback(
    (role: Role) => {
      if (role.is_system || !(canEditRole || canDeleteRole)) return null
      const name = toDisplayText(role.name, 120)
      const actions: RowAction[] = [
        {
          label: t('org.rolesPage.viewDetails', 'View details'),
          icon: Eye,
          onClick: () => openRole(role),
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
                onClick: () => askDelete(role),
              },
            ]
          : []),
      ]
      return (
        <DataTableRowActions
          title={name}
          label={t('common.rowActions.actionsFor', 'Actions for {name}', { name })}
          actions={actions}
        />
      )
    },
    [t, openRole, askDelete, canEditRole, canDeleteRole]
  )

  const dataAccess = (role: Role) => (
    <Badge variant={role.has_full_data_access ? 'default' : 'secondary'}>
      {role.has_full_data_access
        ? t('org.rolesPage.fullAccess', 'Full access')
        : t('org.rolesPage.teamBased', 'Team-based')}
    </Badge>
  )
  const systemBadge = (
    <Badge variant="outline" className="shrink-0">
      {t('org.rolesPage.system', 'System')}
    </Badge>
  )

  const roleLabel = t('org.rolesPage.col.role', 'Role')
  const riskLabel = t('org.roleRisk.column', 'Risk')
  const accessLabel = t('org.rolesPage.col.dataAccess', 'Data access')
  const levelLabel = t('org.rolesPage.col.level', 'Level')
  const membersLabel = t('org.rolesPage.col.members', 'Members')
  const permissionsLabel = t('org.rolesPage.col.permissions', 'Permissions')

  const columns: ColumnDef<Role>[] = [
    {
      accessorKey: 'name',
      meta: { kind: 'name', pin: 'start', minWidth: 200, label: roleLabel },
      enableHiding: false,
      header: ({ column }) => <DataTableColumnHeader column={column} title={roleLabel} />,
      cell: ({ row }) => {
        const role = row.original
        const name = toDisplayText(role.name, 200)
        return (
          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-2">
              <RowNameLink href={roleHref(role.id)} onOpen={() => openRole(role)} title={name}>
                {name}
              </RowNameLink>
              {role.is_system && systemBadge}
            </div>
            {role.description && (
              <p className="text-cap text-muted-foreground truncate">
                {toDisplayText(role.description, 300)}
              </p>
            )}
          </div>
        )
      },
    },
    {
      id: 'risk',
      accessorFn: (r) => (r.summary ? RISKS.length - RISKS.indexOf(r.summary.risk) : 0),
      meta: { kind: 'text', minWidth: 170, maxWidth: 320, label: riskLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={riskLabel} />,
      cell: ({ row }) =>
        row.original.summary ? (
          <div className="min-w-0 space-y-1">
            <RoleRiskBadge risk={row.original.summary.risk} />
            <RoleSummaryLine
              summary={row.original.summary}
              max={3}
              className="text-cap text-muted-foreground truncate"
            />
          </div>
        ) : null,
    },
    {
      accessorKey: 'has_full_data_access',
      meta: { kind: 'status', width: 200, label: accessLabel },
      enableSorting: false,
      header: accessLabel,
      cell: ({ row }) => dataAccess(row.original),
    },
    {
      accessorKey: 'hierarchy_level',
      meta: { kind: 'number', hideBelow: 1000, label: levelLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={levelLabel} />,
      cell: ({ row }) => <span className="tabular-nums">{row.original.hierarchy_level}</span>,
    },
    // The list answer carries no member count today: the column shows only
    // when it does, never a row of zeros.
    ...(hasMemberCounts
      ? [
          {
            id: 'members',
            accessorFn: (r: Role) => r.members_count ?? 0,
            meta: { kind: 'number' as const, hideBelow: 900, label: membersLabel },
            header: ({ column }: { column: Column<Role> }) => (
              <DataTableColumnHeader column={column} title={membersLabel} />
            ),
            cell: ({ row }: { row: Row<Role> }) => (
              <span className="tabular-nums">{row.original.members_count ?? 0}</span>
            ),
          },
        ]
      : []),
    {
      accessorKey: 'permission_count',
      meta: { kind: 'number', hideBelow: 900, label: permissionsLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={permissionsLabel} />,
      cell: ({ row }) => <span className="tabular-nums">{row.original.permission_count}</span>,
    },
    {
      id: 'actions',
      meta: { kind: 'actions' },
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => roleMenu(row.original),
    },
  ]

  const handleDeleteRole = async () => {
    if (!roleToDelete) return
    try {
      await deleteRole()
      toast.success(
        t('org.rolesPage.deleted', 'Role "{name}" deleted', {
          name: toDisplayText(roleToDelete.name, 120),
        })
      )
      setRoleToDelete(null)
      void mutate(
        (key: string) => typeof key === 'string' && key.startsWith('/api/v1/roles'),
        undefined,
        { revalidate: true }
      )
      refreshData()
    } catch (err) {
      // The dialog stays open: the role is still there and can be tried again.
      toast.error(
        t('org.rolesPage.deleteFailed', 'Failed to delete role: {error}', {
          error:
            err instanceof Error ? err.message : t('org.rolesPage.unknownError', 'Unknown error'),
        })
      )
    }
  }

  // Filters: one URL write for several params (two setters in a row would
  // each start from the same URL).
  const clearFilters = () => {
    const next = new URLSearchParams(window.location.search)
    for (const name of FILTER_PARAMS) next.delete(name)
    replaceUrlSearch(next)
  }
  const typeText = (v: Exclude<TypeFilter, 'all'>) => {
    const f = typeFilters.find((x) => x.value === v)!
    return t(f.key, f.en)
  }
  const chipList = [
    ...(typeFilter !== 'all'
      ? [
          {
            key: 'type',
            text: t('org.rolesPage.chip.type', 'Role type: {value}', {
              value: typeText(typeFilter),
            }),
            clear: () => setTypeFilter(''),
          },
        ]
      : []),
    ...(riskFilter
      ? [
          {
            key: 'risk',
            text: t('org.rolesPage.chip.risk', 'Risk: {value}', { value: words.risk(riskFilter) }),
            clear: () => setRiskFilter(''),
          },
        ]
      : []),
  ]
  const activeCount = chipList.length
  const chipsRow =
    chipList.length > 0 ? (
      <FilterChipsRow
        data-testid="roles-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chipList.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={c.clear}
            removeLabel={t('org.rolesPage.chip.remove', 'Remove filter {filter}', {
              filter: c.text,
            })}
          />
        ))}
        onClearAll={chipList.length > 1 ? clearFilters : undefined}
      />
    ) : undefined

  const facets = (
    <FacetPanel
      activeCount={activeCount}
      onClearAll={() => {
        setTypeFilter('')
        setRiskFilter('')
      }}
    >
      <FacetSection
        title={t('org.rolesPage.typeLabel', 'Role type')}
        selectedCount={typeFilter !== 'all' ? 1 : 0}
      >
        {typeFilters.map((f) => (
          <FacetOption
            key={f.value}
            label={t(f.key, f.en)}
            checked={typeFilter === f.value}
            onCheckedChange={(on) => setTypeFilter(on ? f.value : '')}
          />
        ))}
      </FacetSection>
      <FacetSection title={riskLabel} selectedCount={riskFilter ? 1 : 0}>
        {RISKS.map((r) => (
          <FacetOption
            key={r}
            label={words.risk(r)}
            checked={riskFilter === r}
            onCheckedChange={(on) => setRiskFilter(on ? r : '')}
          />
        ))}
      </FacetSection>
    </FacetPanel>
  )

  const narrowed = activeCount > 0 || searchQuery.trim() !== ''
  const filtersLabel = t('org.rolesPage.filtersLabel', 'Role filters')
  // Only the four system roles exist: say so when the list is narrowed to
  // custom roles, with the way to add one.
  const noCustomYet = typeFilter === 'custom' && customCount === 0 && searchQuery.trim() === ''

  const deleteMembers = roleToDelete?.members_count
  const deleteImpact =
    deleteMembers === undefined
      ? t(
          'confirm.role.deleteDesc',
          'Members who have it lose its permissions at once, unless another role grants them. This cannot be undone.'
        )
      : t(
          'confirm.role.deleteImpact',
          '{members, plural, =0 {Nobody has this role now.} one {# member has this role now and loses its permissions at once, unless another role grants them.} other {# members have this role now and lose its permissions at once, unless another role grants them.}} This cannot be undone.',
          { members: deleteMembers }
        )

  return (
    <>
      <SettingsPage
        wide
        title={t('org.rolesPage.title', 'Roles')}
        description={t(
          'org.rolesPage.description',
          'Roles bundle permissions; a user can hold several roles.'
        )}
        readOnly={
          !canCreate
            ? t(
                'org.rolesPage.readOnly',
                'View only. Only owners and administrators can change roles.'
              )
            : undefined
        }
        actions={
          <Can route="POST /api/v1/roles">
            <Button id="create-role" onClick={() => setCreateSheetOpen(true)}>
              <Plus aria-hidden />
              {t('org.rolesPage.createRole', 'Create role')}
            </Button>
          </Can>
        }
      >
        <DataTable
          columns={columns}
          data={filteredData}
          getRowId={(r) => r.id}
          isLoading={isLoading && roles.length === 0}
          error={isError ? (error ?? true) : undefined}
          onRetry={refreshData}
          errorTitle={t('org.rolesPage.subject', 'roles')}
          showSearch={false}
          search={{
            value: searchQuery,
            onChange: setSearchQuery,
            placeholder: t('org.rolesPage.searchPlaceholder', 'Search roles…'),
            label: t('org.rolesPage.searchLabel', 'Search roles'),
          }}
          // One filter entry per width: Add filter from 768 px, the button
          // joined to the search field on a phone (it opens the sheet).
          filterToggle={{
            open: false,
            onToggle: () => setFilterSheetOpen(true),
            onOpenSheet: () => setFilterSheetOpen(true),
            activeCount,
            controlsId: 'role-filters',
            label: filtersLabel,
            sheetOnly: true,
          }}
          toolbarStart={<AddFilterPanel>{facets}</AddFilterPanel>}
          toolbarBelow={chipsRow}
          onRowClick={openRole}
          showPagination={filteredData.length > 25}
          paginationNoun={t('org.rolesPage.noun', 'roles')}
          mobileRow={(role) => (
            <PersonPhoneCard
              title={
                <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="min-w-0">{toDisplayText(role.name, 200)}</span>
                  {role.is_system && systemBadge}
                </span>
              }
              address={role.description ? toDisplayText(role.description, 300) : undefined}
              onOpen={() => openRole(role)}
              menu={roleMenu(role)}
              facts={
                <>
                  {role.summary && <RoleRiskBadge risk={role.summary.risk} />}
                  {dataAccess(role)}
                  <span className="text-cap text-muted-foreground tabular-nums">
                    {role.members_count !== undefined
                      ? t(
                          'org.rolesPage.card.counts',
                          '{members, plural, one {# member} other {# members}}, {permissions, plural, one {# permission} other {# permissions}}',
                          { members: role.members_count, permissions: role.permission_count }
                        )
                      : t(
                          'org.rolesPage.card.permissions',
                          '{permissions, plural, one {# permission} other {# permissions}}',
                          { permissions: role.permission_count }
                        )}
                  </span>
                </>
              }
            />
          )}
          isFiltered={narrowed}
          onClearFilters={clearFilters}
          emptyState={{
            nothingYet: (
              <EmptyState
                icon={Shield}
                title={t('org.rolesPage.emptyTitle', 'No roles yet')}
                description={t(
                  'org.rolesPage.emptyBody',
                  'Create a role to grant a set of permissions to users.'
                )}
              />
            ),
            noMatch: noCustomYet
              ? {
                  title: t('org.rolesPage.noCustomTitle', 'No custom roles yet'),
                  hint: t(
                    'org.rolesPage.noCustomHint',
                    'Owner, Admin, Member and Viewer always exist. Add a custom role for anything in between.'
                  ),
                }
              : {
                  title: t('org.rolesPage.noMatch', 'No roles match these filters'),
                  hint: t(
                    'org.rolesPage.noMatchHint',
                    'Try removing a filter or clearing the search.'
                  ),
                },
          }}
        />
      </SettingsPage>

      <FilterSheet open={filterSheetOpen} onOpenChange={setFilterSheetOpen} title={filtersLabel}>
        {facets}
      </FilterSheet>

      <CreateRoleSheet
        open={createSheetOpen}
        onOpenChange={setCreateSheetOpen}
        onSuccess={refreshData}
      />

      <RoleDetailSheet
        role={selectedRole}
        open={!!selectedRole}
        onOpenChange={(open) => !open && openRole(null)}
        onEdit={(role) => {
          setPendingEditRole(role)
          openRole(null)
        }}
        onDelete={(role) => {
          askDelete(role)
          openRole(null)
        }}
      />

      <EditRoleSheet
        role={editRole}
        open={!!editRole}
        onOpenChange={(open) => !open && setEditRole(null)}
        onSuccess={() => {
          setEditRole(null)
          refreshData()
        }}
      />

      <ConfirmDialog
        open={!!roleToDelete}
        onOpenChange={(open) => {
          if (!open) setRoleToDelete(null)
        }}
        destructive
        title={t('confirm.role.deleteTitle', 'Delete the role "{name}"?', {
          name: roleToDelete ? toDisplayText(roleToDelete.name, 120) : '',
        })}
        desc={deleteImpact}
        confirmText={
          <>
            {isDeleting ? <Loader2 className="animate-spin" aria-hidden /> : <Trash2 aria-hidden />}
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
