'use client'

import { useState, useMemo, useCallback } from 'react'
import Link from '@/components/link'
import { csrfFetch } from '@/lib/api/client'
import { tenantEndpoints } from '@/lib/api/endpoints'
import { useTenant } from '@/context/tenant-provider'
import { useMembers } from '@/features/organization'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { RoleRiskBadge, RoleSummaryLine } from './role-risk'
import { RoleTemplateUpdate } from './role-template-update'
import { useTranslation } from '@/context/i18n-provider'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { TabsCount } from '@/components/ui/tabs'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import {
  ChevronRight,
  Database,
  Eye,
  Hash,
  Key,
  Loader2,
  Lock,
  Mail,
  MoreHorizontal,
  Pencil,
  Search,
  Shield,
  Trash2,
  UserMinus,
  UserPlus,
  Users,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  DetailHeader,
  DetailSection,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  DetailTabs,
  EmptyState,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'
import {
  useRoleMembers,
  useTenantPermissionModules,
  type Role,
  type RoleMember,
} from '@/features/access-control'
import { AddMemberToRoleDialog } from './add-member-to-role-dialog'
import { RoleCapabilities } from './role-capabilities'
import { isAdminBypassRole } from '../lib/authz-reference'

interface RoleDetailSheetProps {
  role: Role | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onEdit?: (role: Role) => void
  onDelete?: (role: Role) => void
}

type RoleTab = 'permissions' | 'features' | 'members'

// The four team roles are the member's role: they change on the Members page
// (PATCH /tenants/{tenant}/members/{id}) and by ownership transfer, never
// through /users/{id}/roles. Taking a person out of the admin role means
// making them a member; out of the member role, a viewer.
const TEAM_ROLE_SLUGS = ['owner', 'admin', 'member', 'viewer']
const TEAM_ROLE_DEMOTION: Record<string, 'member' | 'viewer' | undefined> = {
  admin: 'member',
  member: 'viewer',
}

// Permission types: a category, told apart by icon and label as well as colour.
const permissionTypeConfig: Record<
  'read' | 'write' | 'delete',
  { key: string; en: string; chip: string; icon: React.ElementType }
> = {
  read: {
    key: 'org.roleDetail.type.read',
    en: 'Read',
    chip: 'bg-success/10 text-success',
    icon: Eye,
  },
  write: {
    key: 'org.roleDetail.type.write',
    en: 'Write',
    chip: 'bg-info/10 text-info',
    icon: Pencil,
  },
  delete: {
    key: 'org.roleDetail.type.delete',
    en: 'Delete',
    chip: 'bg-destructive/10 text-destructive',
    icon: Trash2,
  },
}

function getPermissionType(permissionId: string): 'read' | 'write' | 'delete' {
  // Extract the action (last part after the last colon)
  // Permission format: {module}:{subfeature}:{action}
  const action = permissionId.split(':').pop() || ''

  if (action === 'delete' || action === 'remove') return 'delete'
  if (
    [
      'write',
      'create',
      'update',
      'manage',
      'assign',
      'trigger',
      'cancel',
      'schedule',
      'invite',
      'bulk',
      'export',
    ].includes(action)
  )
    return 'write'
  return 'read'
}

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function getInitials(name: string | undefined, email: string): string {
  if (name) {
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2)
  }
  return email.slice(0, 2).toUpperCase()
}

export function RoleDetailSheet({
  role,
  open,
  onOpenChange,
  onEdit,
  onDelete,
}: RoleDetailSheetProps) {
  const {
    members: roleMembers,
    isLoading: isLoadingMembers,
    mutate: mutateMembers,
  } = useRoleMembers(role?.id || null)
  const { modules: permissionModules, isLoading: isLoadingModules } = useTenantPermissionModules()

  // UI state
  const [searchQuery, setSearchQuery] = useState('')
  const [memberSearchQuery, setMemberSearchQuery] = useState('')
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set())
  const [addMemberDialogOpen, setAddMemberDialogOpen] = useState(false)
  const [removingMemberId, setRemovingMemberId] = useState<string | null>(null)
  const [pendingRemove, setPendingRemove] = useState<RoleMember | null>(null)
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const { members: tenantMembers } = useMembers(currentTenant?.slug)
  const isTeamRole = !!role && role.is_system && TEAM_ROLE_SLUGS.includes(role.slug)
  const demoteTo = role && isTeamRole ? TEAM_ROLE_DEMOTION[role.slug] : undefined
  const demoteLabel =
    demoteTo === 'member'
      ? t('org.role.member', 'Member')
      : demoteTo === 'viewer'
        ? t('org.role.viewer', 'Viewer')
        : ''
  const [activeTab, setActiveTab] = useState<RoleTab>('permissions')

  // Reset state when sheet closes
  const handleOpenChange = (open: boolean) => {
    if (!open) {
      setSearchQuery('')
      setMemberSearchQuery('')
      setExpandedModules(new Set())
      setActiveTab('permissions')
    }
    onOpenChange(open)
  }

  // Filter members based on search
  const filteredMembers = useMemo(() => {
    if (!memberSearchQuery.trim()) return roleMembers

    const query = memberSearchQuery.toLowerCase()
    return roleMembers.filter(
      (m) => m.name?.toLowerCase().includes(query) || m.email?.toLowerCase().includes(query)
    )
  }, [roleMembers, memberSearchQuery])

  // Remove member from role
  const handleRemoveMember = useCallback(
    async (member: RoleMember) => {
      if (!role) return

      setRemovingMemberId(member.id)
      try {
        let response: Response
        if (isTeamRole) {
          // A team role changes through the membership, not the roles API.
          const membership = tenantMembers.find((m) => m.user_id === member.user_id)
          if (!demoteTo || !currentTenant?.slug || !membership) {
            throw new Error(
              t('org.roles.teamRoleUnavailable', 'This team role cannot be changed here')
            )
          }
          response = await csrfFetch(
            tenantEndpoints.updateMember(currentTenant.slug, membership.id),
            {
              method: 'PATCH',
              body: JSON.stringify({ role: demoteTo }),
            }
          )
        } else {
          response = await csrfFetch(`/api/v1/users/${member.user_id}/roles/${role.id}`, {
            method: 'DELETE',
          })
        }

        if (!response.ok) {
          const error = await response.json().catch(() => null)
          throw new Error(error?.message || `HTTP ${response.status}`)
        }

        toast.success(
          isTeamRole
            ? t('org.roles.changed', '{name} is now {role}', {
                name: member.name || member.email || '',
                role: demoteLabel,
              })
            : t('org.roleDetail.removedFromRole', '{name} removed from role', {
                name: member.name || member.email || '',
              })
        )
        setPendingRemove(null)
        mutateMembers()
      } catch (error) {
        toast.error(
          t('org.roleDetail.removeFailed', 'Failed to remove member: {error}', {
            error:
              error instanceof Error
                ? error.message
                : t('org.roleDetail.unknownError', 'Unknown error'),
          })
        )
      } finally {
        setRemovingMemberId(null)
      }
    },
    [role, mutateMembers, isTeamRole, demoteTo, demoteLabel, tenantMembers, currentTenant, t]
  )

  // Group permissions by module
  const groupedPermissions = useMemo(() => {
    if (!role || !permissionModules.length) return []

    const rolePermissionSet = new Set(role.permissions)

    return permissionModules
      .map((module) => ({
        ...module,
        permissions: module.permissions.filter((p) => rolePermissionSet.has(p.id)),
      }))
      .filter((module) => module.permissions.length > 0)
  }, [role, permissionModules])

  // Filter permissions based on search
  const filteredPermissions = useMemo(() => {
    if (!searchQuery.trim()) return groupedPermissions

    const query = searchQuery.toLowerCase()
    return groupedPermissions
      .map((module) => ({
        ...module,
        permissions: module.permissions.filter(
          (p) =>
            p.name.toLowerCase().includes(query) ||
            p.id.toLowerCase().includes(query) ||
            p.description?.toLowerCase().includes(query)
        ),
      }))
      .filter(
        (module) => module.permissions.length > 0 || module.name.toLowerCase().includes(query)
      )
  }, [groupedPermissions, searchQuery])

  // Filtered permission count (based on tenant's modules)
  const filteredPermissionCount = useMemo(() => {
    return groupedPermissions.reduce((sum, m) => sum + m.permissions.length, 0)
  }, [groupedPermissions])

  // Permission stats (based on filtered permissions)
  const permissionStats = useMemo(() => {
    if (!groupedPermissions.length) return { read: 0, write: 0, delete: 0, total: 0 }

    const stats = { read: 0, write: 0, delete: 0, total: 0 }
    for (const permModule of groupedPermissions) {
      for (const perm of permModule.permissions) {
        const type = getPermissionType(perm.id)
        stats[type as keyof typeof stats]++
        stats.total++
      }
    }
    return stats
  }, [groupedPermissions])

  // Toggle module expansion
  const toggleModule = (moduleId: string) => {
    setExpandedModules((prev) => {
      const next = new Set(prev)
      if (next.has(moduleId)) {
        next.delete(moduleId)
      } else {
        next.add(moduleId)
      }
      return next
    })
  }

  // Expand all modules
  const expandAll = () => {
    setExpandedModules(new Set(filteredPermissions.map((m) => m.id)))
  }

  // Collapse all modules
  const collapseAll = () => {
    setExpandedModules(new Set())
  }

  if (!role) return null

  const menu: DetailMenuItem[] = [
    {
      label: t('org.roleDetail.copyId', 'Copy ID'),
      icon: Hash,
      onSelect: () => {
        copyToClipboard(role.id)
        toast.success(t('org.roleDetail.idCopied', 'Role ID copied'))
      },
    },
  ]
  if (!role.is_system && onDelete) {
    menu.push({
      label: t('org.roleDetail.deleteRole', 'Delete role'),
      icon: Trash2,
      destructive: true,
      separatorBefore: true,
      onSelect: () => onDelete(role),
    })
  }

  const tabs: DetailTab<RoleTab>[] = [
    {
      value: 'permissions',
      label: (
        <>
          {t('org.roleDetail.tabPermissions', 'Permissions')}
          <TabsCount value={filteredPermissionCount} />
        </>
      ),
    },
    { value: 'features', label: t('org.roleDetail.tabFeatures', 'By feature') },
    {
      value: 'members',
      label: (
        <>
          {t('org.roleDetail.tabMembers', 'Members')}
          {!isLoadingMembers && <TabsCount value={roleMembers.length} />}
        </>
      ),
    },
  ]

  return (
    <>
      <DetailSheet
        open={open}
        onOpenChange={handleOpenChange}
        width="2xl"
        panel={activeTab}
        header={
          <DetailHeader
            title={role.name}
            badges={
              <>
                {role.is_system ? (
                  <Badge variant="outline" className="gap-1 text-xs font-normal">
                    <Lock className="h-3 w-3" />
                    {t('org.roleDetail.system', 'System')}
                  </Badge>
                ) : (
                  <Badge variant="outline" className="gap-1 text-xs font-normal">
                    <Key className="h-3 w-3" />
                    {t('org.roleDetail.custom', 'Custom')}
                  </Badge>
                )}
                {role.has_full_data_access && (
                  <Badge variant="outline" className="gap-1 text-xs font-normal">
                    <Database className="h-3 w-3" />
                    {t('org.roleDetail.fullData', 'Full data access')}
                  </Badge>
                )}
              </>
            }
            meta={[
              t('org.roleDetail.metaLevel', 'Level {level}', { level: role.hierarchy_level }),
              t('org.roleDetail.metaCreated', 'Created {date}', {
                date: formatDate(role.created_at),
              }),
            ]}
            actions={
              !role.is_system && onEdit ? (
                <Button size="sm" onClick={() => onEdit(role)}>
                  <Pencil className="h-4 w-4" />
                  {t('org.roleDetail.editRole', 'Edit role')}
                </Button>
              ) : undefined
            }
            menu={menu}
            onClose={() => handleOpenChange(false)}
          />
        }
        tabs={<DetailTabs tabs={tabs} value={activeTab} onValueChange={setActiveTab} />}
      >
        {activeTab === 'permissions' && (
          <div className="space-y-5">
            {role.description && (
              <p className="text-sm text-muted-foreground">{role.description}</p>
            )}
            {role.summary && (
              <div className="space-y-1">
                <RoleRiskBadge risk={role.summary.risk} />
                <RoleSummaryLine summary={role.summary} max={8} />
              </div>
            )}
            <RoleTemplateUpdate role={role} />

            <DetailStatGrid aria-label={t('org.roleDetail.keyNumbers', 'Key numbers')}>
              <DetailStat
                label={t('org.roleDetail.statPermissions', 'Permissions')}
                value={filteredPermissionCount}
                caption={t(
                  'org.roleDetail.statBreakdown',
                  '{read} read · {write} write · {del} delete',
                  {
                    read: permissionStats.read,
                    write: permissionStats.write,
                    del: permissionStats.delete,
                  }
                )}
              />
              <DetailStat
                label={t('org.roleDetail.statLevel', 'Hierarchy level')}
                value={role.hierarchy_level}
              />
              <DetailStat
                label={t('org.roleDetail.statDataAccess', 'Data access')}
                value={
                  role.has_full_data_access
                    ? t('org.roleDetail.dataFull', 'Full')
                    : t('org.roleDetail.dataByTeam', 'By team')
                }
                caption={
                  role.has_full_data_access
                    ? t('org.roleDetail.sawEveryAsset', 'Sees every asset')
                    : t('org.roleDetail.seesTeamAssets', 'Sees its teams’ assets')
                }
              />
            </DetailStatGrid>

            <DetailSection
              title={t('org.roleDetail.byModule', 'Permissions by module')}
              count={filteredPermissions.length}
              actions={
                <>
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={expandAll}>
                    {t('org.roleDetail.expandAll', 'Expand all')}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={collapseAll}>
                    {t('org.roleDetail.collapse', 'Collapse')}
                  </Button>
                </>
              }
            >
              <div className="relative">
                <Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  aria-label={t('org.roleDetail.searchPermLabel', 'Search permissions')}
                  placeholder={t('org.roleDetail.searchPermPlaceholder', 'Search permissions...')}
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="ps-9"
                />
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <span>{t('org.roleDetail.types', 'Types:')}</span>
                {(['read', 'write', 'delete'] as const).map((kind) => {
                  const cfg = permissionTypeConfig[kind]
                  return (
                    <span
                      key={kind}
                      className={cn('inline-flex items-center gap-1 rounded px-2 py-0.5', cfg.chip)}
                    >
                      <cfg.icon className="h-3 w-3" />
                      {t(cfg.key, cfg.en)}
                    </span>
                  )
                })}
              </div>

              {isLoadingModules ? (
                <div className="space-y-2" aria-hidden>
                  {[1, 2, 3].map((i) => (
                    <Skeleton key={i} className="h-11 w-full" />
                  ))}
                </div>
              ) : filteredPermissions.length === 0 ? (
                <EmptyState
                  icon={searchQuery ? Search : Shield}
                  title={
                    searchQuery
                      ? t('org.roleDetail.noPermMatch', 'No permissions match your search')
                      : t('org.roleDetail.noPermAssigned', 'No permissions assigned')
                  }
                  card={false}
                />
              ) : (
                <ul className="divide-y rounded-lg border">
                  {filteredPermissions.map((module) => {
                    const isExpanded = expandedModules.has(module.id) || searchQuery.length > 0
                    return (
                      <li key={module.id}>
                        <Collapsible open={isExpanded} onOpenChange={() => toggleModule(module.id)}>
                          <CollapsibleTrigger asChild>
                            <button
                              type="button"
                              className="flex w-full items-center gap-2 px-3 py-2.5 text-start hover:bg-muted/50"
                            >
                              <ChevronRight
                                className={cn(
                                  'h-4 w-4 shrink-0 text-muted-foreground transition-transform',
                                  isExpanded && 'rotate-90'
                                )}
                              />
                              <span className="flex-1 text-sm font-medium">{module.name}</span>
                              <span className="text-xs text-muted-foreground tabular-nums">
                                {module.permissions.length}
                              </span>
                            </button>
                          </CollapsibleTrigger>
                          <CollapsibleContent>
                            <div className="space-y-2 px-3 pb-3 ps-9">
                              {module.description && (
                                <p className="text-xs text-muted-foreground">
                                  {module.description}
                                </p>
                              )}
                              <div className="flex flex-wrap gap-1.5">
                                {module.permissions.map((permission) => {
                                  const cfg = permissionTypeConfig[getPermissionType(permission.id)]
                                  return (
                                    <Tooltip key={permission.id}>
                                      <TooltipTrigger asChild>
                                        <span
                                          tabIndex={0}
                                          className={cn(
                                            'inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium',
                                            cfg.chip
                                          )}
                                        >
                                          <cfg.icon className="h-3 w-3" />
                                          {permission.name}
                                        </span>
                                      </TooltipTrigger>
                                      <TooltipContent side="top" className="max-w-xs">
                                        <p className="font-mono text-xs">{permission.id}</p>
                                        {permission.description && (
                                          <p className="mt-1 text-xs">{permission.description}</p>
                                        )}
                                      </TooltipContent>
                                    </Tooltip>
                                  )
                                })}
                              </div>
                            </div>
                          </CollapsibleContent>
                        </Collapsible>
                      </li>
                    )
                  })}
                </ul>
              )}
            </DetailSection>
          </div>
        )}

        {activeTab === 'features' && (
          <RoleCapabilities
            permissions={role.permissions ?? []}
            adminBypass={isAdminBypassRole(role.slug, role.is_system)}
          />
        )}

        {activeTab === 'members' && (
          <DetailSection
            title={t('org.roleDetail.membersTitle', 'Members')}
            count={isLoadingMembers ? undefined : roleMembers.length}
            actions={
              isTeamRole ? undefined : (
                <Button size="sm" onClick={() => setAddMemberDialogOpen(true)}>
                  <UserPlus className="h-4 w-4" />
                  {t('org.roleDetail.addMember', 'Add member')}
                </Button>
              )
            }
          >
            {isTeamRole && (
              <p className="text-sm text-muted-foreground">
                {t(
                  'org.roles.teamRoleNote',
                  'This is a team role. It is the member’s role in the organization, so it changes on the Members page, and ownership moves with Transfer ownership.'
                )}{' '}
                <Link href="/settings/members" className="underline underline-offset-2">
                  {t('org.roles.openMembers', 'Open the Members page')}
                </Link>
              </p>
            )}
            <div className="relative">
              <Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                aria-label={t('org.roleDetail.searchMembersLabel', 'Search members')}
                placeholder={t('org.roleDetail.searchMembersPlaceholder', 'Search members...')}
                value={memberSearchQuery}
                onChange={(e) => setMemberSearchQuery(e.target.value)}
                className="ps-9"
              />
            </div>

            {isLoadingMembers ? (
              <div className="space-y-2" aria-hidden>
                {[1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-14 w-full" />
                ))}
              </div>
            ) : filteredMembers.length === 0 ? (
              <EmptyState
                icon={Users}
                title={
                  memberSearchQuery
                    ? t('org.roleDetail.noMemberMatch', 'No members match your search')
                    : t('org.roleDetail.noMembers', 'No members with this role')
                }
                card={false}
                action={
                  !memberSearchQuery && !isTeamRole ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setAddMemberDialogOpen(true)}
                    >
                      <UserPlus className="h-4 w-4" />
                      {t('org.roleDetail.addFirstMember', 'Add first member')}
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <ul className="divide-y rounded-lg border">
                {filteredMembers.map((member) => {
                  const label = member.name || member.email
                  return (
                    <li key={member.id} className="flex items-center gap-3 px-3 py-2.5">
                      <Avatar className="h-9 w-9 shrink-0">
                        <AvatarFallback className="bg-primary/10 text-xs font-medium text-primary">
                          {getInitials(member.name, member.email || '')}
                        </AvatarFallback>
                      </Avatar>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium break-words">{label}</p>
                        {member.name && (
                          <p className="flex items-center gap-1 text-xs break-all text-muted-foreground">
                            <Mail className="h-3 w-3 shrink-0" />
                            {member.email}
                          </p>
                        )}
                      </div>
                      {member.assigned_at && (
                        <span className="hidden shrink-0 text-xs text-muted-foreground sm:inline">
                          {formatDate(member.assigned_at)}
                        </span>
                      )}
                      {/* Always visible: a hover-only trigger cannot be found on touch. */}
                      {(!isTeamRole || demoteTo) && (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8 shrink-0"
                              aria-label={t('org.roleDetail.actionsFor', 'Actions for {name}', {
                                name: label ?? '',
                              })}
                            >
                              {removingMemberId === member.id ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <MoreHorizontal className="h-4 w-4" />
                              )}
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              variant="destructive"
                              onSelect={() => setPendingRemove(member)}
                              disabled={removingMemberId === member.id}
                            >
                              <UserMinus className="h-4 w-4" />
                              {isTeamRole
                                ? t('org.roles.changeTo', 'Change to {role}', { role: demoteLabel })
                                : t('org.roleDetail.removeFromRole', 'Remove from role')}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      )}
                    </li>
                  )
                })}
              </ul>
            )}
          </DetailSection>
        )}
      </DetailSheet>

      {/* Add Member Dialog */}
      <AddMemberToRoleDialog
        role={role}
        open={addMemberDialogOpen}
        onOpenChange={setAddMemberDialogOpen}
        existingMembers={roleMembers}
        onSuccess={() => mutateMembers()}
      />

      <ConfirmDialog
        open={pendingRemove !== null}
        onOpenChange={(open) => !open && setPendingRemove(null)}
        destructive
        title={
          isTeamRole
            ? t('confirm.role.demoteTitle', 'Change {name} from {role} to {to}?', {
                name: pendingRemove ? pendingRemove.name || pendingRemove.email || '' : '',
                role: role.name,
                to: demoteLabel,
              })
            : t('confirm.role.removeMemberTitle', 'Remove {name} from the role {role}?', {
                name: pendingRemove ? pendingRemove.name || pendingRemove.email || '' : '',
                role: role.name,
              })
        }
        desc={
          isTeamRole
            ? t(
                'confirm.role.demoteDesc',
                'This changes their role in the organization. They lose what the {role} role grants at once. You can promote them again on the Members page.',
                { role: role.name }
              )
            : t(
                'confirm.role.removeMemberDesc',
                'They lose the permissions this role grants at once, unless another role or group grants them too. You can add them back later.'
              )
        }
        confirmText={isTeamRole ? t('confirm.change', 'Change') : t('confirm.remove', 'Remove')}
        isLoading={removingMemberId !== null}
        handleConfirm={() => (pendingRemove ? handleRemoveMember(pendingRemove) : undefined)}
      />
    </>
  )
}
