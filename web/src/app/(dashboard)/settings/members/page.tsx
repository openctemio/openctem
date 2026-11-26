'use client'

import { useNow } from '@/hooks/use-now'
import { useDisplayUser } from '@/hooks/use-display-user'
import { useState, useMemo, useCallback, useEffect, useRef } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  SettingsPage,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  DetailCallout,
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { HealthStatus } from '@/components/ui/health-status'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { OneTimeLinkDialog } from '@/components/one-time-link-dialog'
import { useEmailUnavailable } from '@/features/auth/api/use-auth-providers'
import { buildInvitationLink } from '@/features/organization/components/invite-user-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { roleDisplayName } from '@/features/access-control/lib/system-role'
import { formatCalendarDate } from '@/lib/format-metric'
import { JoinRequestsCard } from '@/features/organization/components/join-requests-card'
import { useJoinRequests } from '@/features/organization/api/use-domain-signup'
import type { RowAction } from '@/features/shared/components/data-table-row-actions'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import {
  UserPlus,
  Shield,
  CheckCircle,
  Trash2,
  Send,
  Ban,
  Eye,
  Pencil,
  Copy,
  Lock,
  Loader2,
  AlertCircle,
  RefreshCw,
  KeyRound,
  ShieldOff,
  UserMinus,
  Eraser,
  CalendarClock,
  Crown,
  Info,
  LinkIcon,
  RotateCw,
} from 'lucide-react'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useTenant } from '@/context/tenant-provider'
import {
  useMembers,
  useMemberStats,
  useUpdateMemberRole,
  useInvitations,
  type MemberWithUser,
  type MemberRole,
  type MemberRBACRole,
  STATUS_DISPLAY,
  AddUserDialog,
  InviteUserDialog,
  RoleChecklist,
  SetupLinkDialog,
  issueSetupLink,
  type SetupLinkTarget,
  isPeerAdminLocked,
  PEER_ADMIN_LOCK_REASON,
  canResetMemberMfa,
  RESET_MFA_OWNER_REASON,
  MemberAccessReportView,
  OffboardMemberDialog,
  useMemberAccessReport,
  eraseMemberPersonalData,
  isDeactivated,
} from '@/features/organization'
import { PendingSetupBadge } from '@/features/shared'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { useUserRoles, useRoles, useSetUserRoles, type Role } from '@/features/access-control'
import { createContext, useContext } from 'react'

// Context to pass member roles without N+1 API calls
type MemberRolesMap = Map<string, MemberRBACRole[]>
const MemberRolesContext = createContext<MemberRolesMap>(new Map())
import { fetcherWithOptions } from '@/lib/api/client'
import { tenantEndpoints } from '@/lib/api/endpoints'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission, usePermissions, useCanMutate } from '@/lib/permissions'
import { useOpenForm } from '@/hooks/use-open-form'
import { MemberMfaBadge } from '@/features/organization/components/member-mfa-badge'
import { MemberBadges } from '@/features/organization/components/member-badges'
import {
  PersonPhoneCard,
  distinctAddress,
} from '@/features/organization/components/person-phone-card'
import { MemberAccessDialog } from '@/features/organization/components/member-access-dialog'
import { suspendedReasonText } from '@/features/organization/lib/external-access'
import { useTenantSettings } from '@/features/organization/api/use-tenant-settings'
import { usePendingOwnershipTransfer } from '@/features/organization/api/use-ownership-transfer'
import { TransferOwnershipDialog } from '@/features/organization/components/transfer-ownership-dialog'
import { OwnershipTransferBanner } from '@/features/organization/components/ownership-transfer-banner'
import { BreakText } from '@/features/shared/components/break-text'

// Tab values for the status filter on the members table (RFC-050 member
// lifecycle). "current" (the default) is active + disabled; offboarded
// members are the tombstones of people who left, listed only on request.
// Pending invitations live in their own section, so they are NOT a tab here.
type StatusFilter = 'current' | 'active' | 'suspended' | 'offboarded' | 'all'
type RoleFilter = 'all' | MemberRole
type KindFilter = 'all' | 'internal' | 'external'

// Static config
const MEMBER_PAGE_SIZES = [10, 20, 50, 100]

const statusFilters: { value: StatusFilter; key: string; en: string }[] = [
  { value: 'current', key: 'org.membersPage.filter.current', en: 'Current members' },
  { value: 'active', key: 'org.membersPage.filter.active', en: 'Active' },
  { value: 'suspended', key: 'org.membersPage.filter.suspended', en: 'Disabled' },
  { value: 'offboarded', key: 'org.membersPage.filter.offboarded', en: 'Offboarded' },
  { value: 'all', key: 'org.membersPage.filter.everyone', en: 'Everyone' },
]

// External members (api RFC-058): people whose email domain the
// organization does not hold.
const kindFilters: { value: KindFilter; key: string; en: string }[] = [
  { value: 'all', key: 'org.membersPage.filter.everyone', en: 'Everyone' },
  { value: 'internal', key: 'org.membersPage.filter.internal', en: 'Internal' },
  { value: 'external', key: 'org.membersPage.filter.external', en: 'External' },
]

const roleFilters: { value: RoleFilter; key: string; en: string }[] = [
  { value: 'all', key: 'org.membersPage.filter.allRoles', en: 'All roles' },
  { value: 'owner', key: 'org.role.owner', en: 'Owner' },
  { value: 'admin', key: 'org.role.admin', en: 'Admin' },
  { value: 'member', key: 'org.role.member', en: 'Member' },
  { value: 'viewer', key: 'org.role.viewer', en: 'Viewer' },
]

// The lists of the page, one tab each; the tab is in the URL (`?tab=`).
type MemberTab = 'members' | 'invitations' | 'requests'

// Helper functions
// In the console language ("25 thg 11, 2026" in Vietnamese), not always English.
const formatDate = (dateString: string, locale: string) => formatCalendarDate(dateString, locale)

type TFn = ReturnType<typeof useTranslation>['t']

const formatLastActive = (t: TFn, locale: string, lastLoginAt?: string) => {
  if (!lastLoginAt) return t('org.membersPage.never', 'Never')
  const date = new Date(lastLoginAt)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return t('org.membersPage.justNow', 'Just now')
  if (diffMins < 60)
    return t('org.membersPage.minsAgo', '{count, plural, one {# min ago} other {# mins ago}}', {
      count: diffMins,
    })
  if (diffHours < 24)
    return t('org.membersPage.hoursAgo', '{count, plural, one {# hour ago} other {# hours ago}}', {
      count: diffHours,
    })
  if (diffDays < 7)
    return t('org.membersPage.daysAgo', '{count, plural, one {# day ago} other {# days ago}}', {
      count: diffDays,
    })
  return formatDate(lastLoginAt, locale)
}

// Role chips are neutral: a role is a label, not a state, so it gets no colour of
// its own (the old per-role palette read as severity and broke in dark mode).
/** A role's name: a built-in role in the console language, a custom role as named. */
const roleName = (t: TFn, role: { slug?: string; name: string; is_system?: boolean }) =>
  roleDisplayName(t, role)

const getRoleColor = (role: Role) =>
  role.is_system ? 'bg-secondary text-secondary-foreground' : 'bg-muted text-foreground'

const MEMBER_STATUS_KEY: Record<string, { key: string; en: string }> = {
  active: { key: 'org.membersPage.filter.active', en: 'Active' },
  suspended: { key: 'org.membersPage.filter.suspended', en: 'Disabled' },
  offboarded: { key: 'org.membersPage.filter.offboarded', en: 'Offboarded' },
}

function MemberStatusBadge({ status, pendingSetup }: { status: string; pendingSetup?: boolean }) {
  const { t } = useTranslation()
  // An admin-created account whose password is not set yet: the membership is
  // active, but the person cannot sign in until they use their setup link.
  if (pendingSetup && status !== 'suspended') return <PendingSetupBadge />
  const label = MEMBER_STATUS_KEY[status]
    ? t(MEMBER_STATUS_KEY[status].key, MEMBER_STATUS_KEY[status].en)
    : (STATUS_DISPLAY[status as keyof typeof STATUS_DISPLAY]?.label ?? status)
  return (
    <HealthStatus
      state={status === 'active' ? 'ok' : status === 'suspended' ? 'paused' : 'off'}
      label={label}
      value={status}
    />
  )
}

// What the member holds and owns (owner/admin only; RFC-050).
function MemberAccessPanel({ memberId }: { memberId: string }) {
  const { report, isLoading } = useMemberAccessReport(memberId)
  return <MemberAccessReportView report={report} isLoading={isLoading} />
}

// Helper to convert MemberRBACRole to Role-like object for styling
const memberRBACRoleToRole = (role: MemberRBACRole): Role => ({
  id: role.id,
  name: role.name,
  slug: role.slug,
  is_system: role.is_system,
  description: '',
  permissions: [],
  hierarchy_level: 0,
  has_full_data_access: false,
  permission_count: 0,
  created_at: '',
  updated_at: '',
})

// Component to display user's RBAC roles (compact for table)
// Uses roles from MemberRolesContext if available, otherwise falls back to useUserRoles hook
function UserRolesCell({ userId }: { userId: string }) {
  const { t } = useTranslation()
  const memberRolesMap = useContext(MemberRolesContext)
  const cachedRoles = memberRolesMap.get(userId)

  // Fallback to individual API call if roles not in context (backward compatibility)
  const { roles: fetchedRoles, isLoading } = useUserRoles(
    cachedRoles === undefined ? userId : null // Only fetch if not in cache
  )

  // Use cached roles if available, otherwise use fetched roles
  const roles = cachedRoles !== undefined ? cachedRoles : fetchedRoles

  if (isLoading && cachedRoles === undefined) {
    return <Skeleton className="h-6 w-20" />
  }

  if (!roles || roles.length === 0) {
    return (
      <span className="text-muted-foreground text-xs">
        {t('org.membersPage.noRoles', 'No roles')}
      </span>
    )
  }

  // Handle both MemberRBACRole (from context) and Role (from useUserRoles) types
  const displayRoles =
    cachedRoles !== undefined ? roles.map(memberRBACRoleToRole) : (roles as Role[])

  return (
    <div className="flex flex-wrap gap-1">
      {displayRoles.slice(0, 2).map((role) => (
        <Badge key={role.id} className={`${getRoleColor(role)} border-0 text-xs`}>
          {roleName(t, role)}
        </Badge>
      ))}
      {displayRoles.length > 2 && (
        <Badge variant="secondary" className="text-xs">
          +{displayRoles.length - 2}
        </Badge>
      )}
    </div>
  )
}

// Component to display user's roles with details (for sheet)
// Uses roles from MemberRolesContext - NO API call needed for viewing
// API call only happens when user clicks "Manage" to edit roles
function UserRolesDetailCard({
  userId,
  onManageRoles,
}: {
  userId: string
  onManageRoles?: () => void
}) {
  const { t } = useTranslation()
  const memberRolesMap = useContext(MemberRolesContext)
  const cachedRoles = memberRolesMap.get(userId)

  // Convert to display format
  const roles = cachedRoles?.map(memberRBACRoleToRole) || []

  return (
    <div className="rounded-xl border bg-card p-4">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-medium">
          {t('org.membersPage.assignedRoles', 'Assigned roles')}
        </h4>
        {onManageRoles && (
          <Can route="PUT /api/v1/users/{userId}/roles">
            <Button variant="ghost" onClick={onManageRoles}>
              <Pencil />
              {t('org.membersPage.manage', 'Manage')}
            </Button>
          </Can>
        )}
      </div>

      {roles.length === 0 ? (
        <div className="text-center py-4">
          <Shield className="h-8 w-8 mx-auto text-muted-foreground/30 mb-2" />
          <p className="text-sm text-muted-foreground">
            {t('org.membersPage.noRolesAssigned', 'No roles assigned')}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {roles.map((role) => (
            <div
              key={role.id}
              className="flex items-start gap-3 p-2 rounded-lg hover:bg-muted/50 transition-colors"
            >
              <div className={`p-1.5 rounded-lg ${getRoleColor(role)}`}>
                <Shield className="h-4 w-4" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="font-medium text-sm">{roleName(t, role)}</p>
                  {role.is_system && (
                    <span className="text-xs text-muted-foreground px-1.5 py-0.5 rounded bg-muted">
                      {t('org.membersPage.system', 'System')}
                    </span>
                  )}
                </div>
                {role.description && (
                  <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                    {role.description}
                  </p>
                )}
                {role.permission_count > 0 && (
                  <p className="text-xs text-muted-foreground mt-1">
                    {role.permission_count} permissions
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// The four team roles are the member's role in the organization. They change
// through the member's role on this page and ownership transfer; the roles
// dialog below edits custom roles only.
const isTeamRoleItem = (r: { slug: string; is_system: boolean }) =>
  r.is_system && ['owner', 'admin', 'member', 'viewer'].includes(r.slug)

// Dialog for editing user roles
function EditUserRolesDialog({
  member,
  open,
  onOpenChange,
  onSuccess,
  canGrantAdmin = false,
}: {
  member: MemberWithUser | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
  /** Only the owner may make someone an administrator (settings decision B2). */
  canGrantAdmin?: boolean
}) {
  // Only fetch data when dialog is actually open (avoid unnecessary API calls)
  const {
    roles: userRoles,
    isLoading: userRolesLoading,
    mutate: mutateUserRoles,
  } = useUserRoles(open ? member?.user_id || null : null)
  const { roles: everyRole, isLoading: allRolesLoading } = useRoles({ skip: !open })
  const { t } = useTranslation()
  const { currentTenant: dialogTenant } = useTenant()
  const { updateRole, isUpdating } = useUpdateMemberRole(dialogTenant?.slug, member?.id)
  // The team role changes through the membership (PATCH), the custom roles
  // through the roles API.
  const [teamRole, setTeamRole] = useState<MemberRole>('member')
  useEffect(() => {
    if (open && member) setTeamRole(member.role)
  }, [open, member])
  const teamRoleLocked = member?.role === 'owner'
  const allRoles = useMemo(() => everyRole.filter((r) => !isTeamRoleItem(r)), [everyRole])
  const { setUserRoles, isSetting } = useSetUserRoles(open ? member?.user_id || null : null)
  const [selectedRoleIds, setSelectedRoleIds] = useState<string[]>([])

  // Initialize selected roles ONCE per open session. The previous version
  // re-ran on every userRoles reference change, which meant any SWR
  // revalidate (e.g. after a tab focus or a manual mutate elsewhere)
  // silently wiped the user's in-progress checkbox toggles. Track init
  // with a ref and reset it when the dialog closes.
  const initialized = useRef(false)
  useEffect(() => {
    if (!open) {
      initialized.current = false
      return
    }
    const custom = userRoles.filter((r) => !isTeamRoleItem(r))
    if (!initialized.current && !userRolesLoading && custom.length > 0) {
      setSelectedRoleIds(custom.map((r) => r.id))
      initialized.current = true
    } else if (!initialized.current && !userRolesLoading) {
      // Loaded with empty result — still mark as initialized so we don't
      // overwrite an explicit "select nothing" state on re-render.
      setSelectedRoleIds([])
      initialized.current = true
    }
  }, [open, userRoles, userRolesLoading])

  // Widening access (a higher role in the organization, or custom roles added)
  // asks first; narrowing saves at once.
  const [confirmGrant, setConfirmGrant] = useState(false)
  const teamRoleRank: Record<string, number> = { viewer: 0, member: 1, admin: 2, owner: 3 }
  const teamRoleLabel = (r: string) =>
    r === 'admin'
      ? t('org.role.admin', 'Admin')
      : r === 'viewer'
        ? t('org.role.viewer', 'Viewer')
        : r === 'owner'
          ? t('org.role.owner', 'Owner')
          : t('org.role.member', 'Member')
  const promoted =
    !!member && !teamRoleLocked && (teamRoleRank[teamRole] ?? 0) > (teamRoleRank[member.role] ?? 0)
  const addedRoleNames = allRoles
    .filter((r) => selectedRoleIds.includes(r.id) && !userRoles.some((u) => u.id === r.id))
    .map((r) => r.name)
  const widens = promoted || addedRoleNames.length > 0

  const handleSave = async () => {
    if (widens && !confirmGrant) {
      setConfirmGrant(true)
      return
    }
    setConfirmGrant(false)
    try {
      if (member && !teamRoleLocked && teamRole !== member.role) {
        await updateRole({ role: teamRole })
      }
      await setUserRoles({ role_ids: selectedRoleIds })
      toast.success(t('org.membersPage.rolesUpdated', 'Roles updated'))
      mutateUserRoles()
      onSuccess?.()
      onOpenChange(false)
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('org.membersPage.rolesUpdateFailed', 'Failed to update roles'))
      )
    }
  }

  const isLoading = userRolesLoading || allRolesLoading

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('org.membersPage.manageRoles', 'Manage roles')}</DialogTitle>
          {member && <DialogDescription>{member.name}</DialogDescription>}
        </DialogHeader>

        <DialogBody>
          <div className="py-4">
            <div className="mb-4 space-y-1.5">
              <Label htmlFor="member-team-role">
                {t('org.roles.teamRole', 'Role in the organization')}
              </Label>
              {teamRoleLocked ? (
                <p className="text-sm text-muted-foreground">
                  {t(
                    'org.roles.ownerLocked',
                    'This person is the owner. Ownership moves with Transfer ownership.'
                  )}
                </p>
              ) : (
                <Select value={teamRole} onValueChange={(v) => setTeamRole(v as MemberRole)}>
                  <SelectTrigger id="member-team-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(canGrantAdmin || member?.role === 'admin') && (
                      <SelectItem
                        value="admin"
                        disabled={!canGrantAdmin && member?.role !== 'admin'}
                      >
                        {t('org.role.admin', 'Admin')}
                      </SelectItem>
                    )}
                    <SelectItem value="member">{t('org.role.member', 'Member')}</SelectItem>
                    <SelectItem value="viewer">{t('org.role.viewer', 'Viewer')}</SelectItem>
                  </SelectContent>
                </Select>
              )}
            </div>
            <p className="mb-3 text-xs text-muted-foreground">
              {t(
                'org.roles.manageNote',
                'Custom roles add permissions on top of the role in the organization.'
              )}
            </p>
            <RoleChecklist
              canGrantAdmin={canGrantAdmin}
              roles={allRoles}
              selected={selectedRoleIds}
              onChange={setSelectedRoleIds}
              loading={isLoading}
              disabled={isSetting || isUpdating}
            />
          </div>
        </DialogBody>

        <DialogFooter>
          <div className="flex-1 text-start">
            {selectedRoleIds.length > 0 && (
              <span className="text-xs text-muted-foreground">
                {selectedRoleIds.length} role{selectedRoleIds.length > 1 ? 's' : ''} selected
              </span>
            )}
          </div>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSetting}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={handleSave} disabled={isSetting || isUpdating || isLoading}>
            {isSetting ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <CheckCircle className="me-2 h-4 w-4" />
            )}
            {t('org.membersPage.saveChanges', 'Save changes')}
          </Button>
        </DialogFooter>
      </DialogContent>
      <ConfirmDialog
        open={confirmGrant}
        onOpenChange={setConfirmGrant}
        title={t('confirm.member.grantTitle', 'Give {name} more access?', {
          name: member?.name || member?.email || '',
        })}
        desc={
          <div className="space-y-2">
            {promoted && member && (
              <p>
                {t(
                  'confirm.member.grantRole',
                  'Role in the organization: {from} to {to}. They can do everything that role allows, in every project they can reach.',
                  { from: teamRoleLabel(member.role), to: teamRoleLabel(teamRole) }
                )}
              </p>
            )}
            {addedRoleNames.length > 0 && (
              <p>
                {t('confirm.member.grantCustom', 'Roles added: {roles}.', {
                  roles: addedRoleNames.join(', '),
                })}
              </p>
            )}
            <p>
              {t(
                'confirm.member.grantNote',
                'The change applies at once and is recorded in the audit log. You can remove the access again later.'
              )}
            </p>
          </div>
        }
        confirmText={t('confirm.member.grantConfirm', 'Give access')}
        handleConfirm={handleSave}
      />
    </Dialog>
  )
}

export default function UsersPage() {
  const { currentTenant } = useTenant()
  const tenantSlug = currentTenant?.slug
  // Peer administrators are the owner's to manage (the API answers 403 to
  // anyone else); their rows show the actions disabled, with the reason.
  const { isOwner, isAtLeast, canAny } = usePermissions()
  // Invitations are read only with members:invite or members:manage (useInvitations);
  // without them the page does not know the count, so it shows none.
  const canSeeInvitations = canAny(Permission.MembersInvite, Permission.MembersManage)
  // Same gate as the old <Can permission={MembersManage} minRole="admin">.
  const canManageMembers = useCanMutate('PATCH /api/v1/tenants/{tenant}/members/{userId}')
  const currentUser = useDisplayUser()
  const caller = { isOwner: isOwner(), userId: currentUser?.id }

  // Search and filters live in the URL so a filtered member list can be linked to.
  const [searchQuery, setSearchQueryParam] = useUrlFilter('q', '')
  const [statusParam, setStatusParam] = useUrlFilter('status', 'current')
  const [roleParam, setRoleParam] = useUrlFilter('role', 'all')
  const [kindParam, setKindParam] = useUrlFilter('kind', 'all')
  const kindFilter: KindFilter = kindFilters.some((f) => f.value === kindParam)
    ? (kindParam as KindFilter)
    : 'all'
  const statusFilter: StatusFilter = statusFilters.some((f) => f.value === statusParam)
    ? (statusParam as StatusFilter)
    : 'current'
  const roleFilter: RoleFilter = roleFilters.some((f) => f.value === roleParam)
    ? (roleParam as RoleFilter)
    : 'all'
  const debouncedSearch = useSearchQuery(searchQuery).term
  const [tabParam, setTabParam] = useUrlFilter('tab', 'members')

  // Paged, searched and filtered on the server. The list used to load one
  // capped page (100) and filter it in the browser, so every member past the
  // cap was unreachable (23a B20).
  const list = useListParams({ pageSizes: MEMBER_PAGE_SIZES })
  const { pagination, setPagination, setPage } = list
  const resetPage = useCallback(() => setPage(1), [setPage])
  const offset = (list.page - 1) * list.perPage
  const limit = list.perPage
  const setSearchQuery = (v: string) => {
    setSearchQueryParam(v)
    resetPage()
  }
  const setStatusFilter = (v: string) => {
    setStatusParam(v)
    resetPage()
  }
  const setRoleFilter = (v: string) => {
    setRoleParam(v)
    resetPage()
  }
  const setKindFilter = (v: string) => {
    setKindParam(v)
    resetPage()
  }

  // API Hooks - includeRoles: true to get RBAC roles in single API call (avoids N+1)
  const {
    members,
    total: membersTotal,
    isLoading: membersLoading,
    isError: membersError,
    mutate: mutateMembers,
  } = useMembers(tenantSlug, {
    includeRoles: true,
    search: debouncedSearch || undefined,
    status: statusFilter,
    role: roleFilter === 'all' ? undefined : roleFilter,
    kind: kindFilter === 'all' ? undefined : kindFilter,
    limit,
    offset,
  })
  // SSO exceptions (owners and admins see the security settings): a badge
  // on the members who may sign in without SSO.
  const { settings: tenantSettings } = useTenantSettings(
    canManageMembers ? currentTenant?.id : undefined
  )
  const ssoExceptionUntil = useMemo(() => {
    const map = new Map<string, string>()
    for (const e of tenantSettings?.security?.sso_exceptions ?? []) map.set(e.user_id, e.expires_at)
    return map
  }, [tenantSettings])
  const canChangeAccess = useCanMutate('PATCH /api/v1/organization/members/{member_id}/access')
  const [accessMember, setAccessMember] = useState<MemberWithUser | null>(null)
  // Organization-wide counts for the metric strip (not just this page).
  const { stats: memberStats, mutate: mutateMemberStats } = useMemberStats(tenantSlug)

  // Build roles map from members data for O(1) lookup in table cells
  const memberRolesMap = useMemo(() => {
    const map: MemberRolesMap = new Map()
    members.forEach((member) => {
      if (member.rbac_roles) {
        map.set(member.user_id, member.rbac_roles)
      }
    })
    return map
  }, [members])
  const { invitations: rawInvitations, mutate: mutateInvitations } = useInvitations(tenantSlug)

  // Filter out expired invitations (safety net - API should already filter)
  const invitations = useMemo(() => {
    const now = new Date()
    return rawInvitations.filter((inv) => new Date(inv.expires_at) > now)
  }, [rawInvitations])

  // UI State
  const [selectedMember, setSelectedMember] = useState<MemberWithUser | null>(null)
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false)
  // "Invite people" from the Create menu: the same gate as the Invite button.
  const canInvite = useCanMutate('POST /api/v1/tenants/{tenant}/invitations')
  const openInviteForm = useCallback(() => setInviteDialogOpen(true), [setInviteDialogOpen])
  useOpenForm('invite', canInvite, openInviteForm)
  const [addUserOpen, setAddUserOpen] = useState(false)
  const [setupLinkTarget, setSetupLinkTarget] = useState<SetupLinkTarget | null>(null)
  const [editRolesMember, setEditRolesMember] = useState<MemberWithUser | null>(null)
  const [editRolesDialogOpen, setEditRolesDialogOpen] = useState(false)
  // Track pending roles edit (used when transitioning from sheet to dialog)
  const [pendingRolesEdit, setPendingRolesEdit] = useState<MemberWithUser | null>(null)
  // Suspend confirmation: holds the member awaiting confirmation, plus an
  // in-flight flag so the action button can show a spinner and be disabled
  // while the request is pending.
  const [suspendConfirmMember, setSuspendConfirmMember] = useState<MemberWithUser | null>(null)
  const [isSuspending, setIsSuspending] = useState(false)
  // Reset-2FA confirmation: the member awaiting confirmation.
  const [resetMfaMember, setResetMfaMember] = useState<MemberWithUser | null>(null)
  const [pendingCancelInvite, setPendingCancelInvite] = useState<Invitation | null>(null)
  const [inviteLink, setInviteLink] = useState<{
    email: string
    url: string
    expiresAt: string
  } | null>(null)
  const emailUnavailable = useEmailUnavailable()
  const { t, locale } = useTranslation()
  // Invitation expiry is read against a clock in state (a minute is fine here).
  const now = useNow(60_000)
  const [isResettingMfa, setIsResettingMfa] = useState(false)
  // Offboarding wizard (RFC-050): the member being offboarded. Offboarding
  // strips every access source and asks for a new owner of their work.
  const [offboardMember, setOffboardMember] = useState<MemberWithUser | null>(null)
  // Erase personal data (owner only, offboarded members): confirmation.
  const [eraseConfirmMember, setEraseConfirmMember] = useState<MemberWithUser | null>(null)
  // Ownership transfer (RFC-095): the member the owner is asking, and the
  // open request the caller is part of (owner or member asked).
  const [transferMember, setTransferMember] = useState<MemberWithUser | null>(null)
  const { transfer: pendingTransfer, mutate: mutateTransfer } = usePendingOwnershipTransfer()
  const [isErasing, setIsErasing] = useState(false)
  const [reactivateMember, setReactivateMember] = useState<MemberWithUser | null>(null)

  // Track if sheet is fully closed (after animation completes)
  const [isSheetAnimating, setIsSheetAnimating] = useState(false)

  // Effect to open roles dialog after sheet closes with delay for animation
  useEffect(() => {
    if (pendingRolesEdit && !selectedMember) {
      setIsSheetAnimating(true)
      // Wait for sheet close animation to fully complete before opening dialog
      const timeoutId = setTimeout(() => {
        setIsSheetAnimating(false)
        setEditRolesMember(pendingRolesEdit)
        setEditRolesDialogOpen(true)
        setPendingRolesEdit(null)
      }, 400) // Allow extra time for sheet animation to fully complete

      return () => {
        clearTimeout(timeoutId)
        setIsSheetAnimating(false)
      }
    }
  }, [pendingRolesEdit, selectedMember])
  // Role names for the pending-invitations table (only fetched when there are any).
  const { roles: availableRolesForInvite } = useRoles({ skip: invitations.length === 0 })

  // Refresh all data
  const refreshData = useCallback(() => {
    if (tenantSlug) {
      mutateMembers()
      mutateMemberStats()
      mutateInvitations()
    }
  }, [tenantSlug, mutateMembers, mutateMemberStats, mutateInvitations])

  // Status counts from members (for the metric strip). Pending invitations are
  // listed in their own section below the table.
  const statusCounts: Record<StatusFilter, number> = useMemo(() => {
    // total_members leaves out the offboarded tombstones (RFC-050).
    const current = memberStats?.total_members ?? 0
    const active = memberStats?.active_members ?? 0
    const suspended = memberStats?.suspended_members ?? Math.max(0, current - active)
    const offboarded = memberStats?.offboarded_members ?? 0
    return { current, active, suspended, offboarded, all: current + offboarded }
  }, [memberStats])

  // A member's row menu: the table's last column and the phone card.
  const memberMenu = (member: MemberWithUser) => {
    const isOwnerRow = member.role === 'owner'
    const locked = isPeerAdminLocked(member, caller)
    const offboarded = member.status === 'offboarded'

    const name = member.name || member.email
    const lockReason = t('org.membersPage.peerAdminLock', PEER_ADMIN_LOCK_REASON)
    const memberRoute = 'PATCH /api/v1/tenants/{tenant}/members/{userId}' as const
    const actions: RowAction[] = [
      {
        label: t('org.membersPage.viewDetails', 'View details'),
        icon: Eye,
        onClick: () => setSelectedMember(member),
      },
    ]
    if (isOwnerRow && canManageMembers && canResetMemberMfa(member, caller)) {
      actions.push({
        label: t('org.membersPage.reset2fa', 'Reset 2FA'),
        icon: ShieldOff,
        onClick: () => setResetMfaMember(member),
        separatorBefore: true,
      })
    }
    if (!isOwnerRow && !offboarded && caller.isOwner) {
      actions.push({
        label: t('org.ownership.action', 'Transfer ownership...'),
        icon: Crown,
        onClick: () => setTransferMember(member),
        disabled: !!pendingTransfer,
        disabledReason: pendingTransfer
          ? t(
              'org.ownership.pendingReason',
              'A transfer is already waiting for an answer: cancel it first.'
            )
          : undefined,
        separatorBefore: true,
      })
    }
    if (!isOwnerRow && !offboarded && locked) {
      // The management actions of an administrator row, shown disabled
      // with the reason to a caller who is not the owner.
      actions.push(
        {
          label: t('org.membersPage.changeRoles', 'Change roles'),
          icon: Pencil,
          onClick: () => undefined,
          disabled: true,
          disabledReason: lockReason,
          separatorBefore: true,
          route: memberRoute,
        },
        ...(member.mfa_status === 'enabled'
          ? [
              {
                label: t('org.membersPage.reset2fa', 'Reset 2FA'),
                icon: ShieldOff,
                onClick: () => undefined,
                disabled: true,
                disabledReason: t('org.membersPage.resetMfaOwnerOnly', RESET_MFA_OWNER_REASON),
                route: memberRoute,
              },
            ]
          : []),
        {
          label: t('org.membersPage.disable', 'Disable'),
          icon: Ban,
          onClick: () => undefined,
          disabled: true,
          disabledReason: lockReason,
          route: memberRoute,
        },
        {
          label: t('org.membersPage.offboard', 'Offboard'),
          icon: UserMinus,
          onClick: () => undefined,
          disabled: true,
          disabledReason: lockReason,
          route: memberRoute,
        }
      )
    }
    if (!isOwnerRow && !locked) {
      actions.push({
        label: t('org.membersPage.changeRoles', 'Change roles'),
        icon: Pencil,
        onClick: () => {
          setEditRolesMember(member)
          setEditRolesDialogOpen(true)
        },
        route: 'PUT /api/v1/users/{userId}/roles',
      })
      if (member.kind === 'external' && canChangeAccess && !offboarded) {
        actions.push({
          label: t('org.membersPage.changeEndOfAccess', 'Change end of access'),
          icon: CalendarClock,
          onClick: () => setAccessMember(member),
          route: memberRoute,
        })
      }
      if (member.pending_setup) {
        actions.push({
          label: t('org.membersPage.getSetupLink', 'Get setup link'),
          icon: KeyRound,
          onClick: () =>
            setSetupLinkTarget({
              userId: member.user_id,
              email: member.email,
              name: member.name,
            }),
          route: memberRoute,
        })
      }
      // Access changes, each asking first, set apart from the edits above.
      const access: RowAction[] = []
      if (canResetMemberMfa(member, caller)) {
        access.push({
          label: t('org.membersPage.reset2fa', 'Reset 2FA'),
          icon: ShieldOff,
          onClick: () => setResetMfaMember(member),
          route: memberRoute,
        })
      }
      access.push(
        member.status === 'suspended'
          ? {
              label:
                member.suspended_reason === 'awaiting_approval'
                  ? t('org.membersPage.approve', 'Approve')
                  : t('org.membersPage.reenable', 'Re-enable'),
              icon: CheckCircle,
              onClick: () => setReactivateMember(member),
              route: memberRoute,
            }
          : {
              label: t('org.membersPage.disable', 'Disable'),
              icon: Ban,
              onClick: () => setSuspendConfirmMember(member),
              route: memberRoute,
            },
        {
          label: t('org.membersPage.offboardEllipsis', 'Offboard...'),
          icon: UserMinus,
          onClick: () => setOffboardMember(member),
          destructive: true,
          route: memberRoute,
        }
      )
      access[0].separatorBefore = true
      actions.push(...access)
    }
    if (!isOwnerRow && offboarded && caller.isOwner) {
      actions.push({
        label: t('org.membersPage.erasePersonalData', 'Erase personal data...'),
        icon: Eraser,
        onClick: () => setEraseConfirmMember(member),
        destructive: true,
        route: 'POST /api/v1/organization/members/{member_id}/erase',
      })
    }

    return (
      <DataTableRowActions
        actions={actions}
        title={name}
        label={t('common.rowActions.actionsFor', 'Actions for {name}', { name })}
      />
    )
  }

  // Table columns. The select-checkbox column was removed alongside the
  // bulk-actions dropdown — there's nothing to do with selected rows now.
  // hideBelow is the table frame width under which a column folds: the sum of the
  // columns still shown with it (name floor 200, roles 160, status 160, row menu 48,
  // two-factor 128, last active 112, joined 112) plus 60 of slack, so no header is cut.
  const columns: ColumnDef<MemberWithUser>[] = [
    {
      accessorKey: 'name',
      // The floor makes the name and e-mail shrink and cut instead of pushing
      // the Two-factor and row-actions columns out of the frame.
      meta: { kind: 'name', minWidth: 200, label: t('org.membersPage.col.user', 'User') },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.membersPage.col.user', 'User')} />
      ),
      cell: ({ row }) => (
        <div
          className={cn(
            'flex min-w-0 items-center gap-2',
            isDeactivated(row.original.status) && 'opacity-60'
          )}
        >
          <button
            type="button"
            className="min-w-0 shrink truncate text-start font-medium underline-offset-3 hover:underline focus-visible:underline focus-visible:outline-none"
            title={`${row.original.name} ${row.original.email}`}
            onClick={(e) => {
              e.stopPropagation()
              setSelectedMember(row.original)
            }}
          >
            {/* No name: the address, wrapping on a phone card only before
                its "@" (each part whole). */}
            {row.original.name || <BreakText>{row.original.email}</BreakText>}
          </button>
          {isDeactivated(row.original.status) && (
            <span className="shrink-0 text-cap text-muted-foreground">
              {t('org.membersPage.deactivated', '(deactivated)')}
            </span>
          )}
          <MemberBadges
            member={row.original}
            ssoExceptionUntil={ssoExceptionUntil.get(row.original.user_id)}
            className="shrink-0"
          />
          {/* Once: not under a name that is the address itself. One line with an ellipsis that gives
              way to the name first (shrinks four times faster); wrapping it beside a long name made
              a column of single letters and rows 90 px tall. The full address is in the name's title. */}
          {distinctAddress(row.original.name, row.original.email) && (
            <span className="min-w-0 shrink-[4] truncate text-cap text-muted-foreground">
              {row.original.email}
            </span>
          )}
        </div>
      ),
    },
    {
      accessorKey: 'role',
      meta: { kind: 'tags', label: t('org.membersPage.col.roles', 'Roles') },
      header: t('org.membersPage.col.roles', 'Roles'),
      enableSorting: false,
      cell: ({ row }) => {
        return <UserRolesCell userId={row.original.user_id} />
      },
    },
    {
      accessorKey: 'joined_at',
      meta: { kind: 'date', label: t('org.membersPage.col.joined', 'Joined'), hideBelow: 1000 },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.membersPage.col.joined', 'Joined')} />
      ),
      cell: ({ row }) => (
        <span className="text-muted-foreground text-sm">
          {formatDate(row.original.joined_at, locale)}
        </span>
      ),
    },
    {
      accessorKey: 'last_login_at',
      meta: {
        kind: 'date',
        label: t('org.membersPage.col.lastActive', 'Last active'),
        hideBelow: 880,
      },
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('org.membersPage.col.lastActive', 'Last active')}
        />
      ),
      cell: ({ row }) => (
        <span className="text-muted-foreground text-sm">
          {formatLastActive(t, locale, row.original.last_login_at)}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      meta: { kind: 'status', label: t('org.membersPage.col.status', 'Status'), width: 160 },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('org.membersPage.col.status', 'Status')} />
      ),
      cell: ({ row }) => {
        const reason =
          row.original.status === 'suspended'
            ? suspendedReasonText(row.original.suspended_reason)
            : ''
        return (
          <div className="flex flex-col items-start gap-0.5">
            <MemberStatusBadge
              status={row.original.status}
              pendingSetup={row.original.pending_setup}
            />
            {reason && <span className="text-muted-foreground text-xs">{reason}</span>}
          </div>
        )
      },
    },
    // Two-factor status: the API includes it for owners and admins only.
    ...(members.some((m) => m.mfa_status)
      ? [
          {
            id: 'mfa',
            meta: {
              kind: 'status',
              label: t('org.membersPage.col.twoFactor', 'Two-factor'),
              hideBelow: 770,
            },
            header: t('org.membersPage.col.twoFactor', 'Two-factor'),
            enableSorting: false,
            cell: ({ row }) => <MemberMfaBadge status={row.original.mfa_status} />,
          } satisfies ColumnDef<MemberWithUser>,
        ]
      : []),
    {
      id: 'actions',
      meta: { kind: 'actions', label: t('org.membersPage.col.actions', 'Actions') },
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => memberMenu(row.original),
    },
  ]

  // Restores a disabled member (or approves one awaiting approval).
  const handleReactivate = async (member: MemberWithUser) => {
    if (!tenantSlug) return
    try {
      await fetcherWithOptions(tenantEndpoints.reactivateMember(tenantSlug, member.id), {
        method: 'POST',
      })
      toast.success(
        member.suspended_reason === 'awaiting_approval'
          ? t('org.membersPage.approved', '{name} approved', { name: member.name || member.email })
          : t('org.membersPage.reenabled', '{name} re-enabled', {
              name: member.name || member.email,
            })
      )
      refreshData()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('org.membersPage.reenableFailed', 'Failed to re-enable member'))
      )
    } finally {
      setReactivateMember(null)
    }
  }

  // Actions
  // Erase an offboarded person's name and email (owner only). Rows and
  // history stay; they then show "Deleted user #...".
  const handleConfirmErase = async () => {
    if (!eraseConfirmMember) return
    setIsErasing(true)
    try {
      await eraseMemberPersonalData(eraseConfirmMember.id)
      toast.success(t('org.membersPage.erased', 'Personal data erased'))
      setEraseConfirmMember(null)
      refreshData()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('org.membersPage.eraseFailed', 'Failed to erase personal data'))
      )
    } finally {
      setIsErasing(false)
    }
  }

  // Confirm and execute the pending suspend. Called from the AlertDialog
  // action button — keeps suspension a deliberate two-click action.
  const handleConfirmSuspend = async () => {
    if (!tenantSlug || !suspendConfirmMember) return
    setIsSuspending(true)
    try {
      await fetcherWithOptions(tenantEndpoints.suspendMember(tenantSlug, suspendConfirmMember.id), {
        method: 'POST',
      })
      toast.success(
        t('org.membersPage.disabledToast', '{name} disabled', {
          name: suspendConfirmMember.name || suspendConfirmMember.email,
        })
      )
      setSuspendConfirmMember(null)
      refreshData()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('org.membersPage.disableFailed', 'Failed to disable member'))
      )
    } finally {
      setIsSuspending(false)
    }
  }

  // Confirm and execute the pending 2FA reset.
  const handleConfirmResetMfa = async () => {
    if (!resetMfaMember) return
    setIsResettingMfa(true)
    try {
      await fetcherWithOptions(tenantEndpoints.resetMemberMfa(resetMfaMember.id), {
        method: 'DELETE',
      })
      toast.success(
        t('org.membersPage.mfaResetToast', 'Two-factor authentication reset for {name}', {
          name: resetMfaMember.name || resetMfaMember.email,
        })
      )
      setResetMfaMember(null)
      refreshData()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('org.membersPage.mfaResetFailed', 'Failed to reset two-factor authentication')
        )
      )
    } finally {
      setIsResettingMfa(false)
    }
  }

  // Pending invitations table. Actions are the per-row menu like every other list.
  type Invitation = (typeof invitations)[number]
  const resendInvite = async (invitation: Invitation) => {
    if (!tenantSlug) return
    try {
      await fetcherWithOptions(tenantEndpoints.resendInvitation(tenantSlug, invitation.id), {
        method: 'POST',
      })
      toast.success(t('org.invitations.resent'))
      mutateInvitations()
    } catch (err) {
      toast.error(
        err instanceof ApiClientError && err.code === 'INVITATION_RESEND_TOO_SOON'
          ? t('org.invitations.resendTooSoon')
          : t('org.invitations.resendFailed')
      )
    }
  }
  // A new link without email: the token rotates (the old link stops working)
  // and the API returns the new one once. Renew does the same for an expired
  // invitation and gives it a new lifetime.
  const reissueInviteLink = async (invitation: Invitation, renew: boolean) => {
    if (!tenantSlug) return
    try {
      const res = await fetcherWithOptions<{ token: string; invitation: Invitation }>(
        renew
          ? tenantEndpoints.renewInvitation(tenantSlug, invitation.id)
          : tenantEndpoints.invitationLink(tenantSlug, invitation.id),
        { method: 'POST' }
      )
      setInviteLink({
        email: invitation.email,
        url: buildInvitationLink(res.token),
        expiresAt: res.invitation.expires_at,
      })
      mutateInvitations()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('org.invitations.linkFailed', 'Could not issue a new invitation link')
        )
      )
    }
  }
  const cancelInvite = async (invitation: Invitation) => {
    if (!tenantSlug) return
    try {
      await fetcherWithOptions(tenantEndpoints.deleteInvitation(tenantSlug, invitation.id), {
        method: 'DELETE',
      })
      toast.success(t('org.membersPage.inviteCancelled', 'Invitation cancelled'))
      setPendingCancelInvite(null)
      refreshData()
    } catch {
      toast.error(t('org.membersPage.inviteCancelFailed', 'Failed to cancel invitation'))
    }
  }

  // An invitation's row menu: the table's last column and the phone card.
  const invitationMenu = (inv: Invitation) => (
    <DataTableRowActions
      title={inv.email}
      label={t('common.rowActions.actionsFor', 'Actions for {name}', {
        name: inv.email,
      })}
      actions={[
        ...(new Date(inv.expires_at).getTime() <= now
          ? [
              {
                label: t('org.membersPage.renewInvitation', 'Renew'),
                icon: RotateCw,
                route: 'POST /api/v1/tenants/{tenant}/invitations/{invitationId}/renew' as const,
                onClick: () => reissueInviteLink(inv, true),
              },
            ]
          : [
              {
                label: t('org.membersPage.copyNewLink', 'Copy new link'),
                icon: LinkIcon,
                route: 'POST /api/v1/tenants/{tenant}/invitations/{invitationId}/link' as const,
                onClick: () => reissueInviteLink(inv, false),
              },
            ]),
        // The email actions only make sense on a server that sends email.
        ...(emailUnavailable
          ? []
          : [
              {
                label: t('org.membersPage.resendEmail', 'Resend email'),
                icon: Send,
                route: 'POST /api/v1/tenants/{tenant}/invitations/{invitationId}/resend' as const,
                onClick: () => resendInvite(inv),
              },
            ]),
        {
          label: t('org.membersPage.cancelInvitation', 'Cancel invitation'),
          icon: Trash2,
          destructive: true,
          separatorBefore: true,
          route: 'DELETE /api/v1/tenants/{tenant}/invitations/{invitationId}' as const,
          onClick: () => setPendingCancelInvite(inv),
        },
      ]}
    />
  )

  // The parts of an invitation row, shared by the table and the phone card.
  const invitationBadges = (inv: Invitation) => (
    <>
      {inv.member_kind === 'external' && (
        <Badge variant="outline" className="text-xs" data-testid="invitation-badge-external">
          {t('org.invitations.external')}
        </Badge>
      )}
      {inv.privileged && (
        <Badge
          variant="outline"
          className="border-warning/50 text-xs text-warning"
          data-testid="invitation-badge-mfa"
          title={t('org.invitations.mfaHint')}
        >
          {t('org.invitations.mfa')}
        </Badge>
      )}
    </>
  )

  const invitationRoles = (invitation: Invitation) => {
    // Role names from role_ids (resolved when the role list is loaded).
    const invitedRoles = (invitation.role_ids || [])
      .map((id) => availableRolesForInvite.find((r) => r.id === id))
      .filter((r): r is NonNullable<typeof r> => r != null)
    if (invitedRoles.length > 0) {
      return (
        <div className="flex flex-wrap items-center gap-1">
          {invitedRoles.slice(0, 2).map((role) => (
            <Badge key={role.id} className={`${getRoleColor(role)} border-0 text-xs`}>
              {roleName(t, role)}
            </Badge>
          ))}
          {invitedRoles.length > 2 && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge variant="secondary" className="text-xs cursor-pointer">
                  +{invitedRoles.length - 2}
                </Badge>
              </TooltipTrigger>
              <TooltipContent>
                {invitedRoles
                  .slice(2)
                  .map((r) => roleName(t, r))
                  .join(', ')}
              </TooltipContent>
            </Tooltip>
          )}
        </div>
      )
    }
    /* Invitations created before the RBAC role picker carry only the
       legacy `role` field ("member", "admin", ...) with empty role_ids —
       show that (in the console language) rather than a confusing "No roles". */
    return (
      <Badge variant="secondary" className="text-xs">
        {invitation.role
          ? roleDisplayName(t, { slug: invitation.role, name: invitation.role, is_system: true })
          : t('org.membersPage.noRoles', 'No roles')}
      </Badge>
    )
  }

  /** When the invitation runs out; `labelled` adds "Expires" for the phone card. */
  const invitationExpiry = (inv: Invitation, labelled = false) => {
    const daysUntilExpiry = Math.ceil(
      (new Date(inv.expires_at).getTime() - now) / (1000 * 60 * 60 * 24)
    )
    const isExpiringSoon = daysUntilExpiry <= 3 && daysUntilExpiry > 0
    const isExpired = daysUntilExpiry <= 0
    const date = formatDate(inv.expires_at, locale)
    return (
      <span
        className={`text-sm ${isExpired || isExpiringSoon ? 'text-destructive' : 'text-muted-foreground'}`}
      >
        {isExpired
          ? t('org.membersPage.expired', 'Expired')
          : isExpiringSoon
            ? daysUntilExpiry > 1
              ? t('org.membersPage.expiresInOther', 'In {count} days', {
                  count: daysUntilExpiry,
                })
              : t('org.membersPage.expiresInOne', 'In {count} day', { count: daysUntilExpiry })
            : labelled
              ? t('org.membersPage.expiresOn', 'Expires {date}', { date })
              : date}
      </span>
    )
  }

  const invitationColumns: ColumnDef<Invitation>[] = [
    {
      accessorKey: 'email',
      meta: { kind: 'name', label: t('org.membersPage.col.email', 'Email') },
      header: t('org.membersPage.col.email', 'Email'),
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex min-w-0 flex-wrap items-center gap-1.5">
          <span className="font-medium">
            <BreakText>{row.original.email}</BreakText>
          </span>
          {invitationBadges(row.original)}
        </div>
      ),
    },
    {
      id: 'roles',
      meta: { kind: 'tags', label: t('org.membersPage.col.roles', 'Roles') },
      header: t('org.membersPage.col.roles', 'Roles'),
      enableSorting: false,
      cell: ({ row }) => invitationRoles(row.original),
    },
    {
      accessorKey: 'expires_at',
      meta: { kind: 'date', label: t('org.membersPage.col.expires', 'Expires') },
      header: t('org.membersPage.col.expires', 'Expires'),
      enableSorting: false,
      cell: ({ row }) => invitationExpiry(row.original),
    },
    {
      id: 'actions',
      meta: { kind: 'actions', label: t('org.membersPage.col.actions', 'Actions') },
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => invitationMenu(row.original),
    },
  ]

  // The organization-wide counts (the old metric strip) ride on the Status options.
  const withCount = (label: string, count: number | undefined) =>
    memberStats && count !== undefined
      ? t('org.membersPage.filter.withCount', '{label} ({count})', { label, count })
      : label

  // Join requests: the same read the card makes (one request, shared), for the tab count.
  const canManageRequests = isAtLeast('admin')
  const { requests: joinRequests } = useJoinRequests(canManageRequests)
  const tabs: MemberTab[] = [
    'members',
    ...(canSeeInvitations ? (['invitations'] as const) : []),
    ...(canManageRequests ? (['requests'] as const) : []),
  ]
  const activeTab: MemberTab = tabs.includes(tabParam as MemberTab)
    ? (tabParam as MemberTab)
    : 'members'

  // The list filters are the shared filter token (research/249 R21): it
  // reads "Status: Current members" at its natural width instead of a
  // fixed-width select that cuts the value off.
  const toolbarStart = (
    <>
      <FilterSelect
        label={t('org.membersPage.filter.status', 'Status')}
        value={statusFilter}
        allValue="current"
        allLabel={t('org.membersPage.filter.current', 'Current members')}
        options={statusFilters
          .filter((f) => f.value !== 'current')
          .map((f) => ({
            value: f.value,
            label: withCount(
              t(f.key, f.en),
              f.value === 'all' ? statusCounts.all : statusCounts[f.value]
            ),
          }))}
        onChange={(v) => setStatusFilter(v || 'current')}
      />
      <FilterSelect
        label={t('org.membersPage.filter.kind', 'Membership')}
        value={kindFilter}
        allValue="all"
        allLabel={t('org.membersPage.filter.everyone', 'Everyone')}
        options={kindFilters
          .filter((f) => f.value !== 'all')
          .map((f) => ({ value: f.value, label: t(f.key, f.en) }))}
        onChange={(v) => setKindFilter(v || 'all')}
      />
      <FilterSelect
        label={t('org.membersPage.filter.role', 'Role')}
        value={roleFilter}
        allValue="all"
        allLabel={t('org.membersPage.filter.allRoles', 'All roles')}
        options={roleFilters
          .filter((f) => f.value !== 'all')
          .map((f) => ({ value: f.value, label: t(f.key, f.en) }))}
        onChange={(v) => setRoleFilter(v || 'all')}
      />
    </>
  )

  return (
    <MemberRolesContext.Provider value={memberRolesMap}>
      <SettingsPage
        wide
        title={t('org.membersPage.title', 'Members')}
        description={t(
          'org.membersPage.description',
          'People in this organization, their roles and pending invitations.'
        )}
        actions={
          <>
            {/* Accounts are created by owners/admins (no self-registration);
              inviting someone who already has an account stays available. */}
            <Can route="POST /api/v1/tenants/{tenant}/users" mode="disable">
              <Button variant="outline" onClick={() => setAddUserOpen(true)}>
                <UserPlus aria-hidden />
                {t('org.membersPage.addUser', 'Add user')}
              </Button>
            </Can>
            <Can route="POST /api/v1/tenants/{tenant}/invitations" mode="disable">
              <Button onClick={() => setInviteDialogOpen(true)}>
                <Send aria-hidden />
                {t('org.membersPage.inviteUser', 'Invite user')}
              </Button>
            </Can>
          </>
        }
        banners={
          <OwnershipTransferBanner
            transfer={pendingTransfer}
            onChanged={() => {
              void mutateTransfer()
              refreshData()
            }}
          />
        }
      >
        <Tabs
          value={activeTab}
          onValueChange={(v) => setTabParam(v === 'members' ? '' : v)}
          className="gap-section"
        >
          {tabs.length > 1 && (
            <TabsList aria-label={t('org.membersPage.tabs.label', 'Member lists')}>
              <TabsTrigger value="members">
                {t('org.membersPage.tabs.members', 'Current members')}
                <TabsCount value={memberStats ? statusCounts.current : null} />
              </TabsTrigger>
              {canSeeInvitations && (
                <TabsTrigger value="invitations">
                  {t('org.membersPage.metric.pendingInvites', 'Pending invitations')}
                  <TabsCount value={invitations.length} />
                </TabsTrigger>
              )}
              {canManageRequests && (
                <TabsTrigger value="requests">
                  {t('org.membersPage.tabs.requests', 'Requests to join')}
                  <TabsCount value={joinRequests.length} />
                </TabsTrigger>
              )}
            </TabsList>
          )}

          <TabsContent value="members">
            {membersError && !membersLoading ? (
              <Alert variant="destructive">
                <AlertCircle aria-hidden />
                <AlertTitle>
                  {t('org.membersPage.loadFailedTitle', 'Failed to load members')}
                </AlertTitle>
                <AlertDescription>
                  <p>
                    {t('org.membersPage.loadFailedBody', 'The member list could not be loaded.')}
                  </p>
                  <Button variant="outline" className="mt-2" onClick={refreshData}>
                    <RefreshCw aria-hidden />
                    {t('common.retry', 'Retry')}
                  </Button>
                </AlertDescription>
              </Alert>
            ) : membersLoading ? (
              <div className="space-y-2" aria-busy="true">
                <Skeleton className="h-8 w-full max-w-sm" />
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : (
              /*
                No selection column: the old bulk "Resend / Deactivate /
                Delete" actions fired toasts without calling any API. Per-row
                actions are the supported way to disable / offboard a member.
              */
              <DataTable
                columns={columns}
                data={members}
                // When the table still scrolls sideways the row menu stays in view.
                pinActions
                getRowId={(m) => m.id}
                manualPagination
                rowCount={membersTotal}
                pagination={pagination}
                onPaginationChange={setPagination}
                pageSizeOptions={MEMBER_PAGE_SIZES}
                paginationNoun={t('org.membersPage.noun', 'members')}
                showSearch={false}
                search={{
                  value: searchQuery,
                  onChange: setSearchQuery,
                  placeholder: t('org.membersPage.searchPlaceholder', 'Search members…'),
                  label: t('org.membersPage.searchLabel', 'Search members'),
                }}
                toolbarStart={toolbarStart}
                onRowClick={(m) => setSelectedMember(m)}
                mobileRow={(m) => (
                  <PersonPhoneCard
                    title={m.name || m.email}
                    address={distinctAddress(m.name, m.email)}
                    dimmed={isDeactivated(m.status)}
                    onOpen={() => setSelectedMember(m)}
                    menu={memberMenu(m)}
                    facts={
                      <>
                        <UserRolesCell userId={m.user_id} />
                        <MemberStatusBadge status={m.status} pendingSetup={m.pending_setup} />
                        {m.mfa_status ? <MemberMfaBadge status={m.mfa_status} labelled /> : null}
                        <MemberBadges
                          member={m}
                          ssoExceptionUntil={ssoExceptionUntil.get(m.user_id)}
                        />
                      </>
                    }
                  />
                )}
                emptyMessage={t('org.membersPage.noMatch', 'No members match these filters')}
              />
            )}
          </TabsContent>

          {canSeeInvitations && (
            <TabsContent value="invitations" className="flex flex-col gap-section">
              {emailUnavailable && (
                <Alert>
                  <Info aria-hidden />
                  <AlertTitle>
                    {t('org.membersPage.noEmailTitle', 'This server cannot send email')}
                  </AlertTitle>
                  <AlertDescription>
                    {t(
                      'org.membersPage.noEmailBody',
                      'Invitation emails are not sent. Copy each invitation link and give it to the person yourself.'
                    )}
                  </AlertDescription>
                </Alert>
              )}
              <DataTable
                columns={invitationColumns}
                data={invitations}
                getRowId={(inv) => inv.id}
                showSearch={false}
                showColumnToggle={false}
                showPagination={invitations.length > 10}
                mobileRow={(inv) => (
                  <PersonPhoneCard
                    title={inv.email}
                    menu={invitationMenu(inv)}
                    facts={
                      <>
                        {invitationRoles(inv)}
                        {invitationExpiry(inv, true)}
                        {invitationBadges(inv)}
                      </>
                    }
                  />
                )}
                emptyMessage={t('org.membersPage.noInvites', 'No pending invitations')}
              />
            </TabsContent>
          )}

          {canManageRequests && (
            <TabsContent value="requests">
              {joinRequests.length === 0 ? (
                <p className="text-body text-muted-foreground">
                  {t('org.membersPage.noRequests', 'Nobody is waiting to join.')}
                </p>
              ) : (
                <JoinRequestsCard canManage={canManageRequests} onChanged={refreshData} />
              )}
            </TabsContent>
          )}
        </Tabs>
      </SettingsPage>

      {/* User Details Sheet */}
      {selectedMember &&
        (() => {
          const member = selectedMember
          const isOwnerRow = member.role === 'owner'
          const locked = !isOwnerRow && isPeerAdminLocked(member, caller)
          const canOffboard =
            canManageMembers && !isOwnerRow && !locked && member.status !== 'offboarded'
          return (
            <DetailSheet
              open
              onOpenChange={(open) => !open && setSelectedMember(null)}
              width="md"
              header={
                <DetailHeader
                  title={member.name}
                  badges={
                    <>
                      <MemberStatusBadge
                        status={member.status}
                        pendingSetup={member.pending_setup}
                      />
                      <MemberBadges
                        member={member}
                        ssoExceptionUntil={ssoExceptionUntil.get(member.user_id)}
                      />
                    </>
                  }
                  meta={[member.email]}
                  menu={[
                    {
                      label: t('org.membersPage.copyId', 'Copy member ID'),
                      icon: Copy,
                      onSelect: () => {
                        copyToClipboard(member.id)
                        toast.success(t('org.membersPage.idCopied', 'Member ID copied'))
                      },
                    },
                    ...(canOffboard
                      ? [
                          {
                            label: t('org.membersPage.offboardEllipsis', 'Offboard...'),
                            icon: UserMinus,
                            destructive: true,
                            separatorBefore: true,
                            // Close the drawer first: the wizard is a dialog
                            // with its own overlay.
                            onSelect: () => {
                              setOffboardMember(member)
                              setSelectedMember(null)
                            },
                          },
                        ]
                      : []),
                  ]}
                  onClose={() => setSelectedMember(null)}
                />
              }
            >
              <div className="space-y-5">
                {canManageMembers && locked && (
                  <DetailCallout
                    tone="info"
                    icon={Lock}
                    title={t('org.membersPage.managedByOwner', 'Managed by the owner')}
                  >
                    {t('org.membersPage.peerAdminLock', PEER_ADMIN_LOCK_REASON)}
                  </DetailCallout>
                )}

                <DetailStatGrid aria-label={t('org.membersPage.keyDates', 'Key dates')}>
                  <DetailStat
                    label={t('org.membersPage.col.joined', 'Joined')}
                    value={formatDate(member.joined_at, locale)}
                  />
                  <DetailStat
                    label={t('org.membersPage.col.lastActive', 'Last active')}
                    value={formatLastActive(t, locale, member.last_login_at)}
                  />
                </DetailStatGrid>

                <UserRolesDetailCard
                  userId={member.user_id}
                  onManageRoles={
                    !isOwnerRow && !locked
                      ? () => {
                          // Set pending edit and close the drawer; an effect opens the dialog.
                          setPendingRolesEdit(member)
                          setSelectedMember(null)
                        }
                      : undefined
                  }
                />

                {canManageMembers && <MemberAccessPanel memberId={member.id} />}

                <DetailFieldGrid>
                  <DetailField label={t('org.membersPage.memberId', 'Member ID')} full>
                    <DetailCopyId
                      id={member.id}
                      label={t('org.membersPage.memberId', 'Member ID')}
                    />
                  </DetailField>
                </DetailFieldGrid>
              </div>
            </DetailSheet>
          )
        })()}

      <MemberAccessDialog
        member={accessMember}
        onOpenChange={(open) => !open && setAccessMember(null)}
        onSaved={refreshData}
      />
      <OneTimeLinkDialog
        open={!!inviteLink}
        onOpenChange={(open) => {
          if (!open) setInviteLink(null)
        }}
        title={t('org.invitations.linkTitle', 'Invitation link')}
        description={t(
          'org.invitations.linkDesc',
          'A new link for {email}. The previous link no longer works.',
          {
            email: inviteLink?.email ?? '',
          }
        )}
        link={inviteLink?.url ?? ''}
        expiresAt={inviteLink?.expiresAt}
      />
      <InviteUserDialog
        tenantSlug={tenantSlug}
        open={inviteDialogOpen}
        onOpenChange={setInviteDialogOpen}
        onInvited={refreshData}
        canGrantAdmin={caller.isOwner}
      />

      <AddUserDialog
        tenantSlug={tenantSlug}
        open={addUserOpen}
        onOpenChange={setAddUserOpen}
        onCreated={refreshData}
        canGrantAdmin={caller.isOwner}
      />

      <SetupLinkDialog
        target={setupLinkTarget}
        onOpenChange={(open) => {
          if (!open) setSetupLinkTarget(null)
        }}
        issue={(userId) => {
          if (!tenantSlug) return Promise.reject(new Error('No organization selected'))
          return issueSetupLink(tenantSlug, userId)
        }}
      />

      {/* Edit User Roles Dialog - Prevent overlap with sheet animation */}
      {!isSheetAnimating && (
        <EditUserRolesDialog
          member={editRolesMember}
          open={editRolesDialogOpen && !selectedMember}
          onOpenChange={(open) => {
            setEditRolesDialogOpen(open)
            if (!open) setEditRolesMember(null)
          }}
          onSuccess={refreshData}
          canGrantAdmin={caller.isOwner}
        />
      )}

      {/* Reset 2FA Confirmation Dialog */}
      <ConfirmDialog
        open={!!resetMfaMember}
        onOpenChange={(open) => {
          if (!open && !isResettingMfa) setResetMfaMember(null)
        }}
        destructive
        title={t('confirm.member.resetMfaTitle', 'Reset two-factor authentication for {name}?', {
          name: resetMfaMember ? resetMfaMember.name || resetMfaMember.email : '',
        })}
        desc={t(
          'confirm.member.resetMfaDesc',
          'They are signed out everywhere and can sign in with their password alone until they set up two-factor authentication again (required at their next sign-in if this organization requires it). Use this only after confirming their identity. They are notified by email, and the reset is recorded in the audit log.'
        )}
        confirmText={
          isResettingMfa ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.member.resettingMfa', 'Resetting…')}
            </>
          ) : (
            <>
              <ShieldOff className="me-2 h-4 w-4" />
              {t('confirm.member.resetMfa', 'Reset 2FA')}
            </>
          )
        }
        isLoading={isResettingMfa}
        handleConfirm={() => handleConfirmResetMfa()}
      />

      {/* Suspend Member Confirmation Dialog */}
      <ConfirmDialog
        open={!!suspendConfirmMember}
        onOpenChange={(open) => {
          if (!open && !isSuspending) setSuspendConfirmMember(null)
        }}
        destructive
        title={t('confirm.member.disableTitle', 'Disable {name}?', {
          name: suspendConfirmMember ? suspendConfirmMember.name || suspendConfirmMember.email : '',
        })}
        desc={t(
          'confirm.member.disableDesc',
          'They lose access at once: sessions end, API keys are suspended, and the scans, report schedules and workflows they own are paused. Their access groups, grants and ownership are kept, so you can re-enable them later. To end access for good, offboard them instead.'
        )}
        confirmText={
          isSuspending ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.disabling', 'Disabling…')}
            </>
          ) : (
            <>
              <Ban className="me-2 h-4 w-4" />
              {t('confirm.disable', 'Disable')}
            </>
          )
        }
        isLoading={isSuspending}
        handleConfirm={() => handleConfirmSuspend()}
      />

      {/* Cancel invitation: the link in the email stops working. */}
      <ConfirmDialog
        open={!!pendingCancelInvite}
        onOpenChange={(open) => !open && setPendingCancelInvite(null)}
        destructive
        title={t('confirm.member.cancelInviteTitle', 'Cancel the invitation to {email}?', {
          email: pendingCancelInvite?.email ?? '',
        })}
        desc={t(
          'confirm.member.cancelInviteDesc',
          'The link in the invitation email stops working. You can invite this address again later.'
        )}
        cancelBtnText={t('confirm.member.keepInvite', 'Keep invitation')}
        confirmText={t('confirm.member.cancelInvite', 'Cancel invitation')}
        handleConfirm={() => (pendingCancelInvite ? cancelInvite(pendingCancelInvite) : undefined)}
      />

      {/* Offboarding wizard (RFC-050) */}
      <TransferOwnershipDialog
        member={transferMember}
        onOpenChange={(open) => {
          if (!open) setTransferMember(null)
        }}
        onStarted={() => void mutateTransfer()}
      />

      <OffboardMemberDialog
        tenantSlug={tenantSlug}
        member={offboardMember}
        onOpenChange={(open) => {
          if (!open) setOffboardMember(null)
        }}
        onOffboarded={refreshData}
      />

      {/* Re-enable or approve a member: restores their access */}
      <ConfirmDialog
        open={!!reactivateMember}
        onOpenChange={(open) => !open && setReactivateMember(null)}
        title={
          reactivateMember?.suspended_reason === 'awaiting_approval'
            ? t('confirm.member.approveTitle', 'Approve {name}?', {
                name: reactivateMember?.name || reactivateMember?.email || '',
              })
            : t('confirm.member.reenableTitle', 'Re-enable {name}?', {
                name: reactivateMember?.name || reactivateMember?.email || '',
              })
        }
        desc={t(
          'confirm.member.reenableDesc',
          'They can sign in again and use what their roles allow. Their schedules and scans resume.'
        )}
        confirmText={
          reactivateMember?.suspended_reason === 'awaiting_approval'
            ? t('confirm.member.approveConfirm', 'Approve member')
            : t('confirm.member.reenableConfirm', 'Re-enable member')
        }
        handleConfirm={() => (reactivateMember ? handleReactivate(reactivateMember) : undefined)}
      />

      {/* Erase personal data confirmation (owner only, offboarded members) */}
      <ConfirmDialog
        open={!!eraseConfirmMember}
        onOpenChange={(open) => {
          if (!open && !isErasing) setEraseConfirmMember(null)
        }}
        title={t('confirm.member.eraseTitle', 'Erase the personal data of {name}?', {
          name: eraseConfirmMember ? eraseConfirmMember.name || eraseConfirmMember.email : '',
        })}
        desc={t(
          'confirm.member.eraseDesc',
          'Their name and email are replaced with an anonymous label everywhere, and their credentials are cleared. Findings, comments and audit history stay, attributed to the anonymous label. This cannot be undone.'
        )}
        confirmText={
          isErasing ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.member.erasing', 'Erasing…')}
            </>
          ) : (
            <>
              <Eraser className="me-2 h-4 w-4" />
              {t('confirm.member.erase', 'Erase')}
            </>
          )
        }
        destructive
        isLoading={isErasing}
        typeToConfirm={eraseConfirmMember?.email || undefined}
        handleConfirm={() => void handleConfirmErase()}
      />
    </MemberRolesContext.Provider>
  )
}
