'use client'

import { useState, useMemo, useCallback, useEffect, useRef } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  DisabledMenuItem,
  MetricStrip,
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
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import {
  UserPlus,
  Shield,
  CheckCircle,
  MoreHorizontal,
  Trash2,
  Send,
  Ban,
  Search as SearchIcon,
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
} from 'lucide-react'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useUrlPagination } from '@/hooks/use-url-pagination'
import { useDebounce } from '@/hooks/use-debounce'
import { useTenant } from '@/context/tenant-provider'
import {
  useMembers,
  useMemberStats,
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
import { useUserRoles, useRoles, useSetUserRoles, type Role } from '@/features/access-control'
import { createContext, useContext } from 'react'

// Context to pass member roles without N+1 API calls
type MemberRolesMap = Map<string, MemberRBACRole[]>
const MemberRolesContext = createContext<MemberRolesMap>(new Map())
import { fetcherWithOptions } from '@/lib/api/client'
import { tenantEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, usePermissions, useCanMutate } from '@/lib/permissions'
import { useUser } from '@/stores/auth-store'
import { MemberMfaBadge } from '@/features/organization/components/member-mfa-badge'

/**
 * The management actions of an administrator row, disabled for a caller who
 * is not the owner, each explaining why on hover or focus.
 */
function PeerAdminLockedItems({ mfaEnabled }: { mfaEnabled: boolean }) {
  return (
    <>
      <DropdownMenuSeparator />
      <DisabledMenuItem label="Change roles" icon={Pencil} reason={PEER_ADMIN_LOCK_REASON} />
      {mfaEnabled && (
        <DisabledMenuItem label="Reset 2FA" icon={ShieldOff} reason={RESET_MFA_OWNER_REASON} />
      )}
      <DisabledMenuItem label="Disable" icon={Ban} reason={PEER_ADMIN_LOCK_REASON} />
      <DisabledMenuItem label="Offboard" icon={UserMinus} reason={PEER_ADMIN_LOCK_REASON} />
    </>
  )
}

// Tab values for the status filter on the members table (RFC-050 member
// lifecycle). "current" (the default) is active + disabled; offboarded
// members are the tombstones of people who left, listed only on request.
// Pending invitations live in their own section, so they are NOT a tab here.
type StatusFilter = 'current' | 'active' | 'suspended' | 'offboarded' | 'all'
type RoleFilter = 'all' | MemberRole

// Static config
const MEMBER_PAGE_SIZES = [10, 20, 50, 100]

const statusFilters: { value: StatusFilter; label: string }[] = [
  { value: 'current', label: 'Current members' },
  { value: 'active', label: 'Active' },
  { value: 'suspended', label: 'Disabled' },
  { value: 'offboarded', label: 'Offboarded' },
  { value: 'all', label: 'Everyone' },
]

const roleFilters: { value: RoleFilter; label: string }[] = [
  { value: 'all', label: 'All roles' },
  { value: 'owner', label: 'Owner' },
  { value: 'admin', label: 'Admin' },
  { value: 'member', label: 'Member' },
  { value: 'viewer', label: 'Viewer' },
]

// Helper functions
const getInitials = (name: string) => {
  return name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

const formatLastActive = (lastLoginAt?: string) => {
  if (!lastLoginAt) return 'Never'
  const date = new Date(lastLoginAt)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins} mins ago`
  if (diffHours < 24) return `${diffHours} hours ago`
  if (diffDays < 7) return `${diffDays} days ago`
  return formatDate(lastLoginAt)
}

// Role chips are neutral: a role is a label, not a state, so it gets no colour of
// its own (the old per-role palette read as severity and broke in dark mode).
const getRoleColor = (role: Role) =>
  role.is_system ? 'bg-secondary text-secondary-foreground' : 'bg-muted text-foreground'

const MEMBER_STATUS_LABEL: Record<string, string> = {
  active: 'Active',
  suspended: 'Disabled',
  offboarded: 'Offboarded',
}

function MemberStatusBadge({ status, pendingSetup }: { status: string; pendingSetup?: boolean }) {
  // An admin-created account whose password is not set yet: the membership is
  // active, but the person cannot sign in until they use their setup link.
  if (pendingSetup && status !== 'suspended') return <PendingSetupBadge />
  const label =
    MEMBER_STATUS_LABEL[status] ??
    STATUS_DISPLAY[status as keyof typeof STATUS_DISPLAY]?.label ??
    status
  return (
    <Badge
      variant={status === 'active' ? 'secondary' : 'outline'}
      className={
        status === 'suspended'
          ? 'border-destructive/40 text-destructive'
          : status === 'offboarded'
            ? 'text-muted-foreground'
            : undefined
      }
    >
      {label}
    </Badge>
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
    return <span className="text-muted-foreground text-xs">No roles</span>
  }

  // Handle both MemberRBACRole (from context) and Role (from useUserRoles) types
  const displayRoles =
    cachedRoles !== undefined ? roles.map(memberRBACRoleToRole) : (roles as Role[])

  return (
    <div className="flex flex-wrap gap-1">
      {displayRoles.slice(0, 2).map((role) => (
        <Badge key={role.id} className={`${getRoleColor(role)} border-0 text-xs`}>
          {role.name}
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
  const memberRolesMap = useContext(MemberRolesContext)
  const cachedRoles = memberRolesMap.get(userId)

  // Convert to display format
  const roles = cachedRoles?.map(memberRBACRoleToRole) || []

  return (
    <div className="rounded-xl border bg-card p-4">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-medium">Assigned roles</h4>
        {onManageRoles && (
          <Can route="PUT /api/v1/users/{userId}/roles">
            <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={onManageRoles}>
              <Pencil className="me-1 h-3 w-3" />
              Manage
            </Button>
          </Can>
        )}
      </div>

      {roles.length === 0 ? (
        <div className="text-center py-4">
          <Shield className="h-8 w-8 mx-auto text-muted-foreground/30 mb-2" />
          <p className="text-sm text-muted-foreground">No roles assigned</p>
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
                  <p className="font-medium text-sm">{role.name}</p>
                  {role.is_system && (
                    <span className="text-[10px] text-muted-foreground px-1.5 py-0.5 rounded bg-muted">
                      System
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
  const { roles: allRoles, isLoading: allRolesLoading } = useRoles({ skip: !open })
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
    if (!initialized.current && !userRolesLoading && userRoles.length > 0) {
      setSelectedRoleIds(userRoles.map((r) => r.id))
      initialized.current = true
    } else if (!initialized.current && !userRolesLoading) {
      // Loaded with empty result — still mark as initialized so we don't
      // overwrite an explicit "select nothing" state on re-render.
      setSelectedRoleIds([])
      initialized.current = true
    }
  }, [open, userRoles, userRolesLoading])

  const handleSave = async () => {
    try {
      await setUserRoles({ role_ids: selectedRoleIds })
      toast.success('Roles updated successfully')
      mutateUserRoles()
      onSuccess?.()
      onOpenChange(false)
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to update roles'))
    }
  }

  const isLoading = userRolesLoading || allRolesLoading

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader className="pb-4 border-b">
          <DialogTitle>Manage roles</DialogTitle>
          {member && <DialogDescription>{member.name}</DialogDescription>}
        </DialogHeader>

        <div className="py-4">
          <RoleChecklist
            canGrantAdmin={canGrantAdmin}
            roles={allRoles}
            selected={selectedRoleIds}
            onChange={setSelectedRoleIds}
            loading={isLoading}
            disabled={isSetting}
            className="max-h-[400px]"
          />
        </div>

        <DialogFooter className="border-t pt-4 gap-2">
          <div className="flex-1 text-start">
            {selectedRoleIds.length > 0 && (
              <span className="text-xs text-muted-foreground">
                {selectedRoleIds.length} role{selectedRoleIds.length > 1 ? 's' : ''} selected
              </span>
            )}
          </div>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSetting}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={isSetting || isLoading}>
            {isSetting ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <CheckCircle className="me-2 h-4 w-4" />
            )}
            Save changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function UsersPage() {
  const { currentTenant } = useTenant()
  const tenantSlug = currentTenant?.slug
  // Peer administrators are the owner's to manage (the API answers 403 to
  // anyone else); their rows show the actions disabled, with the reason.
  const { isOwner, can, isAtLeast } = usePermissions()
  // Same gate as the old <Can permission={MembersManage} minRole="admin">.
  const canManageMembers = useCanMutate('PATCH /api/v1/tenants/{tenant}/members/{userId}')
  const currentUser = useUser()
  const caller = { isOwner: isOwner(), userId: currentUser?.id }

  // Search and filters live in the URL so a filtered member list can be linked to.
  const [searchQuery, setSearchQueryParam] = useUrlFilter('q', '')
  const [statusParam, setStatusParam] = useUrlFilter('status', 'current')
  const [roleParam, setRoleParam] = useUrlFilter('role', 'all')
  const statusFilter: StatusFilter = statusFilters.some((f) => f.value === statusParam)
    ? (statusParam as StatusFilter)
    : 'current'
  const roleFilter: RoleFilter = roleFilters.some((f) => f.value === roleParam)
    ? (roleParam as RoleFilter)
    : 'all'
  const debouncedSearch = useDebounce(searchQuery.trim(), 300)

  // Paged, searched and filtered on the server. The list used to load one
  // capped page (100) and filter it in the browser, so every member past the
  // cap was unreachable (23a B20).
  const { pagination, setPagination, resetPage, offset, limit } = useUrlPagination(
    MEMBER_PAGE_SIZES,
    20
  )
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
    limit,
    offset,
  })
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
  const [isResettingMfa, setIsResettingMfa] = useState(false)
  // Offboarding wizard (RFC-050): the member being offboarded. Offboarding
  // strips every access source and asks for a new owner of their work.
  const [offboardMember, setOffboardMember] = useState<MemberWithUser | null>(null)
  // Erase personal data (owner only, offboarded members): confirmation.
  const [eraseConfirmMember, setEraseConfirmMember] = useState<MemberWithUser | null>(null)
  const [isErasing, setIsErasing] = useState(false)

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

  // Table columns. The select-checkbox column was removed alongside the
  // bulk-actions dropdown — there's nothing to do with selected rows now.
  const columns: ColumnDef<MemberWithUser>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => <DataTableColumnHeader column={column} title="User" />,
      cell: ({ row }) => (
        <div
          className={cn(
            'flex items-center gap-3',
            isDeactivated(row.original.status) && 'opacity-60'
          )}
        >
          <Avatar className="h-8 w-8">
            <AvatarFallback className="text-xs">{getInitials(row.original.name)}</AvatarFallback>
          </Avatar>
          <div>
            <p className="font-medium">
              {row.original.name}
              {isDeactivated(row.original.status) && (
                <span className="text-muted-foreground ms-1 text-xs font-normal">
                  (deactivated)
                </span>
              )}
            </p>
            <p className="text-muted-foreground text-xs">{row.original.email}</p>
          </div>
        </div>
      ),
    },
    {
      accessorKey: 'role',
      header: 'Roles',
      enableSorting: false,
      cell: ({ row }) => {
        return <UserRolesCell userId={row.original.user_id} />
      },
    },
    {
      accessorKey: 'joined_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Joined" />,
      cell: ({ row }) => (
        <span className="text-muted-foreground text-sm">{formatDate(row.original.joined_at)}</span>
      ),
    },
    {
      accessorKey: 'last_login_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Last active" />,
      cell: ({ row }) => (
        <span className="text-muted-foreground text-sm">
          {formatLastActive(row.original.last_login_at)}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ row }) => (
        <MemberStatusBadge status={row.original.status} pendingSetup={row.original.pending_setup} />
      ),
    },
    // Two-factor status: the API includes it for owners and admins only.
    ...(members.some((m) => m.mfa_status)
      ? [
          {
            id: 'mfa',
            header: '2FA',
            enableSorting: false,
            cell: ({ row }) => <MemberMfaBadge status={row.original.mfa_status} />,
          } satisfies ColumnDef<MemberWithUser>,
        ]
      : []),
    {
      id: 'actions',
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => {
        const member = row.original
        const isOwnerRow = member.role === 'owner'
        const locked = isPeerAdminLocked(member, caller)
        const offboarded = member.status === 'offboarded'

        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0"
                aria-label={`Actions for ${member.name || member.email}`}
              >
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
              <DropdownMenuItem onClick={() => setSelectedMember(member)}>
                <Eye className="me-2 h-4 w-4" />
                View details
              </DropdownMenuItem>
              {isOwnerRow && canManageMembers && canResetMemberMfa(member, caller) && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onSelect={(e) => {
                      e.preventDefault()
                      setResetMfaMember(member)
                    }}
                  >
                    <ShieldOff className="me-2 h-4 w-4" />
                    Reset 2FA
                  </DropdownMenuItem>
                </>
              )}
              {!isOwnerRow && !offboarded && locked && (
                <Can route="PATCH /api/v1/tenants/{tenant}/members/{userId}">
                  <PeerAdminLockedItems mfaEnabled={member.mfa_status === 'enabled'} />
                </Can>
              )}
              {!isOwnerRow && !locked && (
                <>
                  <Can route="PUT /api/v1/users/{userId}/roles">
                    <DropdownMenuItem
                      onClick={() => {
                        setEditRolesMember(member)
                        setEditRolesDialogOpen(true)
                      }}
                    >
                      <Pencil className="me-2 h-4 w-4" />
                      Change roles
                    </DropdownMenuItem>
                  </Can>
                  <Can route="PATCH /api/v1/tenants/{tenant}/members/{userId}">
                    {member.pending_setup && (
                      <DropdownMenuItem
                        onSelect={(e) => {
                          e.preventDefault()
                          setSetupLinkTarget({
                            userId: member.user_id,
                            email: member.email,
                            name: member.name,
                          })
                        }}
                      >
                        <KeyRound className="me-2 h-4 w-4" />
                        Get setup link
                      </DropdownMenuItem>
                    )}
                    <DropdownMenuSeparator />
                    {canResetMemberMfa(member, caller) && (
                      <DropdownMenuItem
                        onSelect={(e) => {
                          // Confirm first; onSelect lets the menu close cleanly.
                          e.preventDefault()
                          setResetMfaMember(member)
                        }}
                      >
                        <ShieldOff className="me-2 h-4 w-4" />
                        Reset 2FA
                      </DropdownMenuItem>
                    )}
                    {member.status === 'suspended' ? (
                      <DropdownMenuItem
                        onClick={async () => {
                          if (!tenantSlug) return
                          try {
                            await fetcherWithOptions(
                              tenantEndpoints.reactivateMember(tenantSlug, member.id),
                              { method: 'POST' }
                            )
                            toast.success(`${member.name || member.email} re-enabled`)
                            refreshData()
                          } catch (error) {
                            toast.error(getErrorMessage(error, 'Failed to re-enable member'))
                          }
                        }}
                      >
                        <CheckCircle className="me-2 h-4 w-4" />
                        Re-enable
                      </DropdownMenuItem>
                    ) : (
                      <DropdownMenuItem
                        onSelect={(e) => {
                          // Open confirmation dialog instead of firing
                          // immediately. onSelect lets the dropdown close
                          // cleanly before the AlertDialog opens.
                          e.preventDefault()
                          setSuspendConfirmMember(member)
                        }}
                      >
                        <Ban className="me-2 h-4 w-4" />
                        Disable
                      </DropdownMenuItem>
                    )}
                    <DropdownMenuItem
                      variant="destructive"
                      onSelect={(e) => {
                        // Open the offboarding wizard. onSelect lets the
                        // dropdown close cleanly first.
                        e.preventDefault()
                        setOffboardMember(member)
                      }}
                    >
                      <UserMinus className="me-2 h-4 w-4" />
                      Offboard...
                    </DropdownMenuItem>
                  </Can>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )
      },
    },
  ]

  // Actions
  // Erase an offboarded person's name and email (owner only). Rows and
  // history stay; they then show "Deleted user #...".
  const handleConfirmErase = async () => {
    if (!eraseConfirmMember) return
    setIsErasing(true)
    try {
      await eraseMemberPersonalData(eraseConfirmMember.id)
      toast.success('Personal data erased')
      setEraseConfirmMember(null)
      refreshData()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to erase personal data'))
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
      toast.success(`${suspendConfirmMember.name || suspendConfirmMember.email} disabled`)
      setSuspendConfirmMember(null)
      refreshData()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to disable member'))
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
        `Two-factor authentication reset for ${resetMfaMember.name || resetMfaMember.email}`
      )
      setResetMfaMember(null)
      refreshData()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to reset two-factor authentication'))
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
      toast.success('Invitation email resent')
    } catch {
      toast.error('Failed to resend invitation')
    }
  }
  const cancelInvite = async (invitation: Invitation) => {
    if (!tenantSlug) return
    try {
      await fetcherWithOptions(tenantEndpoints.deleteInvitation(tenantSlug, invitation.id), {
        method: 'DELETE',
      })
      toast.success('Invitation cancelled')
      refreshData()
    } catch {
      toast.error('Failed to cancel invitation')
    }
  }

  const invitationColumns: ColumnDef<Invitation>[] = [
    {
      accessorKey: 'email',
      header: 'Email',
      enableSorting: false,
      cell: ({ row }) => <span className="font-medium">{row.original.email}</span>,
    },
    {
      id: 'roles',
      header: 'Roles',
      enableSorting: false,
      cell: ({ row }) => {
        const invitation = row.original
        // Role names from role_ids (resolved when the role list is loaded).
        const invitedRoles = (invitation.role_ids || [])
          .map((id) => availableRolesForInvite.find((r) => r.id === id))
          .filter((r): r is NonNullable<typeof r> => r != null)
        if (invitedRoles.length > 0) {
          return (
            <div className="flex flex-wrap items-center gap-1">
              {invitedRoles.slice(0, 2).map((role) => (
                <Badge key={role.id} className={`${getRoleColor(role)} border-0 text-xs`}>
                  {role.name}
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
                      .map((r) => r.name)
                      .join(', ')}
                  </TooltipContent>
                </Tooltip>
              )}
            </div>
          )
        }
        /* Invitations created before the RBAC role picker carry only the
           legacy `role` field ("member", "admin", ...) with empty role_ids —
           show that rather than a confusing "No roles". */
        return (
          <Badge variant="secondary" className="text-xs capitalize">
            {invitation.role || 'No roles'}
          </Badge>
        )
      },
    },
    {
      accessorKey: 'expires_at',
      header: 'Expires',
      enableSorting: false,
      cell: ({ row }) => {
        const daysUntilExpiry = Math.ceil(
          (new Date(row.original.expires_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
        )
        const isExpiringSoon = daysUntilExpiry <= 3 && daysUntilExpiry > 0
        const isExpired = daysUntilExpiry <= 0
        return (
          <span
            className={`text-sm ${isExpired || isExpiringSoon ? 'text-destructive' : 'text-muted-foreground'}`}
          >
            {isExpired
              ? 'Expired'
              : isExpiringSoon
                ? `In ${daysUntilExpiry} day${daysUntilExpiry > 1 ? 's' : ''}`
                : formatDate(row.original.expires_at)}
          </span>
        )
      },
    },
    {
      id: 'actions',
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => (
        <DataTableRowActions
          actions={[
            {
              label: 'Resend email',
              icon: Send,
              route: 'POST /api/v1/tenants/{tenant}/invitations/{invitationId}/resend',
              onClick: () => resendInvite(row.original),
            },
            {
              label: 'Cancel invitation',
              icon: Trash2,
              destructive: true,
              separatorBefore: true,
              route: 'DELETE /api/v1/tenants/{tenant}/invitations/{invitationId}',
              onClick: () => cancelInvite(row.original),
            },
          ]}
        />
      ),
    },
  ]

  const toggleStatus = (next: StatusFilter) =>
    setStatusFilter(statusFilter === next ? 'current' : next)

  const toolbarStart = (
    <>
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <SearchIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search users..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="ps-9"
          aria-label="Search users"
        />
      </div>
      <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v)}>
        <SelectTrigger className="h-9 w-[140px]" aria-label="Status">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {statusFilters.map((f) => (
            <SelectItem key={f.value} value={f.value}>
              {f.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={roleFilter} onValueChange={(v) => setRoleFilter(v)}>
        <SelectTrigger className="h-9 w-[130px]" aria-label="Membership role">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {roleFilters.map((f) => (
            <SelectItem key={f.value} value={f.value}>
              {f.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </>
  )

  return (
    <MemberRolesContext.Provider value={memberRolesMap}>
      <Main>
        <PageHeader
          title="Members"
          description="People in this organization, their roles and pending invitations."
        >
          {/* Accounts are created by owners/admins (no self-registration);
              inviting someone who already has an account stays available. */}
          <Can route="POST /api/v1/tenants/{tenant}/invitations" mode="disable">
            <Button size="sm" variant="outline" onClick={() => setInviteDialogOpen(true)}>
              <Send className="me-2 h-4 w-4" />
              Invite user
            </Button>
          </Can>
          <Can route="POST /api/v1/tenants/{tenant}/users" mode="disable">
            <Button size="sm" onClick={() => setAddUserOpen(true)}>
              <UserPlus className="me-2 h-4 w-4" />
              Add user
            </Button>
          </Can>
        </PageHeader>

        {membersError && !membersLoading ? (
          <Alert variant="destructive" className="mt-5">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Failed to load members</AlertTitle>
            <AlertDescription>
              <p>The member list could not be loaded.</p>
              <Button variant="outline" size="sm" className="mt-2" onClick={refreshData}>
                <RefreshCw className="me-2 h-4 w-4" />
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        ) : (
          <>
            <MetricStrip
              className="mt-5"
              loading={membersLoading}
              items={[
                {
                  key: 'current',
                  label: 'Members',
                  value: statusCounts.current,
                  onClick: () => setStatusFilter('current'),
                  active: statusFilter === 'current',
                },
                {
                  key: 'active',
                  label: 'Active',
                  value: statusCounts.active,
                  onClick: () => toggleStatus('active'),
                  active: statusFilter === 'active',
                },
                {
                  key: 'suspended',
                  label: 'Disabled',
                  value: statusCounts.suspended,
                  onClick: () => toggleStatus('suspended'),
                  active: statusFilter === 'suspended',
                },
                {
                  key: 'offboarded',
                  label: 'Offboarded',
                  value: statusCounts.offboarded,
                  onClick: () => toggleStatus('offboarded'),
                  active: statusFilter === 'offboarded',
                },
                {
                  key: 'invites',
                  label: 'Pending invitations',
                  value: invitations.length,
                  onClick: () =>
                    document
                      .getElementById('pending-invitations')
                      ?.scrollIntoView({ behavior: 'smooth' }),
                },
              ]}
            />

            <div className="mt-5">
              {membersLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-9 w-full max-w-sm" />
                  {Array.from({ length: 6 }).map((_, i) => (
                    <Skeleton key={i} className="h-12 w-full" />
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
                  getRowId={(m) => m.id}
                  manualPagination
                  rowCount={membersTotal}
                  pagination={pagination}
                  onPaginationChange={setPagination}
                  pageSizeOptions={MEMBER_PAGE_SIZES}
                  paginationNoun="users"
                  showSearch={false}
                  showColumnToggle={false}
                  toolbarStart={toolbarStart}
                  onRowClick={(m) => setSelectedMember(m)}
                  emptyMessage="No users match these filters"
                />
              )}
            </div>

            {/* Pending Invitations Section */}
            {invitations.length > 0 && (
              <section id="pending-invitations" className="mt-5 scroll-mt-4">
                <h2 className="mb-3 text-base font-semibold">Pending invitations</h2>
                <DataTable
                  columns={invitationColumns}
                  data={invitations}
                  getRowId={(inv) => inv.id}
                  showSearch={false}
                  showColumnToggle={false}
                  showPagination={invitations.length > 10}
                  emptyMessage="No pending invitations"
                />
              </section>
            )}
          </>
        )}
      </Main>

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
                    <MemberStatusBadge status={member.status} pendingSetup={member.pending_setup} />
                  }
                  meta={[member.email]}
                  menu={[
                    {
                      label: 'Copy member ID',
                      icon: Copy,
                      onSelect: () => {
                        copyToClipboard(member.id)
                        toast.success('Member ID copied to clipboard')
                      },
                    },
                    ...(canOffboard
                      ? [
                          {
                            label: 'Offboard...',
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
                  <DetailCallout tone="info" icon={Lock} title="Managed by the owner">
                    {PEER_ADMIN_LOCK_REASON}
                  </DetailCallout>
                )}

                <DetailStatGrid aria-label="Key dates">
                  <DetailStat label="Joined" value={formatDate(member.joined_at)} />
                  <DetailStat label="Last active" value={formatLastActive(member.last_login_at)} />
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
                  <DetailField label="Member ID" full>
                    <DetailCopyId id={member.id} label="Member ID" />
                  </DetailField>
                </DetailFieldGrid>
              </div>
            </DetailSheet>
          )
        })()}

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
      <AlertDialog
        open={!!resetMfaMember}
        onOpenChange={(open) => {
          if (!open && !isResettingMfa) setResetMfaMember(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Reset two-factor authentication?</AlertDialogTitle>
            <AlertDialogDescription>
              {resetMfaMember && (
                <>
                  <span className="font-medium text-foreground">
                    {resetMfaMember.name || resetMfaMember.email}
                  </span>{' '}
                  will be signed out everywhere and can sign in with their password alone until they
                  set up two-factor authentication again (required at their next sign-in if this
                  organization requires it). Use this only after confirming their identity. They are
                  notified by email, and the reset is recorded in the audit log.
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isResettingMfa}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void handleConfirmResetMfa()
              }}
              disabled={isResettingMfa}
              className="bg-destructive text-white hover:bg-destructive/90 focus-visible:ring-destructive/20"
            >
              {isResettingMfa ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  Resetting...
                </>
              ) : (
                <>
                  <ShieldOff className="me-2 h-4 w-4" />
                  Reset 2FA
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Suspend Member Confirmation Dialog */}
      <AlertDialog
        open={!!suspendConfirmMember}
        onOpenChange={(open) => {
          if (!open && !isSuspending) setSuspendConfirmMember(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Disable member?</AlertDialogTitle>
            <AlertDialogDescription>
              {suspendConfirmMember && (
                <>
                  <span className="font-medium text-foreground">
                    {suspendConfirmMember.name || suspendConfirmMember.email}
                  </span>{' '}
                  immediately loses access: sessions end, API keys are suspended, and the scans,
                  report schedules and workflows they own are paused. Their access groups, grants
                  and ownership are kept as they are, so you can re-enable them later. To end access
                  for good, offboard them instead.
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isSuspending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                // Prevent default close so we can keep the dialog open
                // while the request is in flight; close happens in the
                // handler on success.
                e.preventDefault()
                void handleConfirmSuspend()
              }}
              disabled={isSuspending}
              className="bg-destructive text-white hover:bg-destructive/90 focus-visible:ring-destructive/20"
            >
              {isSuspending ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  Disabling...
                </>
              ) : (
                <>
                  <Ban className="me-2 h-4 w-4" />
                  Disable
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Offboarding wizard (RFC-050) */}
      <OffboardMemberDialog
        tenantSlug={tenantSlug}
        member={offboardMember}
        onOpenChange={(open) => {
          if (!open) setOffboardMember(null)
        }}
        onOffboarded={refreshData}
      />

      {/* Erase personal data confirmation (owner only, offboarded members) */}
      <ConfirmDialog
        open={!!eraseConfirmMember}
        onOpenChange={(open) => {
          if (!open && !isErasing) setEraseConfirmMember(null)
        }}
        title="Erase personal data?"
        desc={
          <>
            {eraseConfirmMember && (
              <>
                The name and email of{' '}
                <span className="font-medium text-foreground">
                  {eraseConfirmMember.name || eraseConfirmMember.email}
                </span>{' '}
                are replaced with an anonymous label everywhere, and their credentials are cleared.
                Findings, comments and audit history stay, attributed to the anonymous label. This
                cannot be undone.
              </>
            )}
          </>
        }
        confirmText={
          isErasing ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              Erasing...
            </>
          ) : (
            <>
              <Eraser className="me-2 h-4 w-4" />
              Erase
            </>
          )
        }
        destructive
        isLoading={isErasing}
        handleConfirm={() => void handleConfirmErase()}
      />
    </MemberRolesContext.Provider>
  )
}
