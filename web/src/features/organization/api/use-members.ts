/**
 * Member Management API Hooks
 *
 * SWR hooks for managing team members and invitations
 */

import useSWR from 'swr'
import useSWRMutation from 'swr/mutation'
import { tenantEndpoints } from '@/lib/api/endpoints'
import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type {
  MemberListResponse,
  MemberStats,
  InvitationListResponse,
  Invitation,
  CreateInvitationInput,
  UpdateMemberRoleInput,
  MemberWithUser,
  CreateTenantUserInput,
  CreatedTenantUser,
  MemberStatusFilter,
  MemberAccessReport,
  OffboardMemberInput,
  OffboardResult,
} from '../types/member.types'

// ============================================
// FETCH MEMBERS
// ============================================

export interface UseMembersOptions {
  /** Include RBAC roles for each member (reduces N+1 calls on Users page) */
  includeRoles?: boolean
  /** Search term for name or email (case-insensitive) */
  search?: string
  /** Max results (server default 100, max 100) */
  limit?: number
  /** Pagination offset */
  offset?: number
  /**
   * Membership status filter (server-side). Defaults to `active`: every
   * picker (assignee, group member, approver, owner) must never offer a
   * disabled member or a person who left (RFC-050). `current` lists active
   * and disabled members (the server default), `all` adds offboarded ones.
   */
  status?: MemberStatusFilter | 'current'
  /** Effective system role filter (server-side) */
  role?: 'owner' | 'admin' | 'member' | 'viewer'
}

/**
 * Hook to fetch team members with user details
 * Only fetches if user has members:read permission
 *
 * @param tenantIdOrSlug - Tenant ID or slug
 * @param options - Options for fetching members
 * @param options.includeRoles - Include RBAC roles for each member
 * @param options.search - Search term for name or email
 * @param options.limit - Page size (sent as per_page; default 100, max 500)
 * @param options.offset - Offset of the first member (sent as a 1-based page)
 */
/**
 * The members list pages with page / per_page (one list convention); the
 * options keep an offset window, which maps onto a page of `limit` members.
 */
export function setMemberPage(params: URLSearchParams, options?: UseMembersOptions) {
  const perPage = options?.limit && options.limit > 0 ? options.limit : 0
  if (perPage) params.set('per_page', String(perPage))
  if (perPage && options?.offset && options.offset > 0) {
    params.set('page', String(Math.floor(options.offset / perPage) + 1))
  }
}

export function useMembers(tenantIdOrSlug: string | undefined, options?: UseMembersOptions) {
  const { can } = usePermissions()
  const canReadMembers = can(Permission.MembersRead)

  // Only fetch if user has permission
  const shouldFetch = tenantIdOrSlug && canReadMembers

  // Build query parameters
  const params = new URLSearchParams()

  // Include parameter
  const includes = ['user']
  if (options?.includeRoles) {
    includes.push('roles')
  }
  params.set('include', includes.join(','))

  // Search and pagination parameters
  if (options?.search) {
    params.set('search', options.search)
  }
  setMemberPage(params, options)
  const status = options?.status ?? PICKER_MEMBER_STATUS
  if (status !== 'current') {
    params.set('status', status)
  }
  if (options?.role) {
    params.set('role', options.role)
  }

  const { data, error, isLoading, mutate } = useSWR<MemberListResponse>(
    shouldFetch ? `${tenantEndpoints.members(tenantIdOrSlug)}?${params.toString()}` : null,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000,
    }
  )

  return {
    members: data?.data ?? [],
    total: data?.total ?? 0,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

/**
 * Hook to fetch member statistics
 * Only fetches if user has members:read permission
 */
export function useMemberStats(tenantIdOrSlug: string | undefined) {
  const { can } = usePermissions()
  const canReadMembers = can(Permission.MembersRead)

  // Only fetch if user has permission
  const shouldFetch = tenantIdOrSlug && canReadMembers

  const { data, error, isLoading, mutate } = useSWR<MemberStats>(
    shouldFetch ? tenantEndpoints.memberStats(tenantIdOrSlug) : null,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000,
    }
  )

  return {
    stats: data,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

// ============================================
// MEMBER MUTATIONS
// ============================================

async function updateMemberRole(url: string, { arg }: { arg: UpdateMemberRoleInput }) {
  return fetcherWithOptions<MemberWithUser>(url, {
    method: 'PATCH',
    body: JSON.stringify(arg),
  })
}

/**
 * Hook to update a member's role
 */
export function useUpdateMemberRole(
  tenantIdOrSlug: string | undefined,
  memberId: string | undefined
) {
  const { trigger, isMutating, error } = useSWRMutation(
    tenantIdOrSlug && memberId ? tenantEndpoints.updateMember(tenantIdOrSlug, memberId) : null,
    updateMemberRole
  )

  return {
    updateRole: trigger,
    isUpdating: isMutating,
    error,
  }
}

// ============================================
// MEMBER LIFECYCLE (RFC-050)
// ============================================

/** The member list filter every picker uses (RFC-050: no deactivated people). */
export const PICKER_MEMBER_STATUS: MemberStatusFilter = 'active'

/**
 * What a member holds and owns. Fetched only when `memberId` is set and the
 * caller can manage members (the API answers 403 otherwise).
 */
export function useMemberAccessReport(memberId: string | undefined) {
  const { can } = usePermissions()
  const shouldFetch = !!memberId && can(Permission.MembersManage)
  const { data, error, isLoading, mutate } = useSWR<MemberAccessReport>(
    shouldFetch ? tenantEndpoints.memberAccessReport(memberId) : null,
    fetcher,
    { revalidateOnFocus: false }
  )
  return { report: data, isLoading: shouldFetch ? isLoading : false, error, mutate }
}

/** Offboard a member (mandatory reassignment; 409 reassignment_required otherwise). */
export function offboardMember(memberId: string, input: OffboardMemberInput) {
  return fetcherWithOptions<OffboardResult>(tenantEndpoints.offboardMember(memberId), {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

/** Erase an offboarded person's name and email (owner only). */
export function eraseMemberPersonalData(memberId: string) {
  return fetcherWithOptions<void>(tenantEndpoints.eraseMember(memberId), { method: 'POST' })
}

// ============================================
// FETCH INVITATIONS
// ============================================

/**
 * Hook to fetch pending invitations
 * Only fetches if user has members:invite or members:manage permission
 */
export function useInvitations(tenantIdOrSlug: string | undefined) {
  const { canAny } = usePermissions()
  const canManageInvitations = canAny(Permission.MembersInvite, Permission.MembersManage)

  // Only fetch if user has permission
  const shouldFetch = tenantIdOrSlug && canManageInvitations

  const { data, error, isLoading, mutate } = useSWR<InvitationListResponse>(
    shouldFetch ? tenantEndpoints.invitations(tenantIdOrSlug) : null,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000,
    }
  )

  return {
    invitations: data?.data ?? [],
    total: data?.total ?? 0,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

// ============================================
// INVITATION MUTATIONS
// ============================================

async function deleteInvitation(url: string) {
  return fetcherWithOptions<void>(url, {
    method: 'DELETE',
  })
}

/**
 * Hook to delete/cancel an invitation
 */
export function useDeleteInvitation(
  tenantIdOrSlug: string | undefined,
  invitationId: string | undefined
) {
  const { trigger, isMutating, error } = useSWRMutation(
    tenantIdOrSlug && invitationId
      ? tenantEndpoints.deleteInvitation(tenantIdOrSlug, invitationId)
      : null,
    deleteInvitation
  )

  return {
    deleteInvitation: trigger,
    isDeleting: isMutating,
    error,
  }
}

// ============================================
// ADMIN-CREATED USERS
// ============================================

/**
 * Create an invitation. The response is the only place the raw invitation token
 * appears (the API stores a hash), so the caller shows the link from it.
 */
export function createTenantInvitation(tenantIdOrSlug: string, input: CreateInvitationInput) {
  return fetcherWithOptions<Invitation>(tenantEndpoints.createInvitation(tenantIdOrSlug), {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

/**
 * Create a user account in this organization (owner/admin). The response may
 * carry a one-time `setup_token`: a plain call (not SWR) so it is never cached —
 * show it once and drop it.
 */
export function createTenantUser(tenantIdOrSlug: string, input: CreateTenantUserInput) {
  return fetcherWithOptions<CreatedTenantUser>(tenantEndpoints.createUser(tenantIdOrSlug), {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

/**
 * Issue a fresh one-time setup link for a member whose account is still
 * pending setup. Invalidates any earlier link.
 */
export function issueSetupLink(tenantIdOrSlug: string, userId: string) {
  return fetcherWithOptions<CreatedTenantUser>(
    tenantEndpoints.userSetupLink(tenantIdOrSlug, userId),
    { method: 'POST' }
  )
}

// ============================================
// CACHE KEYS
// ============================================

/**
 * Get the SWR key for members list
 */
export function getMembersKey(tenantIdOrSlug: string, options?: UseMembersOptions) {
  const params = new URLSearchParams()

  const includes = ['user']
  if (options?.includeRoles) {
    includes.push('roles')
  }
  params.set('include', includes.join(','))

  if (options?.search) {
    params.set('search', options.search)
  }
  setMemberPage(params, options)
  const status = options?.status ?? PICKER_MEMBER_STATUS
  if (status !== 'current') {
    params.set('status', status)
  }
  if (options?.role) {
    params.set('role', options.role)
  }

  return `${tenantEndpoints.members(tenantIdOrSlug)}?${params.toString()}`
}

/**
 * Get the SWR key for member stats
 */
export function getMemberStatsKey(tenantIdOrSlug: string) {
  return tenantEndpoints.memberStats(tenantIdOrSlug)
}

/**
 * Get the SWR key for invitations
 */
export function getInvitationsKey(tenantIdOrSlug: string) {
  return tenantEndpoints.invitations(tenantIdOrSlug)
}
