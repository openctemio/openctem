/**
 * Member Management Types
 *
 * Type definitions for team member management
 */

import type { SetupLinkOutcome } from '@/features/shared/components/one-time-setup-link'

// ============================================
// MEMBER TYPES
// ============================================

export type MemberRole = 'owner' | 'admin' | 'member' | 'viewer'
// Membership lifecycle states the UI cares about (RFC-050 member lifecycle):
//   active     — normal access
//   pending    — synthetic state for unaccepted invitations (no membership row yet)
//   suspended  — "Disabled": access cut, groups/grants/ownership frozen, reversible
//   offboarded — tombstone of a person who left: everything stripped, owned work
//                reassigned, kept so history stays valid; a re-invite starts from zero
// User-level "inactive" status is intentionally NOT in this list — it has no
// tenant-admin UI and the OSS product has no super-admin platform layer.
export type MemberStatus = 'active' | 'pending' | 'suspended' | 'offboarded'

/** Server-side member list filter (GET .../members?status=). */
export type MemberStatusFilter = 'active' | 'suspended' | 'offboarded' | 'all'

export interface Member {
  id: string
  user_id: string
  role: MemberRole
  invited_by?: string
  joined_at: string
}

// RBAC role returned with member data
export interface MemberRBACRole {
  id: string
  name: string
  slug: string
  is_system: boolean
}

export type MemberMfaStatus = 'enabled' | 'disabled' | 'idp'

export interface MemberWithUser extends Member {
  email: string
  name: string
  avatar_url?: string
  status: MemberStatus
  last_login_at?: string
  // Two-factor status; the API sends it to owners and admins only.
  // "idp" = signs in through an identity provider, which owns the 2FA.
  mfa_status?: MemberMfaStatus
  // RBAC roles (included when ?include=roles)
  rbac_roles?: MemberRBACRole[]
  /** Account created by an admin whose password has not been set yet. */
  pending_setup?: boolean
  /**
   * External members (api RFC-058): someone whose email domain the
   * organization does not hold. They join by invitation only, as viewers
   * with no data scope, and (when no organization manages their address)
   * with an end date.
   */
  kind?: MemberKind
  /** The organization that manages an external member's address. */
  home_organization?: string
  /** Owners and admins only. */
  access_expires_at?: string
  /** Why the membership is disabled: expired, home_access_ended, ... */
  suspended_reason?: string
  /** The member's email domain lost its verified SSO proof here. */
  domain_lapsed?: boolean
  /** External, with a consumer address (gmail.com, ...) nobody manages. */
  personal?: boolean
}

export type MemberKind = 'internal' | 'external'

/** PATCH /api/v1/organization/members/{member_id}/access */
export interface UpdateMemberAccessInput {
  /** RFC 3339; at most 365 days ahead. Omit only for a managed address. */
  expires_at?: string
  reason?: string
}

export interface MemberStats {
  total_members: number
  active_members: number
  suspended_members?: number
  offboarded_members?: number
  pending_invites: number
  role_counts: Record<string, number>
}

// ============================================
// INVITATION TYPES
// ============================================

export interface Invitation {
  id: string
  email: string
  role: MemberRole // Deprecated: always "member", use role_ids instead
  role_ids: string[] // RBAC role IDs assigned to this invitation
  token?: string
  invited_by: string
  expires_at: string
  created_at: string
  pending: boolean
  /** When an external invitee's access will end. */
  access_expires_at?: string
  /** Members whose address reaches the same mailbox (a warning, create only). */
  lookalike_of?: string[]
}

export interface CreateInvitationInput {
  email: string
  role_ids: string[] // RBAC roles to assign when user accepts invitation (required)
  /**
   * End of access for an invitee outside the organization (RFC 3339). The
   * API proposes 90 days when omitted and ignores it for an internal invitee.
   */
  access_expires_at?: string
  access_reason?: string
}

// ============================================
// API RESPONSE TYPES
// ============================================

export interface MemberListResponse {
  data: MemberWithUser[]
  total: number
}

export interface InvitationListResponse {
  data: Invitation[]
  total: number
}

// ============================================
// UPDATE TYPES
// ============================================

export interface UpdateMemberRoleInput {
  role: MemberRole
}

// ============================================
// ROLE DISPLAY CONFIG
// ============================================

export const ROLE_DISPLAY: Record<
  MemberRole,
  { label: string; description: string; color: string }
> = {
  owner: {
    label: 'Owner',
    description: 'Full access to all features and settings',
    color: 'bg-red-500/20 text-red-400',
  },
  admin: {
    label: 'Admin',
    description: 'Manage team, assign tasks, view reports',
    color: 'bg-purple-500/20 text-purple-400',
  },
  member: {
    label: 'Member',
    description: 'Analyze findings, manage remediation',
    color: 'bg-blue-500/20 text-blue-400',
  },
  viewer: {
    label: 'Viewer',
    description: 'Read-only access to dashboards and reports',
    color: 'bg-gray-500/20 text-gray-400',
  },
}

export const STATUS_DISPLAY: Record<
  MemberStatus,
  { label: string; color: string; bgColor: string }
> = {
  active: { label: 'Active', color: 'text-green-400', bgColor: 'bg-green-500/20' },
  pending: { label: 'Pending', color: 'text-yellow-400', bgColor: 'bg-yellow-500/20' },
  suspended: { label: 'Disabled', color: 'text-warning', bgColor: 'bg-warning/15' },
  offboarded: { label: 'Offboarded', color: 'text-muted-foreground', bgColor: 'bg-muted' },
}

// ============================================
// MEMBER LIFECYCLE (RFC-050)
// ============================================

/** One thing a member holds or owns (GET .../access-report). */
export interface LifecycleRef {
  id: string
  name: string
  status?: string
  /** Type-specific note: key prefix, campaign role, schedule type. */
  detail?: string
}

/**
 * GET /api/v1/organization/members/{member_id}/access-report: everything the
 * member holds (access) and owns (work) in this organization.
 */
export interface MemberAccessReport {
  membership_id: string
  user_id: string
  status: 'active' | 'suspended' | 'offboarded'
  roles: LifecycleRef[]
  groups: LifecycleRef[]
  api_keys: LifecycleRef[]
  campaigns: LifecycleRef[]
  direct_grants: number
  visible_assets: number
  owned_scans: LifecycleRef[]
  owned_report_schedules: LifecycleRef[]
  owned_workflows: LifecycleRef[]
  assigned_findings: number
  owned_assets: number
}

/** POST /api/v1/organization/members/{member_id}/offboard body. */
export interface OffboardMemberInput {
  schedules_to?: string
  findings_to?: string
  unassign_findings?: boolean
  assets_to?: string
}

export interface OffboardResult {
  report: MemberAccessReport
  revoked_keys: number
  removed_groups: number
  removed_grants: number
  removed_campaigns: number
  reassigned_schedules: number
  reassigned_findings: number
  reassigned_assets: number
  offboarded_at: string
}

// ============================================
// ADMIN-CREATED USERS
// ============================================

/**
 * POST /tenants/{tenant}/users — an owner/admin creates the account directly
 * (no self-registration). Same RBAC role picker as invitations.
 */
export interface CreateTenantUserInput {
  email: string
  name: string
  /** 1..10 RBAC role ids */
  role_ids: string[]
}

export const MAX_ROLES_PER_USER = 10

/**
 * Response of POST /tenants/{tenant}/users and
 * POST /tenants/{tenant}/users/{userId}/setup-link. `setup_token` is present
 * only when no email was sent; show it once, never store it.
 */
export interface CreatedTenantUser extends SetupLinkOutcome {
  user: { id: string; email: string; name: string }
  membership_id: string
  role: string
}

// Note: Membership level selection removed from UI.
// All invited users become 'member'. Permissions come from RBAC roles.
// Only 'owner' is special (cannot be removed, full access).
export const INVITABLE_ROLES: MemberRole[] = ['member'] // Simplified: only 'member' for invitations
