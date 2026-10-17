/**
 * Ownership transfer rules as the console shows them (api RFC-095 §3.1). The
 * API decides; these only explain before the owner asks.
 */

import { ApiClientError } from '@/lib/api/error-handler'
import type { MemberWithUser } from '../types/member.types'

/** Why a member cannot be asked, as an i18n key (with its English fallback). */
export interface TransferBlocker {
  key: string
  fallback: string
}

/**
 * Whether the member can be asked to own the organization: an active person
 * with two-factor authentication on, not managed by another organization.
 * Returns null when they qualify. `mfa_status` "idp" counts as no local
 * second factor: the API requires one.
 */
export function transferBlocker(member: MemberWithUser): TransferBlocker | null {
  if (member.role === 'owner') {
    return { key: 'org.ownership.blocker.owner', fallback: 'Already the owner.' }
  }
  if (member.status !== 'active') {
    return {
      key: 'org.ownership.blocker.inactive',
      fallback: 'Only an active member can become the owner.',
    }
  }
  if (member.kind === 'external' && member.home_organization) {
    return {
      key: 'org.ownership.blocker.managed',
      fallback: 'Another organization manages this person, so they cannot become the owner.',
    }
  }
  if (member.mfa_status !== 'enabled') {
    return {
      key: 'org.ownership.blocker.mfa',
      fallback: 'They must turn on two-factor authentication first.',
    }
  }
  return null
}

/** Whether accepting makes the member internal (an unmanaged outsider). */
export function becomesInternal(member: MemberWithUser): boolean {
  return member.kind === 'external' && !member.home_organization
}

const ERROR_KEYS: Record<string, TransferBlocker> = {
  OWNERSHIP_NOT_OWNER: {
    key: 'org.ownership.error.notOwner',
    fallback: 'Only the owner can transfer ownership.',
  },
  OWNERSHIP_TRANSFER_PENDING: {
    key: 'org.ownership.error.pending',
    fallback: 'A transfer is already waiting for an answer. Cancel it first.',
  },
  OWNERSHIP_TRANSFER_NOT_FOUND: {
    key: 'org.ownership.error.notFound',
    fallback: 'This transfer is no longer open.',
  },
  OWNERSHIP_TRANSFER_EXPIRED: {
    key: 'org.ownership.error.expired',
    fallback: 'This transfer has expired. Ask the owner for a new one.',
  },
  OWNERSHIP_TRANSFER_VOID: {
    key: 'org.ownership.error.void',
    fallback: 'The person who asked is no longer the owner, so this transfer is void.',
  },
  OWNERSHIP_TARGET_SELF: { key: 'org.ownership.blocker.owner', fallback: 'Already the owner.' },
  OWNERSHIP_TARGET_INACTIVE: {
    key: 'org.ownership.blocker.inactive',
    fallback: 'Only an active member can become the owner.',
  },
  OWNERSHIP_TARGET_SERVICE_ACCOUNT: {
    key: 'org.ownership.blocker.service',
    fallback: 'A service account cannot own an organization.',
  },
  OWNERSHIP_TARGET_NEEDS_MFA: {
    key: 'org.ownership.blocker.mfa',
    fallback: 'They must turn on two-factor authentication first.',
  },
  OWNERSHIP_TARGET_MANAGED: {
    key: 'org.ownership.blocker.managed',
    fallback: 'Another organization manages this person, so they cannot become the owner.',
  },
  OWNERSHIP_TARGET_NEEDS_CONFIRMATION: {
    key: 'org.ownership.error.confirmInternal',
    fallback: 'Confirm that this person becomes an internal member.',
  },
  OWNERSHIP_PREVIOUS_ROLE_INVALID: {
    key: 'org.ownership.error.previousRole',
    fallback: 'Choose administrator, member or viewer for yourself.',
  },
}

/** The translated message for a transfer API error, or null to use the generic one. */
export function transferErrorKey(err: unknown): TransferBlocker | null {
  if (err instanceof ApiClientError) return ERROR_KEYS[err.code] ?? null
  return null
}
