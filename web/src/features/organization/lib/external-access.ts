/**
 * External members and organization access (api RFC-058): the wording the
 * members list, the organization switcher and the access dialogs share.
 */

import type { MemberWithUser } from '../types/member.types'

/** Longest end of access the API accepts for an external member. */
export const MAX_EXTERNAL_ACCESS_DAYS = 365
/** End of access the API proposes when none is given. */
export const DEFAULT_EXTERNAL_ACCESS_DAYS = 90
/** Longest SSO exception the API accepts. */
export const MAX_SSO_EXCEPTION_DAYS = 90

const BLOCKED_REASON_TEXT: Record<string, string> = {
  suspended: 'Your access is disabled',
  expired: 'Your access ended',
  home_access_ended: 'Your access ended in your own organization',
  home_domain_lapsed: 'Your organization no longer holds your email domain',
  trust_revoked: 'The partnership with your organization ended',
  personal_accounts_blocked: 'This organization does not accept personal email accounts',
  awaiting_approval: 'Waiting for an administrator to approve your access',
}

/** Why an organization cannot be opened, in words ("" when it can). */
export function blockedReasonText(reason?: string): string {
  if (!reason) return ''
  return BLOCKED_REASON_TEXT[reason] ?? 'Your access is disabled'
}

const SUSPENDED_REASON_TEXT: Record<string, string> = {
  expired: 'Access ended',
  home_access_ended: 'Left their organization',
  home_domain_lapsed: 'Their organization lost the domain',
  trust_revoked: 'Trust ended',
  awaiting_approval: 'Waiting for approval',
}

/** Why a member is disabled, for the members list ("" when unknown). */
export function suspendedReasonText(reason?: string): string {
  return reason ? (SUSPENDED_REASON_TEXT[reason] ?? '') : ''
}

export type MemberBadgeTone = 'neutral' | 'info' | 'warning' | 'danger'

export interface MemberBadgeSpec {
  key: 'external' | 'personal' | 'unmanaged' | 'lapsed' | 'exception' | 'ends'
  label: string
  title: string
  tone: MemberBadgeTone
}

/** Whole days from now until iso (negative once past). */
export function daysUntil(iso: string, now: Date = new Date()): number {
  return Math.ceil((new Date(iso).getTime() - now.getTime()) / 86_400_000)
}

/** A date `days` from now as YYYY-MM-DD (the value of a date input). */
export function dateInputDaysFromNow(days: number, now: Date = new Date()): string {
  const d = new Date(now.getTime() + days * 86_400_000)
  return d.toISOString().slice(0, 10)
}

/** The end of a date input's day, UTC, as RFC 3339. */
export function endOfDayISO(dateInput: string): string {
  return `${dateInput}T23:59:59Z`
}

/**
 * The badges that say where a member comes from and how their access is
 * bounded. Order: source first (External, Personal or Unmanaged), then the
 * conditions (lapsed domain, SSO exception, end of access).
 */
export function memberBadges(
  member: Pick<
    MemberWithUser,
    'kind' | 'home_organization' | 'personal' | 'domain_lapsed' | 'access_expires_at' | 'status'
  >,
  opts: { ssoExceptionUntil?: string; now?: Date } = {}
): MemberBadgeSpec[] {
  const out: MemberBadgeSpec[] = []
  if (member.kind === 'external') {
    if (member.personal) {
      out.push({
        key: 'personal',
        label: 'Personal',
        title: 'A personal email account no organization manages',
        tone: 'warning',
      })
    } else if (member.home_organization) {
      out.push({
        key: 'external',
        label: 'External',
        title: `Managed by ${member.home_organization}`,
        tone: 'info',
      })
    } else {
      out.push({
        key: 'unmanaged',
        label: 'Unmanaged',
        title: 'External, and no organization manages this address',
        tone: 'warning',
      })
    }
  }
  if (member.domain_lapsed) {
    out.push({
      key: 'lapsed',
      label: 'Lapsed domain',
      title: 'This organization no longer holds the email domain: review this member',
      tone: 'danger',
    })
  }
  if (opts.ssoExceptionUntil && daysUntil(opts.ssoExceptionUntil, opts.now) >= 0) {
    out.push({
      key: 'exception',
      label: 'SSO exception',
      title: `May sign in without SSO until ${formatShortDate(opts.ssoExceptionUntil)}`,
      tone: 'neutral',
    })
  }
  if (member.access_expires_at && member.status !== 'offboarded') {
    const days = daysUntil(member.access_expires_at, opts.now)
    if (days >= 0) {
      out.push({
        key: 'ends',
        label: days === 0 ? 'Ends today' : `Ends in ${days}d`,
        title: `Access ends ${formatShortDate(member.access_expires_at)}`,
        tone: days <= 7 ? 'warning' : 'neutral',
      })
    }
  }
  return out
}

export function formatShortDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

/**
 * Two addresses that reach the same mailbox: Gmail ignores dots and +tags,
 * other providers +tags. Mirrors the API's warning (never a merge).
 */
export function canonicalMailbox(email: string): string {
  const at = email.lastIndexOf('@')
  if (at <= 0) return ''
  let local = email.slice(0, at).toLowerCase()
  let domain = email.slice(at + 1).toLowerCase()
  const plus = local.indexOf('+')
  if (plus >= 0) local = local.slice(0, plus)
  if (domain === 'googlemail.com') domain = 'gmail.com'
  if (domain === 'gmail.com') local = local.replaceAll('.', '')
  return `${local}@${domain}`
}
