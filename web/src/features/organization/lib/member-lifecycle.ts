/**
 * Member lifecycle helpers (RFC-050): disable, offboard, erase.
 *
 * The backend is the authority: it refuses an offboarding that leaves owned
 * work without a new owner (409 reassignment_required) and a reassignment to
 * anyone but another active member of the organization. These helpers only
 * shape the wizard so the person sees what is required before submitting.
 */

import { ApiClientError } from '@/lib/api/error-handler'
import type {
  MemberAccessReport,
  MemberStatus,
  OffboardMemberInput,
} from '../types/member.types'

/** A category of owned work an offboarding must hand to someone else. */
export type OffboardCategory = 'schedules' | 'findings' | 'assets'

export const OFFBOARD_CATEGORY_LABEL: Record<OffboardCategory, string> = {
  schedules: 'Scans, report schedules and workflows',
  findings: 'Open assigned findings',
  assets: 'Owned assets',
}

/** Picker value that puts the member's open findings back in the queue. */
export const FINDINGS_TO_QUEUE = '__queue__'

/** The wizard's choices: one new owner per category (user ids). */
export interface OffboardPlanDraft {
  schedulesTo?: string
  /** A user id, or FINDINGS_TO_QUEUE. */
  findingsTo?: string
  assetsTo?: string
}

/** How many schedules (scans, report schedules, workflows) the member owns. */
export function ownedScheduleCount(report: MemberAccessReport): number {
  return (
    (report.owned_scans?.length ?? 0) +
    (report.owned_report_schedules?.length ?? 0) +
    (report.owned_workflows?.length ?? 0)
  )
}

/** The categories the member owns something in, in display order. */
export function requiredReassignments(report: MemberAccessReport): OffboardCategory[] {
  const out: OffboardCategory[] = []
  if (ownedScheduleCount(report) > 0) out.push('schedules')
  if ((report.assigned_findings ?? 0) > 0) out.push('findings')
  if ((report.owned_assets ?? 0) > 0) out.push('assets')
  return out
}

/** The required categories the draft leaves without a new owner. */
export function missingReassignments(
  report: MemberAccessReport,
  draft: OffboardPlanDraft
): OffboardCategory[] {
  return requiredReassignments(report).filter((c) => {
    if (c === 'schedules') return !draft.schedulesTo
    if (c === 'findings') return !draft.findingsTo
    return !draft.assetsTo
  })
}

/** The request body for the draft (only the categories that need it). */
export function buildOffboardInput(
  report: MemberAccessReport,
  draft: OffboardPlanDraft
): OffboardMemberInput {
  const required = new Set(requiredReassignments(report))
  const input: OffboardMemberInput = {}
  if (required.has('schedules') && draft.schedulesTo) input.schedules_to = draft.schedulesTo
  if (required.has('findings') && draft.findingsTo) {
    if (draft.findingsTo === FINDINGS_TO_QUEUE) input.unassign_findings = true
    else input.findings_to = draft.findingsTo
  }
  if (required.has('assets') && draft.assetsTo) input.assets_to = draft.assetsTo
  return input
}

/** Disabled or offboarded: shown greyed with "(deactivated)". */
export function isDeactivated(status: MemberStatus | string | undefined): boolean {
  return status === 'suspended' || status === 'offboarded'
}

/** A person's display name, marked when they are deactivated. */
export function memberDisplayName(m: {
  name?: string
  email?: string
  status?: MemberStatus | string
}): string {
  const base = m.name || m.email || 'Unknown user'
  return isDeactivated(m.status) ? `${base} (deactivated)` : base
}

/**
 * The people work can be handed to: active members other than the one being
 * offboarded (the API enforces the same rule).
 */
export function reassignCandidates<T extends { user_id: string; status?: string }>(
  members: T[],
  offboardedUserId: string
): T[] {
  return members.filter((m) => m.status === 'active' && m.user_id !== offboardedUserId)
}

/**
 * The categories a 409 reassignment_required names, or null when the error is
 * something else (the wizard then shows the message).
 */
export function reassignmentConflict(error: unknown): OffboardCategory[] | null {
  if (!(error instanceof ApiClientError) || error.statusCode !== 409) return null
  const details = error.details as { code?: string; missing?: unknown } | undefined
  if (details?.code !== 'reassignment_required' || !Array.isArray(details.missing)) return null
  return details.missing.filter(
    (m): m is OffboardCategory => m === 'schedules' || m === 'findings' || m === 'assets'
  )
}
