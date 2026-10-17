/**
 * The organization's approval policy as the web console sees it
 * (api/docs/rfcs/RFC-111-approval-policy.md): tiers per kind and risk class,
 * the security pool, exclusions, caps and material-change behavior, and the
 * evaluation of one request. The API is the only authority: everything here
 * only shapes what the editor offers and how a decision is explained.
 */

import type { useTranslation } from '@/context/i18n-provider'

type Translate = ReturnType<typeof useTranslation>['t']

export type ApprovalTier = 'single' | 'peer' | 'security' | 'dual'
export type ApprovalKind = 'false_positive' | 'accepted' | 'rule_false_positive' | 'rule_accepted'
export type RiskClass = 'standard' | 'high' | 'critical'

export const APPROVAL_TIERS: readonly ApprovalTier[] = ['single', 'peer', 'security', 'dual']
export const APPROVAL_KINDS: readonly ApprovalKind[] = [
  'false_positive',
  'accepted',
  'rule_false_positive',
  'rule_accepted',
]
export const RISK_CLASSES: readonly RiskClass[] = ['standard', 'high', 'critical']

export type AcceptedChange = 'end_on_tier_rise' | 'end_on_any_change'
export type SinglePersonFPChange = 'flag' | 'revoke'

/** ApprovalPolicyDTO on the wire. */
export interface ApprovalPolicy {
  /** A tier per "<kind>.<class>"; a missing cell follows the platform default. */
  tiers?: Record<string, ApprovalTier>
  security_pool_group_id?: string
  security_pool_strict: boolean
  exclude_assignee: boolean
  step_up_all_tiers: boolean
  /** Per class; a missing class follows the platform cap by priority. */
  max_acceptance_days?: Partial<Record<RiskClass, number>>
  /** 1 to 14; missing or 0 means 14. */
  decide_within_days?: number
  /** 0.01 to 0.5; missing or 0 means 0.5. */
  epss_threshold?: number
  on_material_change_accepted?: AcceptedChange
  on_material_change_single_person_fp?: SinglePersonFPChange
}

/** The evaluation of one request (GET /findings/{id}/approvals/policy). */
export interface ApprovalEvaluation {
  kind: ApprovalKind
  tier: ApprovalTier
  floor: ApprovalTier
  risk_class: RiskClass
  approvals_required: number
  reasons: string[]
  security_pool: boolean
  security_pool_fallback: boolean
  step_up: boolean
  eligible_approvers: number
  eligible_security_pool: number
  satisfiable: boolean
  min_note_length: number
  max_acceptance_days?: number
  decide_within_days: number
  caller_excluded?: string
}

/** Platform bounds the editor enforces before the API does. */
export const POLICY_BOUNDS = {
  maxAcceptanceDays: 365,
  decideWithinDays: { min: 1, max: 14 },
  epss: { min: 0.01, max: 0.5 },
} as const

export function cellKey(kind: ApprovalKind, cls: RiskClass): string {
  return `${kind}.${cls}`
}

export function tierRank(tier: string | undefined): number {
  return APPROVAL_TIERS.indexOf(tier as ApprovalTier)
}

/** The tiers a cell may take: never below its floor. */
export function tiersAtOrAbove(floor: string | undefined): ApprovalTier[] {
  const min = Math.max(0, tierRank(floor))
  return APPROVAL_TIERS.filter((t) => tierRank(t) >= min)
}

/** Cell value meaning "no organization value": the platform default applies. */
export const DEFAULT_CELL = '__default__'

/**
 * The explicit choices a cell offers besides "Default". A false-positive
 * cell only raises the false-positive level, so `single` (never a raise) is
 * not offered there; every other kind offers every tier from its floor.
 */
export function cellChoices(kind: ApprovalKind, floor: string | undefined): ApprovalTier[] {
  const choices = tiersAtOrAbove(floor)
  return kind === 'false_positive' ? choices.filter((t) => t !== 'single') : choices
}

/**
 * The tiers to send: only cells that differ from the platform default (a
 * cell equal to the default means the same as no cell; the API drops it),
 * and never a tier below the floor. For a false positive any explicit
 * choice is kept, because "Default" there means "follow the level".
 */
export function tiersForSave(
  cells: Record<string, string>,
  floors: Record<string, string>,
  defaults: Record<string, string>
): Record<string, ApprovalTier> {
  const out: Record<string, ApprovalTier> = {}
  for (const [key, value] of Object.entries(cells)) {
    if (value === DEFAULT_CELL || tierRank(value) < 0) continue
    if (tierRank(value) < tierRank(floors[key])) continue
    if (!key.startsWith('false_positive.') && value === defaults[key]) continue
    out[key] = value as ApprovalTier
  }
  return out
}

/** The editor's cell values from a stored policy. */
export function cellsFromPolicy(policy: ApprovalPolicy | undefined): Record<string, string> {
  const cells: Record<string, string> = {}
  for (const kind of APPROVAL_KINDS) {
    for (const cls of RISK_CLASSES) {
      const key = cellKey(kind, cls)
      cells[key] = policy?.tiers?.[key] ?? DEFAULT_CELL
    }
  }
  return cells
}

/**
 * The platform's longest acceptance by priority (shown as a hint next to the
 * organization's caps; the API applies the shorter of both).
 */
export const PLATFORM_ACCEPTANCE_CAPS = { p0Kev: 30, p1: 90, p2: 180, p3: 365 } as const

export function tierLabel(t: Translate, tier: string): string {
  switch (tier) {
    case 'single':
      return t('findingApprovals.tier.single', 'One person')
    case 'peer':
      return t('findingApprovals.tier.peer', 'Peer review')
    case 'security':
      return t('findingApprovals.tier.security', 'Security review')
    case 'dual':
      return t('findingApprovals.tier.dual', 'Two approvers')
    default:
      return tier
  }
}

export function tierHelp(t: Translate, tier: string): string {
  switch (tier) {
    case 'single':
      return t(
        'findingApprovals.tier.singleHelp',
        'The requester decides alone when they hold the approve permission.'
      )
    case 'peer':
      return t('findingApprovals.tier.peerHelp', 'One other approver decides.')
    case 'security':
      return t(
        'findingApprovals.tier.securityHelp',
        'One other person from the security pool decides after re-authenticating.'
      )
    case 'dual':
      return t(
        'findingApprovals.tier.dualHelp',
        'Two other people decide, at least one from the security pool, each after re-authenticating.'
      )
    default:
      return ''
  }
}

export function kindLabel(t: Translate, kind: string): string {
  switch (kind) {
    case 'false_positive':
      return t('findingApprovals.kind.false_positive', 'False positive')
    case 'accepted':
      return t('findingApprovals.kind.accepted', 'Accepted risk')
    case 'rule_false_positive':
      return t('findingApprovals.kind.rule_false_positive', 'Suppression rule: false positive')
    case 'rule_accepted':
      return t('findingApprovals.kind.rule_accepted', 'Suppression rule: accepted risk')
    default:
      return kind
  }
}

export function riskClassLabel(t: Translate, cls: string): string {
  switch (cls) {
    case 'standard':
      return t('findingApprovals.class.standard', 'Standard')
    case 'high':
      return t('findingApprovals.class.high', 'High')
    case 'critical':
      return t('findingApprovals.class.critical', 'Critical')
    default:
      return cls
  }
}

/** A reason code of the evaluation as text. */
export function reasonText(t: Translate, code: string): string {
  switch (code) {
    case 'severity_critical':
      return t('findingApprovals.reason.severity_critical', 'critical severity')
    case 'severity_high':
      return t('findingApprovals.reason.severity_high', 'high severity')
    case 'priority_p0':
      return t('findingApprovals.reason.priority_p0', 'priority P0')
    case 'priority_p1':
      return t('findingApprovals.reason.priority_p1', 'priority P1')
    case 'kev':
      return t('findingApprovals.reason.kev', 'known exploited (KEV)')
    case 'epss_at_or_above_threshold':
      return t(
        'findingApprovals.reason.epss_at_or_above_threshold',
        'EPSS at or above the threshold'
      )
    case 'exploit_validated':
      return t('findingApprovals.reason.exploit_validated', 'exploit validated')
    case 'crown_jewel':
      return t('findingApprovals.reason.crown_jewel', 'crown-jewel asset')
    case 'internet_exposed':
      return t('findingApprovals.reason.internet_exposed', 'internet-exposed asset')
    case 'platform_floor':
      return t('findingApprovals.reason.platform_floor', 'the platform minimum')
    case 'platform_default':
      return t('findingApprovals.reason.platform_default', 'the platform default')
    case 'organization_policy':
      return t('findingApprovals.reason.organization_policy', "your organization's policy")
    case 'fp_level':
      return t('findingApprovals.reason.fp_level', 'the false-positive approval level')
    case 'requester_cannot_decide_alone':
      return t(
        'findingApprovals.reason.requester_cannot_decide_alone',
        'you cannot decide this alone'
      )
    case 'requester_owns_asset':
      return t('findingApprovals.reason.requester_owns_asset', 'you own the asset')
    case 'group_decision':
      return t('findingApprovals.reason.group_decision', 'a decision for a group of findings')
    case 'security_pool_fallback':
      return t(
        'findingApprovals.reason.security_pool_fallback',
        'nobody in the security pool is eligible, so any approver may decide'
      )
    case 'no_eligible_approver':
      return t('findingApprovals.reason.no_eligible_approver', 'nobody is eligible to approve')
    case 'not_enough_eligible_approvers':
      return t(
        'findingApprovals.reason.not_enough_eligible_approvers',
        'not enough people are eligible to approve'
      )
    default:
      return code
  }
}

/** Why an approver was refused (APPROVER_NOT_ELIGIBLE details.reason). */
export function refusalText(t: Translate, reason: string | undefined): string {
  switch (reason) {
    case 'asset_owner':
      return t(
        'findingApprovals.refusal.asset_owner',
        "You own this finding's asset, so you cannot approve hiding its risk."
      )
    case 'assignee':
      return t(
        'findingApprovals.refusal.assignee',
        'The finding is assigned to you, and your organization does not let the assignee approve.'
      )
    case 'not_in_security_pool':
      return t(
        'findingApprovals.refusal.not_in_security_pool',
        'This request needs an approver from the security pool.'
      )
    case 'already_signed':
      return t('findingApprovals.refusal.already_signed', 'You already approved this request.')
    case 'requester':
      return t(
        'findingApprovals.refusal.requester',
        'Another approver must decide your own request.'
      )
    case 'not_an_approver':
      return t(
        'findingApprovals.refusal.not_an_approver',
        'You are not an eligible approver for this finding.'
      )
    default:
      return t('findingApprovals.refusal.generic', 'You cannot approve this request.')
  }
}

interface ErrorLike {
  code?: string
  statusCode?: number
  details?: Record<string, unknown>
}

/** What came of an approve call, for the inbox's toast. */
export type ApproveOutcome =
  | { kind: 'applied' }
  | { kind: 'recorded'; remaining: number }
  | { kind: 'refused'; message: string }
  | { kind: 'failed' }

/** The outcome of a successful approve response (200). */
export function approveResultOutcome(result: unknown): ApproveOutcome {
  const r = (result ?? {}) as {
    status?: string
    approvals_required?: number
    approvals_collected?: number
  }
  if (r.status === 'pending') {
    const remaining = Math.max(1, (r.approvals_required ?? 0) - (r.approvals_collected ?? 0))
    return { kind: 'recorded', remaining }
  }
  return { kind: 'applied' }
}

/** The outcome of a refused approve call (403 / 409 with a policy code). */
export function approveErrorOutcome(t: Translate, err: unknown): ApproveOutcome {
  const e = (err ?? {}) as ErrorLike
  switch (e.code) {
    case 'APPROVER_NOT_ELIGIBLE': {
      const reason = typeof e.details?.reason === 'string' ? e.details.reason : undefined
      return { kind: 'refused', message: refusalText(t, reason) }
    }
    case 'NO_ELIGIBLE_APPROVER':
      return {
        kind: 'refused',
        message: t(
          'findingApprovals.refusal.no_eligible_approver',
          'Nobody eligible can complete this approval. Add an approver or change the security pool.'
        ),
      }
    case 'BATCH_NOT_PENDING':
      return {
        kind: 'refused',
        message: t(
          'findingApprovals.group.notPending',
          'This group exception was already decided, canceled or expired.'
        ),
      }
    case 'BATCH_MEMBER':
      return {
        kind: 'refused',
        message: t(
          'findingApprovals.group.memberRefused',
          'This request is part of a group exception: decide the group instead.'
        ),
      }
    case 'STEP_UP_REQUIRED':
      // The client already offered re-authentication; the user cancelled it.
      return {
        kind: 'refused',
        message: t(
          'findingApprovals.refusal.step_up',
          'Confirm your identity to approve this request.'
        ),
      }
    default:
      return { kind: 'failed' }
  }
}

/** Why the group exception preview left a finding out. */
export function groupSkipText(t: Translate, code: string): string {
  switch (code) {
    case 'not_found':
      return t('findingApprovals.group.skip.not_found', 'Finding no longer exists')
    case 'cannot_move':
      return t('findingApprovals.group.skip.cannot_move', 'Cannot take this status')
    case 'pending_request':
      return t('findingApprovals.group.skip.pending_request', 'Has a pending request')
    default:
      return code
  }
}
