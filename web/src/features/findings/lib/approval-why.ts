/**
 * Why a finding request waits for a second person, in plain words, from the
 * reason codes stored with the request (`policy_reasons`) and, for the
 * organization's level, the level in force ("every" or "every serious").
 */

import type { ApiApproval } from '../types'

type Translate = (
  key: string,
  fallback?: string,
  params?: Record<string, string | number>
) => string

export interface ApprovalWhyContext {
  /** The viewer made the request. */
  isRequester: boolean
  /** The false-positive or risk acceptance level in force, when known. */
  level?: string
}

/** The lines that say why the request waits; empty when nothing is known. */
export function approvalWaitReasons(
  t: Translate,
  approval: Pick<
    ApiApproval,
    'policy_reasons' | 'eligible_approver_count' | 'self_approval_available' | 'requested_status'
  >,
  ctx: ApprovalWhyContext
): string[] {
  const reasons = new Set(approval.policy_reasons ?? [])
  const out: string[] = []
  const accepted = approval.requested_status === 'accepted'

  if (reasons.has('automation_cannot_decide')) {
    out.push(
      t(
        'findings.approvalWhy.automation',
        'Requests made by automation or AI always need a person.'
      )
    )
  }
  if (reasons.has('requester_owns_asset')) {
    out.push(
      ctx.isRequester
        ? t(
            'findings.approvalWhy.ownsAssetYou',
            'You own this asset, so someone else must check it.'
          )
        : t(
            'findings.approvalWhy.ownsAsset',
            'The person who asked owns this asset, so someone else must check it.'
          )
    )
  }
  if (reasons.has('requester_cannot_decide_alone') && !reasons.has('automation_cannot_decide')) {
    out.push(
      ctx.isRequester
        ? t(
            'findings.approvalWhy.cannotDecideYou',
            'You cannot approve findings, so someone who can must check it.'
          )
        : t(
            'findings.approvalWhy.cannotDecide',
            'The person who asked cannot approve findings, so someone who can must check it.'
          )
    )
  }
  if (reasons.has(accepted ? 'accept_level' : 'fp_level')) {
    out.push(levelText(t, accepted, ctx.level))
  }
  if (
    reasons.has('no_eligible_approver') &&
    approval.eligible_approver_count === 0 &&
    !approval.self_approval_available
  ) {
    out.push(
      t(
        'findings.approvalWhy.nobody',
        'Nobody else can approve this. Ask an owner to give someone the approve permission.'
      )
    )
  }
  return out
}

function levelText(t: Translate, accepted: boolean, level: string | undefined): string {
  if (accepted) {
    if (level === 'high_and_above')
      return t(
        'findings.approvalWhy.acceptSerious',
        'Your organization asks a second person to check every serious accepted risk.'
      )
    if (level === 'all')
      return t(
        'findings.approvalWhy.acceptAll',
        'Your organization asks a second person to check every accepted risk.'
      )
    return t(
      'findings.approvalWhy.acceptThis',
      'Your organization asks a second person to check this accepted risk.'
    )
  }
  if (level === 'high_and_above')
    return t(
      'findings.approvalWhy.fpSerious',
      'Your organization asks a second person to check every serious false positive.'
    )
  if (level === 'all')
    return t(
      'findings.approvalWhy.fpAll',
      'Your organization asks a second person to check every false positive.'
    )
  return t(
    'findings.approvalWhy.fpThis',
    'Your organization asks a second person to check this false positive.'
  )
}

/** The organization's level is part of the answer: the band reads it. */
export function needsApprovalLevel(approval: Pick<ApiApproval, 'policy_reasons'>): boolean {
  const r = approval.policy_reasons ?? []
  return r.includes('fp_level') || r.includes('accept_level')
}
