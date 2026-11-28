/**
 * Body of POST /api/v1/findings/bulk/status and /bulk/assign. Both answer 200
 * even when some or all findings were refused, so success must be read from
 * the counts, not the HTTP status.
 */
export interface BulkFindingResult {
  updated?: number
  failed?: number
  errors?: string[]
}

export interface BulkSummary {
  kind: 'success' | 'warning' | 'error'
  message: string
  description?: string
}

// Server errors are "<finding id>: <reason>". The id means nothing in a toast.
function reasonOf(error: string | undefined): string | undefined {
  if (!error) return undefined
  const i = error.indexOf(': ')
  return i >= 0 ? error.slice(i + 2) : error
}

type Translate = (
  key: string,
  fallback?: string,
  params?: Record<string, string | number>
) => string

/**
 * Turns a bulk result into what to tell the user, in the app's language.
 * `action` names what was done to each finding.
 */
export function summarizeBulkResult(
  result: BulkFindingResult | undefined,
  requested: number,
  action: 'assigned' | 'updated',
  t: Translate
): BulkSummary {
  const failed = result?.failed ?? 0
  const updated = result?.updated ?? (failed > 0 ? requested - failed : requested)
  // Success needs something done: "Updated 0 findings" is never a success.
  if (failed === 0 && updated > 0) {
    return {
      kind: 'success',
      message:
        action === 'assigned'
          ? t(
              'findings.bulk.result.assigned',
              '{count, plural, one {Assigned # finding} other {Assigned # findings}}',
              { count: updated }
            )
          : t(
              'findings.bulk.result.updated',
              '{count, plural, one {Updated # finding} other {Updated # findings}}',
              { count: updated }
            ),
    }
  }
  const description = reasonOf(result?.errors?.[0])
  if (updated === 0) {
    return {
      kind: failed > 0 ? 'error' : 'warning',
      message: t('findings.bulk.result.none', 'No findings were changed'),
      description,
    }
  }
  return {
    kind: 'warning',
    message:
      action === 'assigned'
        ? t(
            'findings.bulk.result.assignedPartial',
            'Assigned {updated} of {requested} findings. {failed} not changed',
            { updated, requested, failed }
          )
        : t(
            'findings.bulk.result.updatedPartial',
            'Updated {updated} of {requested} findings. {failed} not changed',
            { updated, requested, failed }
          ),
    description,
  }
}

/** Counts and per-item outcomes of POST /approvals/bulk/approve or /bulk/reject. */
export interface ApprovalBulkOutcome {
  results: { outcome: string; code?: string }[]
  approved: number
  signed: number
  rejected: number
  skipped: number
  failed: number
}

/** Why one request or group of a bulk decision was not decided, in plain words. */
export function approvalBulkReasonText(t: Translate, code: string | undefined): string {
  switch (code) {
    case 'not_found':
      return t('findings.bulkDecide.reason.notFound', 'Not found, or outside what you can see')
    case 'not_pending':
      return t('findings.bulkDecide.reason.notPending', 'Already decided')
    case 'batch_member':
      return t('findings.bulkDecide.reason.batchMember', 'Part of a group: decide the group')
    case 'own_request':
      return t('findings.bulkDecide.reason.ownRequest', 'Your own request: someone else decides it')
    case 'overdue':
      return t('findings.bulkDecide.reason.overdue', 'Past its decide-by date')
    case 'approver_not_eligible':
      return t('findings.bulkDecide.reason.notEligible', 'You are not one of its approvers')
    case 'no_eligible_approver':
      return t('findings.bulkDecide.reason.noApprover', 'Nobody can approve it')
    case 'step_up_required':
      return t(
        'findings.bulkDecide.reason.stepUp',
        'Needs its own sign-in check: approve it on its own'
      )
    case 'forbidden':
      return t('findings.bulkDecide.reason.forbidden', 'You do not have permission')
    case 'cannot_decide':
      return t('findings.bulkDecide.reason.cannotDecide', 'It cannot be decided now')
    default:
      return t('findings.bulkDecide.reason.error', 'Something went wrong. Try it again on its own')
  }
}

/**
 * What a bulk approve or reject did, for its toast: the counts as one line
 * and, when some were not decided, each plain reason with how many it held.
 */
export function summarizeApprovalBulk(
  result: ApprovalBulkOutcome | undefined,
  t: Translate
): BulkSummary {
  const approved = result?.approved ?? 0
  const signed = result?.signed ?? 0
  const rejected = result?.rejected ?? 0
  const skipped = result?.skipped ?? 0
  const failed = result?.failed ?? 0
  const decided = approved + signed + rejected
  const parts = [
    approved > 0 &&
      t('findings.bulkDecide.count.approved', '{count} approved', { count: approved }),
    signed > 0 &&
      t('findings.bulkDecide.count.signed', '{count} waiting for more approvals', {
        count: signed,
      }),
    rejected > 0 &&
      t('findings.bulkDecide.count.rejected', '{count} rejected', { count: rejected }),
    skipped > 0 && t('findings.bulkDecide.count.skipped', '{count} skipped', { count: skipped }),
    failed > 0 && t('findings.bulkDecide.count.failed', '{count} not decided', { count: failed }),
  ].filter((p): p is string => !!p)
  const message =
    parts.length > 0 ? parts.join(', ') : t('findings.bulkDecide.count.none', 'Nothing was decided')

  // Each reason once, with how many items it held, most common first.
  const byCode = new Map<string, number>()
  for (const r of result?.results ?? []) {
    if (r.outcome !== 'skipped' && r.outcome !== 'failed') continue
    const code = r.code || 'error'
    byCode.set(code, (byCode.get(code) ?? 0) + 1)
  }
  const description =
    byCode.size > 0
      ? [...byCode.entries()]
          .sort((a, b) => b[1] - a[1])
          .map(([code, n]) =>
            t('findings.bulkDecide.reasonCount', '{reason}: {count}', {
              reason: approvalBulkReasonText(t, code),
              count: n,
            })
          )
          .join('. ')
      : undefined

  // Nothing decided is never a success, even with nothing refused.
  const kind =
    decided === 0
      ? skipped + failed > 0
        ? 'error'
        : 'warning'
      : skipped + failed === 0
        ? 'success'
        : 'warning'
  return { kind, message, description }
}

/**
 * Body of POST /findings/actions/verify and /reject-fix (by ids or by
 * filter). It answers 200 when some or all findings were refused: every
 * finding left alone is a row with a refusal code.
 */
export interface FixDecisionResult {
  updated?: number
  refused?: number
  reasons?: Record<string, number>
  rows?: { finding_id: string; code: string }[]
}

/**
 * The refusal codes the API sends for a verifier's decision on a claimed fix
 * (server: finding.RefusalCodes). Each has a plain sentence below.
 */
export const FIX_REFUSAL_CODES = [
  'not_found',
  'not_fix_applied',
  'evidence_required',
  'checklist_required',
  'missing_permission',
  'lifecycle_refused',
  'note_required',
  'approval_required',
  'changed',
  'not_allowed',
  'unavailable',
] as const

/** Why a verify or a reject left one finding alone, in plain words. */
export function fixRefusalText(t: Translate, code: string | undefined): string {
  switch (code) {
    case 'not_found':
      return t('findings.fixRefusal.not_found', 'Not found, or outside what you can see')
    case 'not_fix_applied':
      return t('findings.fixRefusal.not_fix_applied', 'No longer waiting for verification')
    case 'evidence_required':
      return t(
        'findings.fixRefusal.evidence_required',
        'A critical, P0 or known-exploited finding needs a retest that confirms the fix, or the verification checklist completed by another person'
      )
    case 'checklist_required':
      return t(
        'findings.fixRefusal.checklist_required',
        'Needs the verification checklist completed, or a retest that confirms the fix'
      )
    case 'missing_permission':
      return t('findings.fixRefusal.missing_permission', 'You do not have permission')
    case 'lifecycle_refused':
      return t(
        'findings.fixRefusal.lifecycle_refused',
        "Your organization's finding lifecycle does not allow it here: change the status on the finding"
      )
    case 'note_required':
      return t('findings.fixRefusal.note_required', 'Needs a longer note')
    case 'approval_required':
      return t(
        'findings.fixRefusal.approval_required',
        'Needs an approver: send it for approval from the finding'
      )
    case 'changed':
      return t('findings.fixRefusal.changed', 'Changed meanwhile: reload and try again')
    case 'unavailable':
      return t('findings.fixRefusal.unavailable', 'Could not be checked: try again')
    default:
      return t('findings.fixRefusal.not_allowed', 'This change is not allowed for it')
  }
}

/**
 * What a verify or a reject of claimed fixes did, for its toast. Nothing done
 * is an error that says why; a part done is a warning with the reasons; only
 * a decision that moved every finding is a success.
 */
export function summarizeFixDecision(
  result: FixDecisionResult | undefined,
  action: 'verified' | 'rejected',
  t: Translate
): BulkSummary {
  const updated = result?.updated ?? 0
  const reasons = Object.entries(result?.reasons ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
  const refused = result?.refused ?? reasons.reduce((sum, [, n]) => sum + n, 0)
  const total = updated + refused
  const reasonList = reasons
    .map(([code, n]) =>
      t('findings.fixDecision.reasonCount', '{reason} ({count})', {
        reason: fixRefusalText(t, code),
        count: n,
      })
    )
    .join('. ')
  const oneReason = reasons.length === 1 ? fixRefusalText(t, reasons[0][0]) : undefined

  if (updated > 0 && refused === 0) {
    return {
      kind: 'success',
      message:
        action === 'verified'
          ? t('findings.verifyGroup.verified', '{count} findings verified', { count: updated })
          : t(
              'findings.verifyGroup.rejected',
              '{count} findings rejected, sent back to the assignee',
              {
                count: updated,
              }
            ),
    }
  }
  if (updated === 0) {
    const message =
      action === 'verified'
        ? oneReason
          ? t('findings.fixDecision.noneVerifiedBecause', 'Nothing was verified: {reason}', {
              reason: oneReason,
            })
          : t('findings.fixDecision.noneVerified', 'Nothing was verified')
        : oneReason
          ? t('findings.fixDecision.noneRejectedBecause', 'Nothing was rejected: {reason}', {
              reason: oneReason,
            })
          : t('findings.fixDecision.noneRejected', 'Nothing was rejected')
    return {
      // Nothing refused either: the queue was already empty (someone else
      // decided it meanwhile). Not an error, never a success.
      kind: refused > 0 ? 'error' : 'warning',
      message:
        refused > 0
          ? message
          : t(
              'findings.fixDecision.nothingWaiting',
              'Nothing was waiting for verification here any more'
            ),
      description: oneReason ? undefined : reasonList || undefined,
    }
  }
  return {
    kind: 'warning',
    message:
      action === 'verified'
        ? t('findings.fixDecision.someVerified', '{updated} of {total} verified', {
            updated,
            total,
          })
        : t('findings.fixDecision.someRejected', '{updated} of {total} rejected', {
            updated,
            total,
          }),
    description: t('findings.fixDecision.notDone', '{count} not changed: {reasons}', {
      count: refused,
      reasons: reasonList,
    }),
  }
}
