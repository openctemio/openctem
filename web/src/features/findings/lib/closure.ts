/**
 * Why a closed finding is closed (closure reason) and how a closing claim was
 * proven (verification). The server owns both sets
 * (api/pkg/domain/vulnerability/closure.go); this module holds the reasons a
 * person may choose per status and their translated labels.
 */

import type { FindingStatus } from '../types'

export type ClosureReason =
  | 'fixed'
  | 'mitigated'
  | 'obsolete_asset'
  | 'obsolete_source'
  | 'obsolete_rule'
  | 'component_not_present'
  | 'vulnerable_code_not_present'
  | 'vulnerable_code_not_in_execute_path'
  | 'vulnerable_code_cannot_be_controlled_by_adversary'
  | 'inline_mitigations_already_exist'
  | 'detection_error'
  | 'test_or_example_code'
  | 'risk_accepted'
  | 'compensating_control'
  | 'wont_fix'
  | 'no_fix_available'
  | 'duplicate'
  | 'correlated'
  | 'unknown'

export type Verification =
  | 'covered_scan'
  | 'retest'
  | 'source_reported'
  | 'vex_statement'
  | 'security_review'
  | 'attested'
  | 'none'
  | 'unknown'

/** The reasons a person may choose when requesting or making a closure. */
export const PERSON_CLOSURE_REASONS: Partial<Record<FindingStatus, ClosureReason[]>> = {
  resolved: ['fixed', 'mitigated'],
  false_positive: [
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
    'detection_error',
    'test_or_example_code',
  ],
  accepted: ['risk_accepted', 'compensating_control', 'wont_fix', 'no_fix_available'],
}

const REASON_FALLBACK: Record<ClosureReason, string> = {
  fixed: 'Fixed',
  mitigated: 'Mitigated by a control',
  obsolete_asset: 'Asset retired',
  obsolete_source: 'Source removed',
  obsolete_rule: 'Check or rule changed',
  component_not_present: 'Component not present',
  vulnerable_code_not_present: 'Vulnerable code not present',
  vulnerable_code_not_in_execute_path: 'Vulnerable code not in the execution path',
  vulnerable_code_cannot_be_controlled_by_adversary: 'Cannot be controlled by an attacker',
  inline_mitigations_already_exist: 'Mitigations already in place',
  detection_error: 'Scanner was wrong',
  test_or_example_code: 'Test or example code',
  risk_accepted: 'Risk accepted',
  compensating_control: 'Compensating control',
  wont_fix: "Won't fix",
  no_fix_available: 'No fix available',
  duplicate: 'Duplicate',
  correlated: 'Linked by correlation',
  unknown: 'Not recorded',
}

const VERIFICATION_FALLBACK: Record<Verification, string> = {
  covered_scan: 'Covering scan',
  retest: 'Retest',
  source_reported: 'Reported by the source',
  vex_statement: 'VEX statement',
  security_review: 'Security review',
  attested: 'Closed without proof',
  none: 'Nothing to verify',
  unknown: 'Not recorded',
}

type Translate = (key: string, fallback?: string) => string

export function closureReasonLabel(t: Translate, reason: string): string {
  const fallback = REASON_FALLBACK[reason as ClosureReason] ?? reason
  return t(`findings.closureReason.${reason}`, fallback)
}

export function verificationLabel(t: Translate, verification: string): string {
  const fallback = VERIFICATION_FALLBACK[verification as Verification] ?? verification
  return t(`findings.verification.${verification}`, fallback)
}

/** Every reason and verification code, for the dictionary completeness test. */
export const ALL_CLOSURE_REASONS = Object.keys(REASON_FALLBACK) as ClosureReason[]
export const ALL_VERIFICATIONS = Object.keys(VERIFICATION_FALLBACK) as Verification[]
