/**
 * Human text for every scope code the API returns (RFC-054 §6.1, §6.5).
 *
 * - Refusal codes (lower case) say why a target may not be probed; they come
 *   with POST /scope/check results, `TARGET_OUT_OF_SCOPE` error details and
 *   the attribution view.
 * - Error codes (upper case) refuse a scope change (create, approve, widen).
 * - Fix actions are what the caller may do about a refusal.
 *
 * Each has an i18n key (en + vi catalogs) and an English fallback. A code the
 * web does not know falls back to the server's message, never to the raw
 * code, so a new server code still reads as a sentence.
 */

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** Refusal codes (§6.5), with a short label and a sentence. */
export const SCOPE_REFUSAL_TEXT = {
  invalid_target: {
    label: 'Not a valid target',
    message:
      'Not a valid scan target here: malformed, loopback, link-local, cloud metadata, or a private address outside every scan zone.',
  },
  deny_list: {
    label: 'Not allowed by the platform',
    message: 'The platform does not allow this target.',
  },
  excluded: {
    label: 'Excluded',
    message: 'An active scope exclusion covers this target.',
  },
  rejected: {
    label: 'Marked not ours',
    message: 'Your organization marked this name, or a name above it, as not yours.',
  },
  needs_review: {
    label: 'Needs review',
    message: "This asset's ownership is waiting for review.",
  },
  candidate: {
    label: 'Candidate',
    message: 'This asset is a discovery candidate; its ownership is not confirmed.',
  },
  dependency: {
    label: 'Third-party infrastructure',
    message:
      'This name runs on third-party infrastructure; only passive and takeover checks apply.',
  },
  monitor_only: {
    label: 'Monitor only',
    message: 'This asset is watched passively only.',
  },
  no_entry: {
    label: 'Not in scope',
    message: 'No scope entry, seed or verified domain covers this target.',
  },
  entry_pending: {
    label: 'Waiting for approval',
    message: 'The scope entry that covers this target is waiting for approval.',
  },
  entry_expired: {
    label: 'Entry expired',
    message: 'The scope entry that covered this target has expired.',
  },
  entry_inactive: {
    label: 'Entry deactivated',
    message: 'The scope entry that covers this target is deactivated.',
  },
  tier_exceeds: {
    label: 'Tier too high',
    message: "The scope entries covering this target do not allow this probe's tier.",
  },
  proof_required: {
    label: 'Proof needed',
    message: 'This probe needs a verified domain of your organization.',
  },
  out_of_data_scope: {
    label: 'Outside your data scope',
    message: 'This asset is outside your data scope.',
  },
  not_an_asset: {
    label: 'Not one of your assets',
    message: 'You may scan only assets in your data scope.',
  },
  zone_none: {
    label: 'No scan zone',
    message: 'No scan zone covers this private target.',
  },
  zone_no_sensor: {
    label: 'Zone has no sensor',
    message: 'The scan zone of this target has no sensors.',
  },
  zone_sensor_mismatch: {
    label: 'Wrong sensor for the zone',
    message: "The chosen sensor is not in this target's scan zone.",
  },
  program_platform: {
    label: 'Program target',
    message: 'Platform sensors never probe bug-bounty program targets; use your own sensors.',
  },
} as const satisfies Record<string, { label: string; message: string }>

export type ScopeRefusalCode = keyof typeof SCOPE_REFUSAL_TEXT
export const SCOPE_REFUSAL_CODES = Object.keys(SCOPE_REFUSAL_TEXT) as ScopeRefusalCode[]

/** Error codes of the scope write routes (§6.1, §6.7, §8) and the scan gate. */
export const SCOPE_ERROR_TEXT = {
  PUBLIC_SUFFIX:
    'A public suffix (such as com.vn or azurewebsites.net) cannot be a scope entry. Enter a domain your organization registered.',
  DENY_LIST: 'The platform does not allow this target as a scope entry.',
  CIDR_TOO_LARGE:
    'This address range is larger than the platform allows. Split it into smaller ranges.',
  ONE_OFF_TOO_LONG: 'A one-off entry cannot last longer than your organization allows.',
  ONE_OFF_DISABLED: 'Your organization does not allow one-off scope entries.',
  REASON_REQUIRED: 'Say why this target may be probed. The reason is kept in the audit log.',
  REQUEST_NOT_ALLOWED: 'Your organization does not accept scope requests from members.',
  REQUEST_MUST_BE_ONE_OFF: 'A request must expire. Choose how many days it lasts.',
  REQUEST_MUST_BE_SINGLE:
    'A request covers one name or address. Wildcards and ranges need an approver.',
  REQUEST_TIER: 'A request cannot ask for intrusive (T2) probes.',
  INTRUSIVE_NEEDS_EXPIRY: 'Intrusive (T2) entries must expire and need an approval.',
  WIDENING_NEEDS_APPROVER: 'Only a scope approver can widen what may be probed.',
  ENTRY_SELF_APPROVAL: 'You requested this change, so another approver must approve it.',
  SELF_APPROVAL_NOT_ALLOWED:
    'You can approve your own entry only as an owner, and only when nobody else can approve it. Ask one of the approvers listed on the entry.',
  SELF_APPROVAL_REASON_REQUIRED:
    'Say why this entry may take effect without a second person. The reason is kept in the audit log.',
  SELF_APPROVAL_NEEDS_TOTP:
    'Approving your own entry needs a code from your authenticator app. Turn on two-factor authentication in your account first.',
  SELF_APPROVAL_INVALID_CODE:
    'That code is wrong or was already used. Wait for your authenticator to show a new one.',
  REMINDER_TOO_SOON: 'The approvers were reminded less than an hour ago.',
  ENTRY_ALREADY_APPROVED: 'You already approved this entry.',
  ENTRY_NOT_PENDING: 'This entry is not waiting for approval any more.',
  ENTRY_EXPIRED: 'This entry expired. Renew it with a new expiry instead.',
  ENTRY_REJECTED: 'This entry was rejected. Create a new one if it is still needed.',
  STEP_UP_REQUIRED: 'Confirm your identity to make this change.',
  STEP_UP_UNAVAILABLE:
    'This change needs you to confirm your identity, and your account has no way to do that here. Sign out and sign in again, then retry.',
  PROOF_REQUIRED:
    'These targets need a verified domain of your organization for this kind of scan. Verify the domain, or run the scan on your own sensor.',
  TARGET_OUT_OF_SCOPE: 'Some targets may not be scanned. See each target for the reason.',
  WILDCARD_TARGET:
    'A wildcard names a set of hosts, not a host. Choose the hosts to scan, or run a discovery scan on the domain.',
} as const satisfies Record<string, string>

export type ScopeErrorCode = keyof typeof SCOPE_ERROR_TEXT
export const SCOPE_ERROR_CODES = Object.keys(SCOPE_ERROR_TEXT) as ScopeErrorCode[]

/** Fix actions (§6.5) as button labels. */
export const SCOPE_FIX_TEXT = {
  add_entry: 'Add to scope',
  allow_temporarily: 'Allow for {days} days',
  request_access: 'Request access',
  approve_entry: 'Approve the entry',
  renew_entry: 'Renew for {days} days',
  activate_entry: 'Activate the entry',
  remove_exclusion: 'Review the exclusion',
  review_asset: 'Review ownership',
  verify_domain: 'Verify {domain}',
  use_tenant_sensor: 'Use your own sensor',
  add_zone: 'Set up a scan zone',
  contact_support: 'Contact support',
  raise_tier: 'Raise the tier',
} as const satisfies Record<string, string>

export type ScopeFixAction = keyof typeof SCOPE_FIX_TEXT
export const SCOPE_FIX_ACTIONS = Object.keys(SCOPE_FIX_TEXT) as ScopeFixAction[]

function has<T extends object>(obj: T, key: string): key is Extract<keyof T, string> {
  return Object.prototype.hasOwnProperty.call(obj, key)
}

export function isScopeRefusalCode(code: unknown): code is ScopeRefusalCode {
  return typeof code === 'string' && has(SCOPE_REFUSAL_TEXT, code)
}

export function isScopeErrorCode(code: unknown): code is ScopeErrorCode {
  return typeof code === 'string' && has(SCOPE_ERROR_TEXT, code)
}

/** Short label of a refusal code ("Not in scope"). */
export function scopeRefusalLabel(t: Translate, code: string | undefined): string {
  if (!isScopeRefusalCode(code)) return t('scope.refusal.label.unknown', 'Refused')
  return t(`scope.refusal.label.${code}`, SCOPE_REFUSAL_TEXT[code].label)
}

/**
 * The sentence for a refusal code. Unknown codes use the server's message,
 * or a generic sentence.
 */
export function scopeRefusalMessage(
  t: Translate,
  code: string | undefined,
  serverMessage?: string
): string {
  if (isScopeRefusalCode(code)) {
    return t(`scope.refusal.message.${code}`, SCOPE_REFUSAL_TEXT[code].message)
  }
  return serverMessage || t('scope.refusal.message.unknown', 'This target may not be scanned.')
}

/** The message for a scope error code, or `undefined` for other codes. */
export function scopeErrorText(t: Translate, code: string | undefined): string | undefined {
  if (!isScopeErrorCode(code)) return undefined
  return t(`scope.error.${code}`, SCOPE_ERROR_TEXT[code])
}

/** Button label of a fix action. */
export function scopeFixLabel(
  t: Translate,
  fix: { action?: string; days?: number; domain?: string; pattern?: string }
): string {
  const action = fix.action ?? ''
  const vars = { days: fix.days ?? 7, domain: fix.domain ?? fix.pattern ?? '' }
  if (!has(SCOPE_FIX_TEXT, action)) return action.replace(/_/g, ' ')
  return t(`scope.fix.${action}`, SCOPE_FIX_TEXT[action as ScopeFixAction], vars)
}

/**
 * The human message of an error thrown by the API client: a known scope
 * code's sentence first, then the server's message, then `fallback`.
 */
export function scopeErrorMessage(t: Translate, err: unknown, fallback: string): string {
  const e = err as { code?: unknown; message?: unknown } | null | undefined
  const known = scopeErrorText(t, typeof e?.code === 'string' ? e.code : undefined)
  if (known) return known
  if (e && typeof e.message === 'string' && e.message) return e.message
  return fallback
}
