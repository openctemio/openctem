/**
 * The password policy as the API reports it (GET /auth/providers,
 * `password_policy`). Every form that has a person choose a password, and
 * every text about the reset link, states these values; the web keeps no
 * copy of them. The server enforces the policy (and also refuses known
 * breached passwords); the checks here only give earlier feedback and are
 * never stricter than the server.
 */

export interface PasswordPolicy {
  min_length: number
  require_uppercase: boolean
  require_lowercase: boolean
  require_number: boolean
  require_special: boolean
  /** Lifetime of a forgot-password link, in minutes. */
  reset_link_valid_minutes: number
}

// The server counts bytes (Go len), so a multi-byte character counts as
// more than one; counting the same way keeps the check from being stricter.
function byteLength(value: string): number {
  return new TextEncoder().encode(value).length
}

const UPPER = /\p{Lu}/u
const LOWER = /\p{Ll}/u
const NUMBER = /\p{N}/u
const SPECIAL = /[\p{P}\p{S}]/u

/**
 * Translator the texts below go through: the web app's `t` (key, English
 * text, values). Without one the English text is used, with `{name}` values
 * filled in (tests, and callers outside the i18n provider).
 */
export type PolicyTranslate = (
  key: string,
  fallback: string,
  vars?: Record<string, string | number>
) => string

const english: PolicyTranslate = (_key, fallback, vars) =>
  fallback.replace(/\{(\w+)\}/g, (whole, name: string) =>
    vars && name in vars ? String(vars[name]) : whole
  )

/** The first rule the password breaks, as a sentence; null when it meets the policy. */
export function passwordPolicyIssue(
  password: string,
  policy: PasswordPolicy,
  t: PolicyTranslate = english
): string | null {
  if (byteLength(password) < policy.min_length) {
    return t(
      'auth.passwordPolicy.issueLength',
      'Password must be at least {count} characters long',
      { count: policy.min_length }
    )
  }
  if (policy.require_uppercase && !UPPER.test(password)) {
    return t('auth.passwordPolicy.issueUppercase', 'Password must contain an uppercase letter')
  }
  if (policy.require_lowercase && !LOWER.test(password)) {
    return t('auth.passwordPolicy.issueLowercase', 'Password must contain a lowercase letter')
  }
  if (policy.require_number && !NUMBER.test(password)) {
    return t('auth.passwordPolicy.issueNumber', 'Password must contain a number')
  }
  if (policy.require_special && !SPECIAL.test(password)) {
    return t('auth.passwordPolicy.issueSymbol', 'Password must contain a symbol')
  }
  return null
}

function joinWithAnd(parts: string[], t: PolicyTranslate): string {
  if (parts.length <= 1) return parts.join('')
  return t('auth.passwordPolicy.listAnd', '{list} and {last}', {
    list: parts.slice(0, -1).join(', '),
    last: parts[parts.length - 1],
  })
}

/** "At least 12 characters, with an uppercase letter, a lowercase letter and a number." */
export function describePasswordPolicy(
  policy: PasswordPolicy,
  t: PolicyTranslate = english
): string {
  const classes: string[] = []
  if (policy.require_uppercase)
    classes.push(t('auth.passwordPolicy.uppercase', 'an uppercase letter'))
  if (policy.require_lowercase)
    classes.push(t('auth.passwordPolicy.lowercase', 'a lowercase letter'))
  if (policy.require_number) classes.push(t('auth.passwordPolicy.number', 'a number'))
  if (policy.require_special) classes.push(t('auth.passwordPolicy.symbol', 'a symbol'))
  const base = t('auth.passwordPolicy.atLeast', 'At least {count} characters', {
    count: policy.min_length,
  })
  return classes.length
    ? t('auth.passwordPolicy.withClasses', '{base}, with {classes}.', {
        base,
        classes: joinWithAnd(classes, t),
      })
    : t('auth.passwordPolicy.baseOnly', '{base}.', { base })
}

/** "1 hour", "90 minutes", "24 hours", "2 days". */
export function formatLinkLifetime(minutes: number, t: PolicyTranslate = english): string {
  if (minutes >= 1440 && minutes % 1440 === 0) {
    const count = minutes / 1440
    return t('auth.passwordPolicy.days', count === 1 ? '{count} day' : '{count} days', { count })
  }
  if (minutes >= 60 && minutes % 60 === 0) {
    const count = minutes / 60
    return t('auth.passwordPolicy.hours', count === 1 ? '{count} hour' : '{count} hours', {
      count,
    })
  }
  return t('auth.passwordPolicy.minutes', minutes === 1 ? '{count} minute' : '{count} minutes', {
    count: minutes,
  })
}
