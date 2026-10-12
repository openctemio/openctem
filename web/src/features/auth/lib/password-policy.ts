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

/** The first rule the password breaks, as a sentence; null when it meets the policy. */
export function passwordPolicyIssue(password: string, policy: PasswordPolicy): string | null {
  if (byteLength(password) < policy.min_length) {
    return `Password must be at least ${policy.min_length} characters long`
  }
  if (policy.require_uppercase && !UPPER.test(password)) {
    return 'Password must contain an uppercase letter'
  }
  if (policy.require_lowercase && !LOWER.test(password)) {
    return 'Password must contain a lowercase letter'
  }
  if (policy.require_number && !NUMBER.test(password)) {
    return 'Password must contain a number'
  }
  if (policy.require_special && !SPECIAL.test(password)) {
    return 'Password must contain a symbol'
  }
  return null
}

function joinWithAnd(parts: string[]): string {
  if (parts.length <= 1) return parts.join('')
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`
}

/** "At least 12 characters, with an uppercase letter, a lowercase letter and a number." */
export function describePasswordPolicy(policy: PasswordPolicy): string {
  const classes: string[] = []
  if (policy.require_uppercase) classes.push('an uppercase letter')
  if (policy.require_lowercase) classes.push('a lowercase letter')
  if (policy.require_number) classes.push('a number')
  if (policy.require_special) classes.push('a symbol')
  const base = `At least ${policy.min_length} characters`
  return classes.length ? `${base}, with ${joinWithAnd(classes)}.` : `${base}.`
}

/** "1 hour", "90 minutes", "24 hours", "2 days". */
export function formatLinkLifetime(minutes: number): string {
  const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? '' : 's'}`
  if (minutes >= 1440 && minutes % 1440 === 0) return plural(minutes / 1440, 'day')
  if (minutes >= 60 && minutes % 60 === 0) return plural(minutes / 60, 'hour')
  return plural(minutes, 'minute')
}
