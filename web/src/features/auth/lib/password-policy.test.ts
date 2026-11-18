import { describe, expect, it } from 'vitest'

import { translate } from '@/lib/i18n'
import viAuth from '@/lib/i18n/dictionaries/vi/auth.json'

import {
  describePasswordPolicy,
  formatLinkLifetime,
  passwordPolicyIssue,
  type PasswordPolicy,
} from './password-policy'

const policy: PasswordPolicy = {
  min_length: 12,
  require_uppercase: true,
  require_lowercase: true,
  require_number: true,
  require_special: false,
  reset_link_valid_minutes: 60,
}

describe('passwordPolicyIssue', () => {
  it('accepts a password that meets the policy', () => {
    expect(passwordPolicyIssue('Correct1Horse', policy)).toBeNull()
  })

  it('states the minimum the API reports', () => {
    expect(passwordPolicyIssue('Short1', policy)).toBe(
      'Password must be at least 12 characters long'
    )
    expect(passwordPolicyIssue('Short1Short1', { ...policy, min_length: 20 })).toBe(
      'Password must be at least 20 characters long'
    )
  })

  it('checks each required character class', () => {
    expect(passwordPolicyIssue('correct1horse', policy)).toMatch(/uppercase/)
    expect(passwordPolicyIssue('CORRECT1HORSE', policy)).toMatch(/lowercase/)
    expect(passwordPolicyIssue('CorrectHorse!', policy)).toMatch(/number/)
    expect(passwordPolicyIssue('Correct1Horse', { ...policy, require_special: true })).toMatch(
      /symbol/
    )
    expect(passwordPolicyIssue('Correct1Horse!', { ...policy, require_special: true })).toBeNull()
  })

  it('counts length as the server does (bytes), so it is never stricter', () => {
    // 6 characters, 12 UTF-8 bytes: the server accepts the length.
    expect(passwordPolicyIssue('ÄÖÜäöü', { ...policy, require_number: false })).toBeNull()
  })
})

describe('describePasswordPolicy', () => {
  it('lists the rules in a sentence', () => {
    expect(describePasswordPolicy(policy)).toBe(
      'At least 12 characters, with an uppercase letter, a lowercase letter and a number.'
    )
    expect(
      describePasswordPolicy({
        ...policy,
        require_uppercase: false,
        require_lowercase: false,
        require_number: false,
      })
    ).toBe('At least 12 characters.')
  })
})

describe('formatLinkLifetime', () => {
  it('uses the largest whole unit', () => {
    expect(formatLinkLifetime(60)).toBe('1 hour')
    expect(formatLinkLifetime(90)).toBe('90 minutes')
    expect(formatLinkLifetime(1440)).toBe('1 day')
    expect(formatLinkLifetime(2880)).toBe('2 days')
    expect(formatLinkLifetime(180)).toBe('3 hours')
  })
})

describe('the texts go through the translator', () => {
  // The Vietnamese catalog, through the same interpolation as the app (plural blocks included).
  const vi = (key: string, fallback: string, vars?: Record<string, string | number>) =>
    translate(viAuth, key, fallback, vars)

  it('words the rules, the issue and the link lifetime in the reader’s language', () => {
    expect(describePasswordPolicy(policy, vi)).toBe(
      'Ít nhất 12 ký tự, gồm một chữ hoa, một chữ thường và một chữ số.'
    )
    expect(passwordPolicyIssue('short', policy, vi)).toBe('Mật khẩu phải có ít nhất 12 ký tự')
    expect(formatLinkLifetime(30, vi)).toBe('30 phút')
    expect(formatLinkLifetime(1440, vi)).toBe('1 ngày')
  })
})
