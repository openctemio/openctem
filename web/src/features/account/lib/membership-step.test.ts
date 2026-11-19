import { describe, expect, it } from 'vitest'

import { membershipStep } from './membership-step'

describe('membershipStep', () => {
  it('maps each refusal to its one step', () => {
    expect(membershipStep('MFA_ENROLLMENT_REQUIRED')).toBe('two_factor_setup')
    expect(membershipStep('MFA_REQUIRED_BY_POLICY')).toBe('two_factor_sign_in')
    expect(membershipStep('SSO_REQUIRED')).toBe('single_sign_on')
  })

  it('offers no step for any other answer', () => {
    for (const code of [undefined, '', 'FORBIDDEN', 'TENANT_REQUIRED', 'sso_required']) {
      expect(membershipStep(code)).toBeNull()
    }
  })
})
