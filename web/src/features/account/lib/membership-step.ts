/**
 * The one next step when an organization refuses to open for this session.
 * The API decides (token exchange); this maps its refusal code to what the
 * person can do. There is never a step that skips the organization's rule:
 * two-factor is set up or proved, and single sign-on is done at its provider.
 */
export type MembershipRefusal = 'two_factor_setup' | 'two_factor_sign_in' | 'single_sign_on'

export function membershipStep(code: string | undefined): MembershipRefusal | null {
  switch (code) {
    case 'MFA_ENROLLMENT_REQUIRED':
      return 'two_factor_setup'
    case 'MFA_REQUIRED_BY_POLICY':
      return 'two_factor_sign_in'
    case 'SSO_REQUIRED':
      return 'single_sign_on'
    default:
      return null
  }
}
