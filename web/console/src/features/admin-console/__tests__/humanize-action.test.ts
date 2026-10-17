import { describe, it, expect } from 'vitest'
// Static import: the component tree is heavy to transform, and a dynamic
// import inside the test counted that cold transform against the 5s timeout.
import { humanizeAction } from '../components/admin-activity-table'

describe('humanizeAction', () => {
  it('reads audit actions as words, with acronyms kept', () => {
    expect(humanizeAction('organization.idp_create')).toBe('Identity provider create')
    expect(humanizeAction('console.mfa_enrolled')).toBe('Two-step verification enrolled')
    expect(humanizeAction('organization.sso_enforcement')).toBe('SSO enforcement')
  })
})
