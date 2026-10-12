import { describe, expect, it } from 'vitest'
import { isPendingSSOChange } from '../api/use-sso-changes'

describe('isPendingSSOChange', () => {
  it('recognizes a 202 pending change', () => {
    expect(isPendingSSOChange({ id: 'c1', kind: 'saml_config', status: 'pending' })).toBe(true)
  })

  it('does not mistake an applied config or provider for a pending change', () => {
    // SAML config (organization without an owner): no status field.
    expect(isPendingSSOChange({ idp_entity_id: 'x', enabled: true })).toBe(false)
    // Identity provider: has is_active, no kind/status.
    expect(isPendingSSOChange({ id: 'p1', provider: 'okta', is_active: true })).toBe(false)
    expect(isPendingSSOChange(undefined)).toBe(false)
    expect(isPendingSSOChange(null)).toBe(false)
  })
})
