import { describe, it, expect } from 'vitest'
import { mergeFindingFilter } from '../finding-filter'

describe('mergeFindingFilter (task edit)', () => {
  it('keeps the other scope conditions and replaces the linked findings', () => {
    expect(
      mergeFindingFilter({ cve_ids: ['CVE-2024-1234'], finding_ids: ['a'] }, { finding_ids: ['b'] })
    ).toEqual({ cve_ids: ['CVE-2024-1234'], finding_ids: ['b'] })
  })
  it('never adds linked findings to a campaign tracked by a fix', () => {
    expect(mergeFindingFilter({ remediation_key: 'sol:x' }, { finding_ids: ['b'] })).toBeUndefined()
  })
  it('leaves the scope untouched when nothing is linked', () => {
    expect(mergeFindingFilter({ severity: 'high' }, undefined)).toBeUndefined()
  })
})
