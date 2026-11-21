import { describe, expect, it } from 'vitest'
import { authorizedByText } from '../scope-entry'

describe('authorizedByText', () => {
  it('names the CI trust that manages an entry', () => {
    expect(
      authorizedByText({ origin: 'ci_trust', managed_by: [{ trust_name: 'example-ci' }] })
    ).toBe('CI trust example-ci')
  })
  it('says what authorizes each source', () => {
    expect(authorizedByText({ authorization_source: 'program' })).toBe('A bug bounty program')
    expect(authorizedByText({ authorization_source: 'authorization_letter' })).toBe(
      'A letter of authorization'
    )
    expect(authorizedByText({ authorization_source: 'self_attestation' })).toBe(
      'Attested by a member'
    )
  })
  it('defaults to ownership, also for a ci_trust entry no trust claims any more', () => {
    expect(authorizedByText({})).toBe('Our organization owns it')
    expect(authorizedByText({ origin: 'ci_trust', managed_by: [] })).toBe(
      'Our organization owns it'
    )
  })
  it('goes through the catalog', () => {
    const t = (k: string) => `[${k}]`
    expect(authorizedByText({ authorization_source: 'ownership' }, t)).toBe(
      '[scope.authorizedBy.ownership]'
    )
  })
})
