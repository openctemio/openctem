import { describe, expect, it } from 'vitest'
import type { EASMVerifiedDomain } from '@/lib/api/generated'
import { domainFor } from '../use-easm-verified-domains'

const row = (domain: string, status: string, purpose = 'easm'): EASMVerifiedDomain => ({
  id: domain,
  domain,
  status,
  purpose,
  managed: purpose !== 'easm',
  created_at: '2026-10-05T00:00:00Z',
})

describe('domainFor', () => {
  const domains = [row('example.com', 'pending'), row('corp.example', 'verified', 'sso')]

  it('finds the row of the same name, case-insensitively', () => {
    expect(domainFor('Example.com', domains)?.domain).toBe('example.com')
  })

  it('falls back to a verified parent only', () => {
    expect(domainFor('shop.corp.example', domains)?.domain).toBe('corp.example')
    expect(domainFor('www.example.com', domains)).toBeUndefined()
  })

  it('does not match a look-alike suffix', () => {
    expect(domainFor('evilcorp.example', domains)).toBeUndefined()
    expect(domainFor(undefined, domains)).toBeUndefined()
  })
})
