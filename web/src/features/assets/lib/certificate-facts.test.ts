import { describe, expect, it } from 'vitest'
import type { Asset } from '../types'
import {
  certDaysLeft,
  certIsWildcard,
  certIssuer,
  certKeySize,
  certSans,
  certStatus,
  certSubject,
} from './certificate-facts'

const NOW = Date.parse('2026-10-01T00:00:00Z')
const DAY = 24 * 60 * 60 * 1000

function asset(metadata: Record<string, unknown>, name = 'x.example.com'): Asset {
  return { id: '1', name, type: 'certificate', metadata } as unknown as Asset
}

describe('certStatus', () => {
  it('is unknown, not valid, when the certificate has no expiry', () => {
    expect(certStatus(asset({}), NOW)).toBe('unknown')
    expect(certStatus(asset({ not_after: 'not a date' }), NOW)).toBe('unknown')
  })

  it('reads the flat schema key, and never a key outside the schema', () => {
    const iso = new Date(NOW + 10 * DAY).toISOString()
    expect(certStatus(asset({ not_after: iso }), NOW)).toBe('expiring')
    expect(certStatus(asset({ cert_not_after: iso }), NOW)).toBe('unknown')
  })

  it('reads the keys ingest stores (the CTIS block promoted)', () => {
    const ok = new Date(NOW + 200 * DAY).toISOString()
    const gone = new Date(NOW - 2 * DAY).toISOString()
    expect(certStatus(asset({ not_after: ok }), NOW)).toBe('valid')
    expect(certStatus(asset({ not_after: gone }), NOW)).toBe('expired')
    expect(certDaysLeft(asset({ not_after: gone }), NOW)).toBe(-2)
    // A block is promoted before a row is stored; it is never read.
    expect(certStatus(asset({ certificate: { not_after: ok } }), NOW)).toBe('unknown')
  })

  it("trusts the scanner's expired flag when there is no date", () => {
    expect(certStatus(asset({ is_expired: true }), NOW)).toBe('expired')
  })
})

describe('certIssuer', () => {
  it('prefers the organisation, then the CN', () => {
    expect(certIssuer(asset({ issuer_org: 'Org A', issuer_cn: 'CN A' }))).toBe('Org A')
    expect(certIssuer(asset({ issuer_cn: 'CN A' }))).toBe('CN A')
    expect(certIssuer(asset({}))).toBeUndefined()
  })
})

describe('certificate details', () => {
  it('reads subject, SANs, key size and wildcard', () => {
    const ingest = asset({
      subject_cn: '*.example.com',
      sans: ['*.example.com', 'example.com'],
      key_size: 2048,
    })
    expect(certSubject(ingest)).toBe('*.example.com')
    expect(certSans(ingest)).toEqual(['*.example.com', 'example.com'])
    expect(certKeySize(ingest)).toBe(2048)
    expect(certIsWildcard(ingest)).toBe(true)

    const flat = asset({ subject_cn: 'a.example.com', sans: ['a.example.com', 'b.example.com'] })
    expect(certSubject(flat)).toBe('a.example.com')
    expect(certSans(flat)).toEqual(['a.example.com', 'b.example.com'])
  })

  it('does not say "not a wildcard" when nothing is known', () => {
    expect(certIsWildcard(asset({}))).toBeNull()
    expect(certKeySize(asset({}))).toBeNull()
  })
})
