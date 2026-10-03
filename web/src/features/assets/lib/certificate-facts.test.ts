import { describe, expect, it } from 'vitest'
import type { Asset } from '../types'
import { certDaysLeft, certIssuer, certStatus, httpStatus, websiteTLS } from './certificate-facts'

const NOW = Date.parse('2026-10-01T00:00:00Z')
const DAY = 24 * 60 * 60 * 1000

function asset(metadata: Record<string, unknown>, name = 'x.example.com'): Asset {
  return { id: '1', name, type: 'certificate', metadata } as unknown as Asset
}

describe('certStatus', () => {
  it('is unknown, not valid, when the certificate has no expiry', () => {
    expect(certStatus(asset({}), NOW)).toBe('unknown')
    expect(certStatus(asset({ cert_not_after: 'not a date' }), NOW)).toBe('unknown')
  })

  it('reads the flat form key', () => {
    const iso = new Date(NOW + 10 * DAY).toISOString()
    expect(certStatus(asset({ cert_not_after: iso }), NOW)).toBe('expiring')
  })

  it('reads the nested map ingest writes', () => {
    const ok = new Date(NOW + 200 * DAY).toISOString()
    const gone = new Date(NOW - 2 * DAY).toISOString()
    expect(certStatus(asset({ certificate: { not_after: ok } }), NOW)).toBe('valid')
    expect(certStatus(asset({ certificate: { not_after: gone } }), NOW)).toBe('expired')
    expect(certDaysLeft(asset({ certificate: { not_after: gone } }), NOW)).toBe(-2)
  })

  it("trusts the scanner's expired flag when there is no date", () => {
    expect(certStatus(asset({ certificate: { expired: true } }), NOW)).toBe('expired')
  })
})

describe('certIssuer', () => {
  it('prefers the form key, then the ingest organisation, then the CN', () => {
    expect(certIssuer(asset({ cert_issuer: 'Manual' }))).toBe('Manual')
    expect(certIssuer(asset({ certificate: { issuer_org: 'Org', issuer_cn: 'CN' } }))).toBe('Org')
    expect(certIssuer(asset({ certificate: { issuer_cn: 'R11' } }))).toBe('R11')
    expect(certIssuer(asset({}))).toBeUndefined()
  })
})

describe('website facts', () => {
  it('has no HTTP status unless one was recorded (never a default 200)', () => {
    expect(httpStatus(asset({}))).toBeNull()
    expect(httpStatus(asset({ http_status: 404 }))).toBe(404)
    expect(httpStatus(asset({ status_code: '301' }))).toBe(301)
  })

  it('reports TLS only as recorded, else unknown (never "insecure")', () => {
    expect(websiteTLS(asset({}, 'https://shop.example.com'))).toBeNull()
    expect(websiteTLS(asset({ ssl: false }))).toBe(false)
    expect(websiteTLS(asset({ ssl: true }))).toBe(true)
    expect(websiteTLS(asset({ tls: true }))).toBe(true)
  })
})
