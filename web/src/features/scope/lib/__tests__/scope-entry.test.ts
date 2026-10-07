import { describe, expect, it } from 'vitest'
import {
  approvalsMissing,
  canApproveEntry,
  coversText,
  daysUntil,
  entryStatus,
  expiryText,
  patternForCoverage,
  wildcardApex,
} from '../scope-entry'

const NOW = Date.parse('2026-10-07T12:00:00Z')

describe('what an entry covers (RFC-054 §4.1: *.x is x and every name below it)', () => {
  it('reads a wildcard as the domain and its subdomains', () => {
    expect(coversText({ pattern: '*.vndirect.com.vn', covers: 'domain_and_subdomains' })).toBe(
      'vndirect.com.vn and every name below it'
    )
    // Without the server's reading, the pattern still says it.
    expect(coversText({ pattern: '**.acme.io' })).toBe('acme.io and every name below it')
  })

  it('reads an exact name and addresses', () => {
    expect(coversText({ pattern: 'api.acme.io', covers: 'name' })).toBe('api.acme.io only')
    expect(coversText({ pattern: '203.0.113.0/24', covers: 'addresses' })).toBe(
      'every address in 203.0.113.0/24'
    )
    expect(coversText({ pattern: '203.0.113.7', covers: 'addresses' })).toBe('203.0.113.7 only')
  })

  it('reads a plain domain or address by its kind when the server sent no covers', () => {
    expect(coversText({ pattern: 'shop.globex.io', target_type: 'domain' })).toBe(
      'shop.globex.io only'
    )
    expect(coversText({ pattern: '203.0.113.0/24', target_type: 'ip_range' })).toBe(
      'every address in 203.0.113.0/24'
    )
  })

  it('turns a coverage choice into the pattern the API stores', () => {
    expect(patternForCoverage('acme.io', 'subdomains')).toBe('*.acme.io')
    expect(patternForCoverage('acme.io', 'name')).toBe('acme.io')
    expect(patternForCoverage('*.acme.io', 'name')).toBe('acme.io')
    expect(wildcardApex('acme.io')).toBe('')
  })
})

describe('expiry', () => {
  it('says how long is left, and when it ran out', () => {
    expect(expiryText(undefined, NOW)).toBe('Permanent')
    expect(expiryText('2026-10-14T12:00:00Z', NOW)).toBe('Expires in 7 days')
    expect(expiryText('2026-10-07T15:00:00Z', NOW)).toBe('Expires in 3 hours')
    expect(expiryText('2026-10-05T12:00:00Z', NOW)).toBe('Expired 2 days ago')
    expect(daysUntil('2026-10-10T12:00:00Z', NOW)).toBe(3)
  })
})

describe('approving', () => {
  const pending = {
    status: 'pending',
    created_by: { kind: 'user', id: 'requester' },
    approvals: [{ user_id: 'first' }],
    approvals_required: 2,
  }

  it('lets another approver approve a pending entry once', () => {
    expect(canApproveEntry(pending, 'second')).toBe(true)
    expect(approvalsMissing(pending)).toBe(1)
  })

  it('never offers approval to the requester, a repeat approver, or on a non-pending entry', () => {
    expect(canApproveEntry(pending, 'requester')).toBe(false)
    expect(canApproveEntry(pending, 'first')).toBe(false)
    expect(canApproveEntry({ ...pending, status: 'active' }, 'second')).toBe(false)
    expect(canApproveEntry(pending, undefined)).toBe(false)
  })

  it('treats an unknown status as inactive', () => {
    expect(entryStatus({ status: 'weird' })).toBe('inactive')
    expect(entryStatus({ status: 'expired' })).toBe('expired')
  })
})
