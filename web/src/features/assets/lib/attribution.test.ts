import { describe, expect, it } from 'vitest'
import { decisionsFor, describeEvidence, scanStanding } from './attribution'

const base = {
  technique: 'cert_transparency',
  source: 'crt.sh',
  weight: 0.99,
  first_observed_at: '2026-10-02T00:00:00Z',
  last_observed_at: '2026-10-02T00:00:00Z',
}

describe('describeEvidence', () => {
  it('reads a verified-root CT sighting as a sentence', () => {
    expect(
      describeEvidence({
        ...base,
        rule: 'fqdn_under_verified_root',
        observed: { root: 'acme.com', first_seen: '2026-01-05T00:00:00Z' },
      })
    ).toBe(
      'Under verified domain acme.com — seen in Certificate Transparency (crt.sh) since 5 Jan 2026'
    )
  })

  it('says when the domain was only listed, and names Cert Spotter', () => {
    expect(
      describeEvidence({
        ...base,
        source: 'certspotter',
        rule: 'fqdn_under_asserted_root',
        observed: { root: 'listed.com' },
      })
    ).toBe(
      'Under listed.com, a domain you listed but have not verified — seen in Certificate Transparency (Cert Spotter)'
    )
  })

  it('falls back to readable text for unknown rules and techniques', () => {
    expect(
      describeEvidence({ ...base, rule: 'favicon_hash', technique: 'http_probe', source: 's1' })
    ).toBe('favicon hash — seen in http probe (s1)')
  })
})

describe('scanStanding', () => {
  it('explains what a scan does', () => {
    expect(scanStanding({ active_checks_allowed: true, state: 'confirmed' })).toMatch(/can reach/)
    expect(scanStanding({ active_checks_allowed: false, state: 'needs_review' })).toMatch(
      /until its ownership/
    )
    expect(scanStanding({ active_checks_allowed: false, state: 'dependency' })).toMatch(/passively/)
    // A legacy asset (reported as confirmed) outside every scope target.
    expect(
      scanStanding({
        active_checks_allowed: false,
        state: 'confirmed',
        active_checks_blocked_by: 'unattributed',
      })
    ).toMatch(/no scope target or seed/)
    expect(
      scanStanding({
        active_checks_allowed: false,
        state: 'confirmed',
        active_checks_blocked_by: 'rejected',
      })
    ).toMatch(/marked not yours/)
  })
})

describe('decisionsFor', () => {
  it('never offers the current state and never candidate', () => {
    expect(decisionsFor('needs_review')).toEqual([
      'confirmed',
      'rejected',
      'dependency',
      'monitor_only',
    ])
    expect(decisionsFor('confirmed')).toEqual(['rejected', 'dependency', 'monitor_only'])
  })
})
