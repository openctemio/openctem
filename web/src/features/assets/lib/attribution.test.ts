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

describe('describeEvidence scan rules', () => {
  const base = {
    technique: 'subfinder',
    source: 'sensor:s1',
    weight: 0.6,
    first_observed_at: '',
    last_observed_at: '',
  }
  it('tells a scanned target from a name a scan found', () => {
    expect(describeEvidence({ ...base, rule: 'tenant_scanned' })).toMatch(
      /^A target your organization scanned/
    )
    expect(describeEvidence({ ...base, rule: 'tenant_scan_discovered' })).toMatch(
      /^Found by a scan/
    )
  })
})

describe('scanStanding', () => {
  it('explains what a scan does', () => {
    expect(scanStanding({ active_checks_allowed: true, state: 'confirmed' })).toMatch(/can reach/)
    expect(scanStanding({ active_checks_allowed: false, state: 'needs_review' })).toMatch(
      /until its ownership/
    )
    expect(scanStanding({ active_checks_allowed: false, state: 'dependency' })).toMatch(/passively/)
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
