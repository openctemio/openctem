import { describe, expect, it } from 'vitest'
import { decisionsFor, describeEvidence, scanStanding, type AttributionT } from './attribution'

// English fallback with {name} interpolation, like the provider's t().
const t: AttributionT = (_key, fallback = '', vars) =>
  fallback.replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? ''))

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
      describeEvidence(t, {
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
      describeEvidence(t, {
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
      describeEvidence(t, { ...base, rule: 'favicon_hash', technique: 'http_probe', source: 's1' })
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
    expect(describeEvidence(t, { ...base, rule: 'tenant_scanned' })).toMatch(
      /^A target your organization scanned/
    )
    expect(describeEvidence(t, { ...base, rule: 'tenant_scan_discovered' })).toMatch(
      /^Found by a scan/
    )
  })
  it('names the certificate a SAN came from', () => {
    expect(
      describeEvidence(t, {
        ...base,
        rule: 'certificate_san',
        technique: 'certificate',
        source: 'certificate_san',
        observed: { root: 'acme.com' },
      })
    ).toMatch(/^Named in a TLS certificate, under acme\.com — seen in a TLS certificate/)
  })
})

describe('scanStanding', () => {
  it('explains what a scan does', () => {
    expect(scanStanding(t, { active_checks_allowed: true, state: 'confirmed' })).toMatch(
      /can reach/
    )
    expect(scanStanding(t, { active_checks_allowed: false, state: 'needs_review' })).toMatch(
      /until its ownership/
    )
    expect(scanStanding(t, { active_checks_allowed: false, state: 'dependency' })).toMatch(
      /passively/
    )
    // A legacy asset (reported as confirmed) outside every scope target.
    expect(
      scanStanding(t, {
        active_checks_allowed: false,
        state: 'confirmed',
        active_checks_blocked_by: 'unattributed',
      })
    ).toMatch(/no scope target, seed or verified domain/)
    // Confirmed by a person, but nothing in Scoping covers it (RFC-054).
    expect(
      scanStanding(t, {
        active_checks_allowed: false,
        state: 'confirmed',
        active_checks_blocked_by: 'out_of_scope',
      })
    ).toMatch(/confirmed as yours, but no scope target/)
    expect(
      scanStanding(t, {
        active_checks_allowed: false,
        state: 'confirmed',
        active_checks_blocked_by: 'rejected',
      })
    ).toMatch(/marked not yours/)
    // Inventory first (RFC-054 §15): discovered and uncovered is passive only.
    expect(
      scanStanding(t, {
        active_checks_allowed: false,
        state: 'discovered',
        active_checks_blocked_by: 'discovered',
      })
    ).toMatch(/Not in scope: passive only/)
    expect(
      scanStanding(t, {
        active_checks_allowed: false,
        state: 'discovered',
        active_checks_blocked_by: 'wildcard_only',
      })
    ).toMatch(/wildcard DNS record/)
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
