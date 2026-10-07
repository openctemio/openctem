import { describe, expect, it } from 'vitest'
import { evidenceSourceText, reviewNetworkText } from '../attribution'

describe('evidence source', () => {
  it('names a sensor by the server label and never shows its id', () => {
    expect(evidenceSourceText({ source: 'sensor:0190a1b2', source_label: 'dc-west' })).toBe(
      'dc-west'
    )
    expect(evidenceSourceText({ source: 'sensor:0190a1b2', source_label: 'platform sensor' })).toBe(
      'platform sensor'
    )
    expect(evidenceSourceText({ source: 'sensor:0190a1b2' })).toBe('a removed sensor')
    expect(evidenceSourceText({ source: 'certspotter' })).toBe('Cert Spotter')
  })
})

describe('review network', () => {
  it('says when the organization matches, and that shared space cannot be added', () => {
    expect(reviewNetworkText({ asn: 'AS1', org: 'ACME', org_matches: true })).toMatch(
      /matches your organization/
    )
    expect(
      reviewNetworkText({ asn: 'AS13335', shared: true, shared_provider: 'Cloudflare' })
    ).toMatch(/shared provider space \(Cloudflare\); it cannot be added/)
    expect(reviewNetworkText({})).toBeNull()
    expect(reviewNetworkText(undefined)).toBeNull()
  })
})
