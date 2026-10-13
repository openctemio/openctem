import { describe, expect, it } from 'vitest'
import {
  evidenceSourceText,
  reviewHintText,
  reviewNetworkText,
  type AttributionT,
} from '../attribution'

// English fallback with {name} interpolation, like the provider's t().
const t: AttributionT = (_key, fallback = '', vars) =>
  fallback.replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? ''))

describe('evidence source', () => {
  it('names a sensor by the server label and never shows its id', () => {
    expect(evidenceSourceText(t, { source: 'sensor:0190a1b2', source_label: 'dc-west' })).toBe(
      'dc-west'
    )
    expect(
      evidenceSourceText(t, { source: 'sensor:0190a1b2', source_label: 'platform sensor' })
    ).toBe('platform sensor')
    expect(evidenceSourceText(t, { source: 'sensor:0190a1b2' })).toBe('a removed sensor')
    expect(evidenceSourceText(t, { source: 'certspotter' })).toBe('Cert Spotter')
  })
})

describe('review network', () => {
  it('says when the organization matches, and that shared space cannot be added', () => {
    expect(reviewNetworkText(t, { asn: 'AS1', org: 'ACME', org_matches: true })).toMatch(
      /matches your organization/
    )
    expect(
      reviewNetworkText(t, { asn: 'AS13335', shared: true, shared_provider: 'Cloudflare' })
    ).toMatch(/shared provider space \(Cloudflare\); it cannot be added/)
    expect(reviewNetworkText(t, {})).toBeNull()
    expect(reviewNetworkText(t, undefined)).toBeNull()
  })
})

describe('review hint', () => {
  it('words the IP hint and ignores unknown ones', () => {
    expect(reviewHintText(t, 'ip_needs_ip_entry')).toMatch(/needs its own scope entry/)
    expect(reviewHintText(t, 'x')).toBe('')
  })
})
