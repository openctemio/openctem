import { describe, it, expect } from 'vitest'

import { legalConfig, securityContactUri, securityTxt } from '../legal'

describe('legalConfig', () => {
  it('is off by default: no templates, no links', () => {
    const cfg = legalConfig({})
    expect(cfg.templatesEnabled).toBe(false)
    expect(cfg.termsUrl).toBe('')
    expect(cfg.privacyUrl).toBe('')
  })

  it('serves the templates when enabled, with placeholders for unset values', () => {
    const cfg = legalConfig({ LEGAL_PAGES_ENABLED: 'true', LEGAL_ORGANIZATION_NAME: 'Acme Ltd' })
    expect(cfg.templatesEnabled).toBe(true)
    expect(cfg.termsUrl).toBe('/terms')
    expect(cfg.privacyUrl).toBe('/privacy')
    expect(cfg.values.organization).toBe('Acme Ltd')
    expect(cfg.values.contactEmail).toBe('[Contact email]')
  })

  it('documents hosted elsewhere win over the templates', () => {
    const cfg = legalConfig({
      LEGAL_PAGES_ENABLED: 'true',
      LEGAL_TERMS_URL: 'https://legal.example.com/terms',
      NEXT_PUBLIC_PRIVACY_URL: 'https://legal.example.com/privacy',
    })
    expect(cfg.termsUrl).toBe('https://legal.example.com/terms')
    expect(cfg.privacyUrl).toBe('https://legal.example.com/privacy')
  })

  it('never links a script or protocol-relative URL', () => {
    const cfg = legalConfig({
      LEGAL_TERMS_URL: 'javascript:alert(1)',
      LEGAL_PRIVACY_URL: '//evil.example.com/p',
    })
    expect(cfg.termsUrl).toBe('')
    expect(cfg.privacyUrl).toBe('')
  })
})

describe('securityTxt', () => {
  const now = new Date('2026-10-08T00:00:00Z')

  it('is absent without a contact', () => {
    expect(securityTxt({}, now)).toBeNull()
    expect(securityTxt({ SECURITY_CONTACT: 'not a contact' }, now)).toBeNull()
    expect(securityTxt({ SECURITY_CONTACT: 'http://insecure.example.com' }, now)).toBeNull()
  })

  it('publishes an email contact with a one-year expiry', () => {
    const body = securityTxt({ SECURITY_CONTACT: 'security@example.com' }, now)
    expect(body).toBe(
      'Contact: mailto:security@example.com\n' +
        'Expires: 2027-10-08T00:00:00.000Z\n' +
        'Preferred-Languages: en, vi\n'
    )
  })

  it('accepts an https contact and an https policy, drops a bad policy', () => {
    expect(
      securityTxt(
        {
          SECURITY_CONTACT: 'https://example.com/report',
          SECURITY_POLICY_URL: 'https://example.com/policy',
        },
        now
      )
    ).toContain('Policy: https://example.com/policy\n')
    expect(
      securityTxt({ SECURITY_CONTACT: 'security@example.com', SECURITY_POLICY_URL: 'ftp://x' }, now)
    ).not.toContain('Policy:')
  })

  it('a contact cannot inject extra fields', () => {
    expect(securityContactUri('a@example.com\nPolicy: https://evil.example.com')).toBe('')
    expect(securityTxt({ SECURITY_CONTACT: 'a@example.com\r\nCanonical: x' }, now)).toBeNull()
  })
})
