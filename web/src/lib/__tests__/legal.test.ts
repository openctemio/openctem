import { describe, it, expect } from 'vitest'

import { DEFAULT_CONTACTS, legalConfig, PENDING, securityContactUri, securityTxt } from '../legal'

describe('legalConfig', () => {
  it('is off by default: no templates, no links', () => {
    const cfg = legalConfig({})
    expect(cfg.templatesEnabled).toBe(false)
    expect(cfg.termsUrl).toBe('')
    expect(cfg.privacyUrl).toBe('')
  })

  it('defaults the contacts to OpenCTEM and marks what is still pending', () => {
    const cfg = legalConfig({ LEGAL_PAGES_ENABLED: 'true' })
    expect(cfg.termsUrl).toBe('/terms')
    expect(cfg.privacyUrl).toBe('/privacy')
    expect(cfg.values.contactEmail).toBe('info@openctem.io')
    expect(cfg.values.securityEmail).toBe('security@openctem.io')
    expect(cfg.values.website).toBe('https://openctem.io')
    expect(cfg.values.docsUrl).toBe('https://docs.openctem.io')
    expect(cfg.values.organization).toBe(PENDING.organization)
    expect(cfg.values.jurisdiction).toBe(PENDING.jurisdiction)
  })

  it('takes configured values, and ignores invalid contacts', () => {
    const cfg = legalConfig({
      LEGAL_ORGANIZATION_NAME: 'Acme Ltd',
      LEGAL_CONTACT_EMAIL: 'legal@acme.example',
      LEGAL_DOCS_URL: 'javascript:alert(1)',
      LEGAL_WEBSITE_URL: 'http://insecure.example',
    })
    expect(cfg.values.organization).toBe('Acme Ltd')
    expect(cfg.values.contactEmail).toBe('legal@acme.example')
    expect(cfg.values.docsUrl).toBe(DEFAULT_CONTACTS.docs)
    expect(cfg.values.website).toBe(DEFAULT_CONTACTS.website)
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

  it('is served with security@openctem.io by default', () => {
    expect(securityTxt({}, now)).toBe(
      'Contact: mailto:security@openctem.io\n' +
        'Expires: 2027-10-08T00:00:00.000Z\n' +
        'Preferred-Languages: en, vi\n'
    )
  })

  it('can be turned off, and an invalid configured contact turns it off', () => {
    expect(securityTxt({ SECURITY_TXT_ENABLED: 'false' }, now)).toBeNull()
    expect(securityTxt({ SECURITY_CONTACT: 'not a contact' }, now)).toBeNull()
    expect(securityTxt({ SECURITY_CONTACT: 'http://insecure.example.com' }, now)).toBeNull()
  })

  it('a configured email or https contact replaces the default', () => {
    expect(securityTxt({ SECURITY_CONTACT: 'psirt@example.com' }, now)).toMatch(
      /^Contact: mailto:psirt@example.com\n/
    )
    expect(securityTxt({ SECURITY_CONTACT: 'https://example.com/report' }, now)).toMatch(
      /^Contact: https:\/\/example.com\/report\n/
    )
  })

  it('adds an https policy and drops a bad one', () => {
    expect(securityTxt({ SECURITY_POLICY_URL: 'https://example.com/policy' }, now)).toContain(
      'Policy: https://example.com/policy\n'
    )
    expect(securityTxt({ SECURITY_POLICY_URL: 'ftp://x' }, now)).not.toContain('Policy:')
  })

  it('a contact cannot inject extra fields', () => {
    expect(securityContactUri('a@example.com\nPolicy: https://evil.example.com')).toBe('')
    expect(securityTxt({ SECURITY_CONTACT: 'a@example.com\r\nCanonical: x' }, now)).toBeNull()
  })
})
