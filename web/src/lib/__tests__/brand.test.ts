import { afterEach, describe, expect, it, vi } from 'vitest'

import { DEFAULT_BRAND, docsLink, toBrand } from '@/lib/brand'
import { withBrand } from '@/lib/legal-settings'
import { translate } from '@/lib/i18n'
import { en } from '@/lib/i18n/dictionaries'

const custom = {
  name: 'Acme Exposure',
  short_name: 'Acme',
  primary_color: '#0a7b83',
  docs_url: 'https://help.example.com/',
  website_url: 'https://example.com',
  support_url: 'https://example.com/support',
  support_email: 'support@example.com',
  terms_url: 'https://example.com/terms',
  privacy_url: 'https://example.com/privacy',
  powered_by: true,
  logo_light_url: '/api/v1/brand/images/logo-light?v=0123abcd',
  logo_dark_url: '',
  favicon_url: '/api/v1/brand/images/favicon?v=ff',
}

describe('toBrand', () => {
  it('keeps the OpenCTEM defaults for an empty or missing answer', () => {
    expect(toBrand(undefined)).toEqual(DEFAULT_BRAND)
    expect(toBrand({})).toEqual(DEFAULT_BRAND)
    expect(DEFAULT_BRAND.name).toBe('OpenCTEM')
    expect(DEFAULT_BRAND.poweredBy).toBe(false)
  })

  it('takes a valid brand', () => {
    const b = toBrand(custom)
    expect(b).toMatchObject({
      name: 'Acme Exposure',
      shortName: 'Acme',
      primaryColor: '#0a7b83',
      docsUrl: 'https://help.example.com',
      poweredBy: true,
      logoLightUrl: custom.logo_light_url,
      logoDarkUrl: custom.logo_light_url, // falls back to the light logo
      faviconUrl: custom.favicon_url,
    })
    expect(docsLink(b, '/sensors/')).toBe('https://help.example.com/sensors/')
  })

  it('refuses unsafe values one by one', () => {
    const b = toBrand({
      name: '<img src=x onerror=alert(1)>',
      primary_color: 'red;background:url(x)',
      docs_url: 'javascript:alert(1)',
      website_url: 'http://example.com',
      support_url: 'https://user:pw@example.com',
      support_email: 'not an email',
      terms_url: 'data:text/html,x',
      logo_light_url: 'https://evil.example/logo.svg',
      logo_dark_url: '/api/v1/brand/images/../../admin',
      favicon_url: '//evil.example/x.png',
      powered_by: true,
    })
    expect(b).toEqual({ ...DEFAULT_BRAND, poweredBy: false })
  })

  it('never credits OpenCTEM to itself', () => {
    expect(toBrand({ name: 'OpenCTEM', powered_by: true }).poweredBy).toBe(false)
  })
})

describe('{product} in the catalogs', () => {
  it('defaults to OpenCTEM and follows the brand', () => {
    expect(translate(en, 'help.about')).toBe('About OpenCTEM')
    expect(translate(en, 'help.about', undefined, { product: 'Acme Exposure' })).toBe(
      'About Acme Exposure'
    )
  })
})

describe('legal values from the brand', () => {
  it('fills only what the legal settings leave unset', () => {
    const rec = withBrand(
      { LEGAL_CONTACT_EMAIL: 'legal@example.org', LEGAL_TERMS_URL: '' },
      toBrand(custom)
    )
    expect(rec).toMatchObject({
      LEGAL_CONTACT_EMAIL: 'legal@example.org',
      LEGAL_SERVICE_NAME: 'Acme Exposure',
      LEGAL_TERMS_URL: 'https://example.com/terms',
      LEGAL_DOCS_URL: 'https://help.example.com',
    })
  })
})

describe('brandSettings', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('falls back to the defaults when the API fails or is old', async () => {
    const { brandSettings } = await import('@/lib/brand-settings')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('not found', { status: 404 }))
    )
    expect(await brandSettings()).toEqual(DEFAULT_BRAND)
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('down')
      })
    )
    expect(await brandSettings()).toEqual(DEFAULT_BRAND)
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(custom))
    )
    expect((await brandSettings()).name).toBe('Acme Exposure')
  })
})
