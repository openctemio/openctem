import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { BrandLogoFull, BrandMark, PoweredBy } from '@/components/brand-logo'
import { BrandProvider } from '@/context/brand-provider'
import { I18nProvider, useTranslation } from '@/context/i18n-provider'
import { DEFAULT_BRAND, toBrand, type Brand } from '@/lib/brand'

function About() {
  const { t } = useTranslation()
  return <p>{t('help.about')}</p>
}

function withBrand(brand: Brand, ui: React.ReactNode) {
  return render(
    <BrandProvider brand={brand}>
      <I18nProvider locale="en">{ui}</I18nProvider>
    </BrandProvider>
  )
}

const acme = toBrand({
  name: 'Acme Exposure',
  short_name: 'Acme',
  powered_by: true,
  logo_light_url: '/api/v1/brand/images/logo-light?v=1',
  logo_dark_url: '/api/v1/brand/images/logo-dark?v=2',
})

describe('brand in the console', () => {
  afterEach(() => cleanup())

  it('defaults: the built-in logo, OpenCTEM text, no credit', () => {
    const { container } = withBrand(
      DEFAULT_BRAND,
      <>
        <BrandLogoFull />
        <About />
        <PoweredBy />
      </>
    )
    expect(container.querySelector('svg[aria-label="OpenCTEM"]')).not.toBeNull()
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('About OpenCTEM')).toBeTruthy()
    expect(screen.queryByText(/Powered by/)).toBeNull()
  })

  it('a configured brand changes the logo, the text and shows the credit', () => {
    const { container } = withBrand(
      acme,
      <>
        <BrandLogoFull />
        <About />
        <PoweredBy />
      </>
    )
    const imgs = [...container.querySelectorAll('img')].map((i) => i.getAttribute('src'))
    expect(imgs).toEqual([
      '/api/v1/brand/images/logo-light?v=1',
      '/api/v1/brand/images/logo-dark?v=2',
    ])
    expect(container.querySelector('svg')).toBeNull()
    expect(screen.getByText('About Acme Exposure')).toBeTruthy()
    expect(screen.getByText('Powered by OpenCTEM')).toBeTruthy()
  })

  it('a renamed brand without a logo never shows the built-in mark', () => {
    const { container } = withBrand(toBrand({ name: 'Acme Exposure' }), <BrandMark />)
    expect(container.querySelector('svg')).toBeNull()
    expect(screen.getByRole('img', { name: 'Acme Exposure' }).textContent).toBe('A')
  })
})
