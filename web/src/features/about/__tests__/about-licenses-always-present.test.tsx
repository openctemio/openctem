/**
 * About > Open-source licenses is part of the core and is always present: no
 * brand pack, white-label setting or extension removes or replaces it
 * (api/docs/architecture/third-party-notices.md). This test asserts the route
 * exists in both apps and that the About dialog links to it in both shells,
 * under the default brand and under a white-label brand that hides the
 * upstream credit and points every link elsewhere.
 */
import fs from 'node:fs'
import path from 'node:path'

import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AboutDialog } from '@/components/layout/about-dialog'
import { BrandProvider } from '@/context/brand-provider'
import { LICENSES_ROUTE } from '@/features/about/routes'
import { DEFAULT_BRAND, type Brand } from '@/lib/brand'

vi.mock('@/hooks/use-build-versions', () => ({
  useBuildVersions: () => ({ web: null, api: null }),
}))

const WEB = path.resolve(__dirname, '../../../..')

const WHITE_LABEL: Brand = {
  ...DEFAULT_BRAND,
  name: 'Acme Exposure',
  shortName: 'Acme',
  primaryColor: '#123456',
  docsUrl: 'https://docs.acme.test',
  websiteUrl: 'https://acme.test',
  supportUrl: 'https://acme.test/support',
  poweredBy: false,
  logoLightUrl: '/brand/logo.svg',
  logoDarkUrl: '/brand/logo-dark.svg',
}

describe('About > Open-source licenses is always present', () => {
  it('has a page in the tenant app and in the console at the same route', () => {
    expect(LICENSES_ROUTE).toBe('/about/licenses')
    for (const page of [
      'src/app/(dashboard)/about/licenses/page.tsx',
      'console/src/app/(console)/about/licenses/page.tsx',
    ]) {
      const src = fs.readFileSync(path.join(WEB, page), 'utf8')
      expect(src).toContain('<OpenSourceLicenses')
      // Not behind a brand, a setting, a module or a permission gate.
      expect(src).not.toMatch(/useBrand|useModule|usePermissions|Can |featureFlag|RequireModule/)
    }
  })

  it('serves the web build notices from both apps', () => {
    for (const route of [
      'src/app/api/licenses/route.ts',
      'console/src/app/api/v1/admin/web-licenses/route.ts',
    ]) {
      expect(fs.readFileSync(path.join(WEB, route), 'utf8')).toContain('readWebNotices')
    }
  })

  it.each([
    ['default brand', 'app', DEFAULT_BRAND],
    ['default brand', 'admin', DEFAULT_BRAND],
    ['white-label brand', 'app', WHITE_LABEL],
    ['white-label brand', 'admin', WHITE_LABEL],
  ] as const)('links from About with the %s (%s shell)', (_, shell, brand) => {
    render(
      <BrandProvider brand={brand}>
        <AboutDialog open onOpenChange={() => {}} shell={shell} />
      </BrandProvider>
    )
    const link = screen.getByRole('link', { name: 'Open-source licenses' })
    expect(link).toHaveAttribute('href', LICENSES_ROUTE)
  })
})
