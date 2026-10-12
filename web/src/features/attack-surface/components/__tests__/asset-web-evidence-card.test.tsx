/**
 * Web evidence on the asset page (RFC-081): captures shown as text, the
 * screenshot from the data-scoped API route, nothing when there is none or
 * the module is off.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: () => true }) }
})
const modules = vi.hoisted(() => ({ ids: ['attack_surface'] }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: modules.ids, isLoading: false }),
}))

const { AssetWebEvidenceCard } = await import('../asset-web-evidence-card')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  modules.ids = ['attack_surface']
  api.get.mockReset().mockResolvedValue({
    items: [
      {
        id: 'e1',
        url: 'https://app.example.com/',
        status_code: 200,
        title: '<img src=x onerror=alert(1)>',
        snippet: '<script>alert(1)</script> «secret:token#1»',
        snippet_truncated: true,
        captured_at: '2026-10-10T00:00:00Z',
        has_screenshot: true,
        screenshot_width: 1280,
        screenshot_height: 800,
      },
    ],
  })
})

describe('AssetWebEvidenceCard', () => {
  it('shows the capture as text and the screenshot from the API', async () => {
    const { container } = wrap(<AssetWebEvidenceCard assetId="a1" />)
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(screen.getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument()
    expect(container.querySelector('script')).toBeNull()
    const img = screen.getByRole('img', { name: 'Screenshot of https://app.example.com/' })
    expect(img).toHaveAttribute('src', '/api/v1/assets/a1/web-evidence/e1/screenshot')
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/web-evidence')
  })

  it('renders nothing without captures', async () => {
    api.get.mockResolvedValue({ items: [] })
    const { container } = wrap(<AssetWebEvidenceCard assetId="a1" />)
    await Promise.resolve()
    expect(container).toBeEmptyDOMElement()
  })

  it('fetches nothing when the attack surface module is off', () => {
    modules.ids = []
    const { container } = wrap(<AssetWebEvidenceCard assetId="a1" />)
    expect(api.get).not.toHaveBeenCalled()
    expect(container).toBeEmptyDOMElement()
  })
})
