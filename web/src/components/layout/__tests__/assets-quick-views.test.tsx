import axe from 'axe-core'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'

let pathname = '/assets'
vi.mock('next/navigation', () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}))
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
  useLinkStatus: () => ({ pending: false }),
}))
vi.mock('@/components/ui/sidebar', () => ({
  SidebarMenuSub: ({ children, ...p }: { children: React.ReactNode }) => <ul {...p}>{children}</ul>,
  SidebarMenuSubItem: ({ children }: { children: React.ReactNode }) => <li>{children}</li>,
  SidebarMenuSubButton: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  useSidebarActions: () => ({ setOpenMobile: vi.fn() }),
}))

const perms = { canRead: true }
vi.mock('@/lib/permissions', () => ({
  Permission: { AssetsRead: 'assets:read' },
  usePermissions: () => ({ can: () => perms.canRead }),
}))

const REGISTRY = {
  lenses: [
    { id: 'external_surface', label: 'External surface' },
    { id: 'applications', label: 'Applications' },
    { id: 'code', label: 'Code' },
  ],
  types: [
    { type: 'subdomain', label: 'Subdomain', lens: 'external_surface' },
    { type: 'certificate', label: 'Certificate', lens: 'external_surface' },
    { type: 'application', label: 'Application', lens: 'applications' },
    { type: 'repository', label: 'Repository', lens: 'code' },
    { type: 'unclassified', label: 'Unclassified' },
  ],
}
vi.mock('@/features/asset-types/api/use-asset-type-registry', () => ({
  useAssetTypeRegistry: () => ({ registry: REGISTRY }),
}))

const statsCalls: number[] = []
const stats = {
  total: 557,
  byTypeSubType: { subdomain: 400, certificate: 109, application: 6, unclassified: 1 } as Record<
    string,
    number
  >,
}
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAssetStats: () => {
    statsCalls.push(1)
    return { stats, isLoading: false, error: undefined }
  },
}))

import { AssetsQuickViews } from '../assets-quick-views'

beforeEach(() => {
  pathname = '/assets'
  perms.canRead = true
  statsCalls.length = 0
  window.history.replaceState(null, '', '/assets')
})

describe('AssetsQuickViews', () => {
  it('lists All assets and each lens with an asset as links with ?lens=, then Other', () => {
    render(<AssetsQuickViews />)
    const list = screen.getByRole('list', { name: 'Asset views' })
    const links = within(list).getAllByRole('link')
    expect(links.map((l) => [l.textContent, l.getAttribute('href')])).toEqual([
      ['All assets557', '/assets'],
      ['External surface509', '/assets?lens=external_surface'],
      ['Applications6', '/assets?lens=applications'],
      ['Other1', '/assets?types=unclassified'],
    ])
    // Code has no asset in the caller's scope: not listed.
    expect(within(list).queryByRole('link', { name: /^Code/ })).toBeNull()
  })

  it('marks the open lens, and All assets on a plain list', () => {
    window.history.replaceState(null, '', '/assets?lens=external_surface&criticalities=high')
    const { unmount } = render(<AssetsQuickViews />)
    expect(screen.getByRole('link', { name: /^External surface/ })).toHaveAttribute(
      'aria-current',
      'page'
    )
    expect(screen.getByRole('link', { name: /^All assets/ })).not.toHaveAttribute('aria-current')
    unmount()
    window.history.replaceState(null, '', '/assets')
    render(<AssetsQuickViews />)
    expect(screen.getByRole('link', { name: /^All assets/ })).toHaveAttribute(
      'aria-current',
      'page'
    )
  })

  it('renders nothing, and reads no stats, off the inventory', () => {
    for (const p of ['/assets/groups', '/assets/123', '/findings']) {
      pathname = p
      const { container, unmount } = render(<AssetsQuickViews />)
      expect(container).toBeEmptyDOMElement()
      unmount()
    }
    expect(statsCalls).toHaveLength(0)
  })

  it('renders nothing without assets:read', () => {
    perms.canRead = false
    const { container } = render(<AssetsQuickViews />)
    expect(container).toBeEmptyDOMElement()
    expect(statsCalls).toHaveLength(0)
  })

  it('has no accessibility violations', async () => {
    const { container } = render(<AssetsQuickViews />)
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
