import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AssetAccessGrantsSection } from '../asset-access-grants-section'

/**
 * Being an owner gives no access; direct access grants do. The section is
 * shown only with team:groups:read and editable only with team:groups:write.
 */

const perms = new Set<string>()
const mockGrants = vi.fn()

vi.mock('@/lib/permissions', () => ({
  Permission: { GroupsRead: 'team:groups:read', GroupsWrite: 'team:groups:write' },
  usePermissions: () => ({ can: (p: string) => perms.has(p) }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { slug: 'acme' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../../hooks/use-asset-access-grants', () => ({
  useAssetAccessGrants: () => mockGrants(),
  createAssetAccessGrant: vi.fn(),
  deleteAssetAccessGrant: vi.fn(),
}))

const grant = {
  id: 'g-1',
  userId: 'u-1',
  userName: 'Dev One',
  userEmail: 'dev@example.test',
  source: 'migration' as const,
  grantedAt: '2026-10-03T00:00:00Z',
}

describe('AssetAccessGrantsSection', () => {
  beforeEach(() => {
    perms.clear()
    mockGrants.mockReturnValue({ grants: [grant], isLoading: false, mutate: vi.fn() })
  })

  it('renders nothing without team:groups:read', () => {
    const { container } = render(<AssetAccessGrantsSection assetId="a-1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('lists grants read-only with team:groups:read', () => {
    perms.add('team:groups:read')
    render(<AssetAccessGrantsSection assetId="a-1" />)
    expect(screen.getByText('Dev One')).toBeInTheDocument()
    expect(screen.getByText('From ownership')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /grant access/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /revoke access/i })).not.toBeInTheDocument()
  })

  it('offers grant and revoke with team:groups:write', () => {
    perms.add('team:groups:read')
    perms.add('team:groups:write')
    render(<AssetAccessGrantsSection assetId="a-1" />)
    expect(screen.getByRole('button', { name: /grant access/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /revoke access for dev one/i })).toBeInTheDocument()
  })
})
