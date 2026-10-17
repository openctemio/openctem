import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import MCPSettingsPage from '../page'

const mockCreate = vi.fn()
const replace = vi.fn()
let perms = new Set<string>()
let role = 'member'
let tabParam: string | null = null

vi.mock('@/features/api-keys/api/use-api-keys', () => ({
  useCreateApiKey: () => ({ trigger: mockCreate, isMutating: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: vi.fn(async () => true) }))
vi.mock('next/navigation', () => ({ useRouter: () => ({ replace }) }))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlParams: () => ({
    get: (k: string) => (k === 'tab' ? tabParam : null),
    toString: () => (tabParam ? `tab=${tabParam}` : ''),
  }),
}))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: {
    ApiKeysWrite: 'integrations:api_keys:write',
    SettingsRead: 'settings:read',
    SettingsWrite: 'settings:write',
  },
  useHasPermission: (p: string) => perms.has(p),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'Acme', slug: 'acme', role } }),
}))
// The cards have their own tests (features/mcp-oauth).
vi.mock('@/features/mcp-oauth/components/mcp-policy-card', () => ({
  McpPolicyCard: () => <div>policy card</div>,
}))
vi.mock('@/features/mcp-oauth/components/org-clients-card', () => ({ OrgClientsCard: () => null }))
vi.mock('@/features/mcp-oauth/components/mcp-status-strip', () => ({
  McpStatusStrip: () => <div>status strip</div>,
}))
vi.mock('@/features/mcp-oauth/api/access-requests', () => ({
  useAccessRequests: (on: boolean) => ({
    data: on ? { data: [{ id: 'r1' }, { id: 'r2' }] } : undefined,
  }),
}))
vi.mock('@/features/mcp-oauth/components/access-requests-card', () => ({
  AccessRequestsCard: () => <div>requests card</div>,
}))
vi.mock('@/features/mcp-oauth/api/connections', () => ({
  useMcpPolicy: (on: boolean) => ({ data: on ? { any_client: false } : undefined }),
  useOrgConnections: () => ({ data: undefined, isLoading: false }),
  revokeOrgConnection: vi.fn(),
}))

describe('AI assistants settings page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms = new Set(['integrations:api_keys:write'])
    role = 'member'
    tabParam = null
  })

  it('shows a member only how to connect, with a link to their connections', () => {
    render(<MCPSettingsPage />)
    expect(screen.getByText('AI assistants (MCP)')).toBeInTheDocument()
    expect(screen.queryByRole('tablist')).toBeNull()
    expect(screen.queryByText('status strip')).toBeNull()
    expect(
      screen.getByRole('link', { name: /See and disconnect your connected applications/ })
    ).toHaveAttribute('href', '/account/connected-apps')
    expect(screen.getByText(/oct_YOUR_KEY_HERE/)).toBeInTheDocument()
  })

  it('gives administrators the tabs, the waiting count and the tab from the URL', () => {
    perms = new Set(['integrations:api_keys:write', 'settings:read', 'settings:write'])
    role = 'owner'
    tabParam = 'policy'
    render(<MCPSettingsPage />)
    const tabs = screen.getAllByRole('tab').map((t) => t.textContent)
    expect(tabs).toEqual(['Connect', 'Applications2', 'Connections', 'Policy'])
    expect(screen.getByText('status strip')).toBeInTheDocument()
    expect(screen.getByText('policy card')).toBeInTheDocument()
  })

  it('ignores a tab the caller may not see', () => {
    tabParam = 'connections'
    render(<MCPSettingsPage />)
    expect(screen.queryByText('No connected applications')).toBeNull()
    expect(screen.getByText(/oct_YOUR_KEY_HERE/)).toBeInTheDocument()
  })

  it('generates a key with exactly the MCP read scopes and reveals it once', async () => {
    mockCreate.mockResolvedValueOnce({ key: 'oct_secret_generated', key_prefix: 'oct_secr' })
    render(<MCPSettingsPage />)
    await userEvent.click(screen.getAllByRole('button', { name: /generate key/i })[0])
    await userEvent.click(screen.getByRole('button', { name: /^generate$/i }))
    expect(mockCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        scopes: ['findings:read', 'assets:read', 'compliance:frameworks:read'],
        // Every key expires: the API requires 1 to 365 days.
        expires_in_days: 90,
      })
    )
    expect(await screen.findByDisplayValue('oct_secret_generated')).toBeInTheDocument()
  })
})
