import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import ApprovalsSettingsPage from '../page'

if (!('ResizeObserver' in globalThis)) {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => '/settings/approvals',
  useSearchParams: () => new URLSearchParams(),
}))

const state: { data?: unknown; error?: unknown; isLoading: boolean } = { isLoading: false }
vi.mock('@/features/findings/api/use-findings-api', () => ({
  useFindingApprovalSettings: () => ({ ...state, mutate: vi.fn() }),
  updateFindingApprovalSettings: vi.fn(),
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({ groups: [], isLoading: false }),
}))
let perms = new Set<string>()
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: (p: string) => perms.has(p) }),
  Permission: {
    GroupsRead: 'team:groups:read',
    ScansRead: 'scans:read',
    SettingsWrite: 'settings:write',
  },
}))
let canOpen = false
const asked: unknown[] = []
vi.mock('@/lib/permissions/use-filtered-sidebar', () => ({
  useNavItemAccess: () => (item: unknown) => {
    asked.push(item)
    return canOpen
  },
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const settings = { backup_contact_email: '', fp_approval: 'all', accept_approval: 'all' }

describe('Settings > Approvals page', () => {
  beforeEach(() => {
    state.data = settings
    state.error = undefined
    state.isLoading = false
    perms = new Set(['settings:write'])
    canOpen = false
    asked.length = 0
  })

  it('links to scan approval only for whoever may open it (scans:read and the scans module)', () => {
    const { unmount } = render(<ApprovalsSettingsPage />)
    expect(screen.queryByRole('link', { name: 'Open scan approval' })).toBeNull()
    expect(asked).toContainEqual({
      permission: 'scans:read',
      module: 'scans',
    })
    unmount()
    canOpen = true
    render(<ApprovalsSettingsPage />)
    expect(screen.getByRole('link', { name: 'Open scan approval' })).toHaveAttribute(
      'href',
      '/settings/scanning/scan-approval'
    )
  })

  it('is view only without settings:write', () => {
    perms = new Set()
    render(<ApprovalsSettingsPage />)
    expect(screen.getByText(/view only/i)).toBeInTheDocument()
    for (const r of screen.getAllByRole('radio')) expect(r).toBeDisabled()
  })

  it('shows the load failure with Retry, never default values', () => {
    state.data = undefined
    state.error = new Error('boom')
    render(<ApprovalsSettingsPage />)
    expect(screen.getByText("Couldn't load Approvals")).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(screen.queryByRole('radio')).toBeNull()
  })
})
